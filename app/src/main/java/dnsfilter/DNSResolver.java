package dnsfilter;

import android.util.Log;

import dnsfilter.android.DNSFilterService;
import ip.IPPacket;
import ip.UDPPacket;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.util.Hashtable;

import util.ExecutionEnvironment;
import util.Logger;

public class DNSResolver implements Runnable {

	private static final String TAG = "DNSResolver";
	private static int THR_COUNT = 0;
	private static Object CNT_SYNC = new Object();
	private static boolean IO_ERROR = false;

	private UDPPacket udpRequestPacket;
	private OutputStream responseOut;

	private DatagramPacket dataGramRequest;
	private DatagramSocket replySocket;

	private boolean datagramPacketMode = false;

	private static boolean enableLocalResolver = false;
	private static int localResolverTTL = 0;
	private static Hashtable<String, byte[]> customIPMappings = null;

	private static final String GTBLCL_DOMAIN = ".gtblcl.com";
	private static final String LOCAL_SUFFIX = ".local";

	public static void initLocalResolver(Hashtable<String, byte[]> customMappings, boolean enabled, int ttl) {
		customIPMappings = customMappings;
		localResolverTTL = ttl;
		enableLocalResolver = enabled;
	}

	public DNSResolver(UDPPacket udpRequestPacket, OutputStream responseOut) {
		this.udpRequestPacket = udpRequestPacket;
		this.responseOut = responseOut;
	}

	public DNSResolver(DatagramPacket request, DatagramSocket replySocket) {
		datagramPacketMode = true;
		this.dataGramRequest = request;
		this.replySocket = replySocket;
	}

	private boolean resolveLocal(String client, DatagramPacket request, DatagramPacket response) throws IOException {
		Log.d(TAG, "Entering resolveLocal for client: " + client);

		if (!enableLocalResolver) {
			Log.d(TAG, "Local resolver is disabled");
			return false;
		}

		SimpleDNSMessage dnsQuery = null;
		try {
			dnsQuery = new SimpleDNSMessage(request.getData(), request.getOffset(), request.getLength());
			Log.d(TAG, "Successfully parsed DNS query");
		} catch (Exception e) {
			Log.e(TAG, "Failed to parse DNS query: " + e.getMessage());
			if (ExecutionEnvironment.getEnvironment().debug()) {
				File dump = new File(ExecutionEnvironment.getEnvironment().getWorkDir() + "/dnsdump_" + System.currentTimeMillis());
				FileOutputStream dumpout = new FileOutputStream(dump);
				dumpout.write(request.getData(), request.getOffset(), request.getLength());
				dumpout.flush();
				dumpout.close();
				Log.d(TAG, "DNS query dump created at " + dump.getAbsolutePath());
			}
			Logger.getLogger().logException(e);
			throw new IOException(e);
		}

		if (!dnsQuery.isStandardQuery()) {
			Log.d(TAG, "Not a standard query, skipping");
			return false;
		}

		Object[] info = dnsQuery.getQueryData();

		short type = (short) info[1];
		short clss = (short) info[2];
		String host = (String) info[0];

		Log.d(TAG, "Query for host: " + host + ", type: " + type + ", class: " + clss);

		// Check for custom gtblcl.com resolution
		if (host.endsWith(GTBLCL_DOMAIN)) {
			Log.d(TAG, "Detected gtblcl.com domain: " + host);
			String localDomain = host.substring(0, host.length() - GTBLCL_DOMAIN.length()) + LOCAL_SUFFIX;
			Log.d(TAG, "Attempting to resolve local domain: " + localDomain);
			InetAddress resolvedAddress = resolveCustomDomain(localDomain);
			if (resolvedAddress != null) {
				byte[] ip = resolvedAddress.getAddress();
				int length = dnsQuery.produceResponse(response.getData(), response.getOffset(), ip, localResolverTTL);
				response.setLength(length);
				DNSResponsePatcher.trafficLog(client, clss, type, host, resolvedAddress.getHostAddress(), ip.length);
				Log.i(TAG, "CUSTOM_RESOLVED: " + host + " -> " + localDomain + " -> " + resolvedAddress.getHostAddress());
				return true;
			} else {
				Log.d(TAG, "Failed to resolve local domain: " + localDomain);
			}
		}

		if (type != 1 && type != 28) {
			Log.d(TAG, "Handling non-standard type: " + type);
			return handle_NonTyp_1_28(client, dnsQuery, response);
		}

		byte[] ip = null;
		String prfx = ">4";
		byte[] filterIP = DNSResponsePatcher.ipv4_blocked;
		if (type == 28) {
			prfx = ">6";
			filterIP = DNSResponsePatcher.ipv6_blocked;
		}

		Log.d(TAG, "Checking custom IP mappings for " + prfx + host.toLowerCase());
		if (customIPMappings != null)
			ip = customIPMappings.get(prfx + host.toLowerCase());
		if (ip == null && DNSResponsePatcher.filter(host, false)) {
			Log.d(TAG, "Host filtered: " + host);
			DNSResponsePatcher.logNstats(true, host);
			ip = filterIP;
		}
		if (ip != null) {
			Log.d(TAG, "IP found for host: " + host);
			DNSResponsePatcher.trafficLog(client, clss, type, host, null, 0);
			int length = dnsQuery.produceResponse(response.getData(), response.getOffset(), ip, localResolverTTL);
			response.setLength(length);

			String addrStr = InetAddress.getByAddress(ip).getHostAddress();

			DNSResponsePatcher.trafficLog(client, clss, type, host, addrStr, ip.length);

			if (ip != filterIP)
				Log.i(TAG, "MAPPED_CUSTOM_IP: " + host + "->" + addrStr);

			return true;
		} else {
			Log.d(TAG, "No custom IP or filter applied for host: " + host);
			return false;
		}
	}

	private InetAddress resolveCustomDomain(String localDomain) {
		Log.d(TAG, "Entering resolveCustomDomain for: " + localDomain);
		try {
			// Try mDNS resolution first
			Log.d(TAG, "Attempting mDNS resolution");
			InetAddress address = DNSFilterService.resolveMDNS(localDomain);
			if (address != null) {
				Log.d(TAG, "mDNS resolution successful: " + address.getHostAddress());
				return address;
			} else {
				Log.d(TAG, "mDNS resolution failed, falling back to system resolver");
			}

			// If mDNS fails or is not available, try system resolver
			Log.d(TAG, "Attempting system resolver");
			InetAddress systemResolved = InetAddress.getByName(localDomain);
			if (systemResolved != null) {
				Log.d(TAG, "System resolver successful: " + systemResolved.getHostAddress());
			} else {
				Log.d(TAG, "System resolver returned null");
			}
			return systemResolved;
		} catch (IOException e) {
			Log.e(TAG, "Failed to resolve " + localDomain + ": " + e.getMessage());
			return null;
		}
	}


	private boolean handle_NonTyp_1_28(String client, SimpleDNSMessage dnsQuery, DatagramPacket response) {
		String host = dnsQuery.qHost;
		if (!DNSResponsePatcher.filter(host, false))
			return false;
		DNSResponsePatcher.trafficLog(client, dnsQuery.qClass, dnsQuery.qType, host, null, 0);
		DNSResponsePatcher.logNstats(true, host);
		int length = dnsQuery.get_NonTyp_1_28_FilterResponse(response.getData(), response.getOffset());
		response.setLength(length);
		return true;
	}

	private void processIPPackageMode() throws Exception {
		int ttl = udpRequestPacket.getTTL();
		int[] sourceIP = udpRequestPacket.getSourceIP();
		int[] destIP = udpRequestPacket.getDestIP();
		int sourcePort = udpRequestPacket.getSourcePort();
		int destPort = udpRequestPacket.getDestPort();
		int version = udpRequestPacket.getVersion();
		String clientID = IPPacket.int2ip(sourceIP).getHostAddress() + ":" + sourcePort;

		int hdrLen = udpRequestPacket.getHeaderLength();
		byte[] packetData = udpRequestPacket.getData();
		int ipOffs = udpRequestPacket.getIPPacketOffset();
		int offs = ipOffs + hdrLen;
		int len = udpRequestPacket.getIPPacketLength() - hdrLen;

		DatagramPacket request = new DatagramPacket(packetData, offs, len);
		DatagramPacket response = new DatagramPacket(packetData, offs, packetData.length - offs);

		if (!resolveLocal(clientID, request, response)) {
			DNSCommunicator.getInstance().requestDNS(request, response);
			byte[] buf = DNSResponsePatcher.patchResponse(clientID, response.getData(), offs);
		}

		UDPPacket udp = UDPPacket.createUDPPacket(response.getData(), ipOffs, hdrLen + response.getLength(), version);
		udp.updateHeader(ttl, 17, destIP, sourceIP);
		udp.updateHeader(destPort, sourcePort);

		synchronized (responseOut) {
			responseOut.write(udp.getData(), udp.getIPPacketOffset(), udp.getIPPacketLength());
			responseOut.flush();
		}
	}

	private void processDatagramPackageMode() throws Exception {
		SocketAddress sourceAdr = dataGramRequest.getSocketAddress();
		String clientID = sourceAdr.toString();

		byte[] data = dataGramRequest.getData();
		DatagramPacket response = new DatagramPacket(data, dataGramRequest.getOffset(), data.length - dataGramRequest.getOffset());

		if (!resolveLocal(clientID, dataGramRequest, response)) {
			DNSCommunicator.getInstance().requestDNS(dataGramRequest, response);
			DNSResponsePatcher.patchResponse(clientID, response.getData(), response.getOffset());
		}

		response.setSocketAddress(sourceAdr);
		replySocket.send(response);
	}

	@Override
	public void run() {
		try {
			synchronized (CNT_SYNC) {
				THR_COUNT++;
			}
			if (datagramPacketMode)
				processDatagramPackageMode();
			else
				processIPPackageMode();

			IO_ERROR = false;

		} catch (IOException e) {
			boolean hasNetwork = ExecutionEnvironment.getEnvironment().hasNetwork();
			if (!hasNetwork)
				Logger.getLogger().message("No network!");
			String msg = e.getMessage();
			if (e.getMessage() == null)
				msg = e.toString();
			if (ExecutionEnvironment.getEnvironment().debug())
				Logger.getLogger().logLine(msg);
			else if (!IO_ERROR && hasNetwork) {
				Logger.getLogger().logLine(msg + "\nIO Error occurred! Check network or DNS config!");
				IO_ERROR = true;
			}
		} catch (Exception e) {
			Logger.getLogger().logException(e);
		} finally {
			synchronized (CNT_SYNC) {
				THR_COUNT--;
			}
		}
	}

	public static int getResolverCount() {
		return THR_COUNT;
	}
}