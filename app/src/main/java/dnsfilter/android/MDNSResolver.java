package dnsfilter.android;

import android.content.Context;
import android.net.wifi.WifiManager;
import android.util.Log;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

import javax.jmdns.JmDNS;
import javax.jmdns.ServiceInfo;

 public class MDNSResolver {
    private static final String TAG = "MDNSResolver";
    private final Context context;
    private static final int INITIAL_TIMEOUT = 1000; // 1 second
    private static final int MAX_TIMEOUT = 5000; // 5 seconds
    private static final int MAX_RETRIES = 3;
    private JmDNS jmdns;

    MDNSResolver(Context context) {
        Log.i(TAG, "MDNSResolver: Initializing");
        this.context = context;
        try {
            WifiManager wifi = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
            WifiManager.MulticastLock multicastLock = wifi.createMulticastLock("mdnslock");
            multicastLock.setReferenceCounted(true);
            multicastLock.acquire();
            
            InetAddress addr = getLocalIPv4Address();
            jmdns = JmDNS.create(addr);
            Log.i(TAG, "MDNSResolver: JmDNS created with address: " + addr);
        } catch (IOException e) {
            Log.e(TAG, "MDNSResolver: Failed to initialize JmDNS", e);
        }
    }

    private InetAddress getLocalIPv4Address() throws UnknownHostException {
        WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
        int ipAddress = wifiManager.getConnectionInfo().getIpAddress();
        return InetAddress.getByAddress(new byte[]{
                (byte) (ipAddress & 0xff),
                (byte) (ipAddress >> 8 & 0xff),
                (byte) (ipAddress >> 16 & 0xff),
                (byte) (ipAddress >> 24 & 0xff)
        });
    }

    public InetAddress resolve(String domain) {
        Log.i(TAG, "resolve: Attempting to resolve " + domain);
        try {
            // First, try system DNS resolution
            InetAddress address = InetAddress.getByName(domain);
            Log.i(TAG, "resolve: Resolved " + domain + " to " + address.getHostAddress() + " using system DNS");
            return address;
        } catch (UnknownHostException e) {
            Log.w(TAG, "resolve: System DNS resolution failed for " + domain, e);
        }

        // If system DNS fails, try mDNS resolution
        return resolveMdnsName(domain);
    }

    private InetAddress resolveMdnsName(String domain) {
        Log.i(TAG, "resolveMdnsName: Attempting mDNS resolution for " + domain);
        if (jmdns == null) {
            Log.e(TAG, "resolveMdnsName: JmDNS is not initialized");
            return null;
        }

        ServiceInfo serviceInfo = jmdns.getServiceInfo("_http._tcp.local.", domain, MAX_TIMEOUT);
        if (serviceInfo != null) {
            InetAddress[] addresses = serviceInfo.getInetAddresses();
            if (addresses.length > 0) {
                Log.i(TAG, "resolveMdnsName: Resolved " + domain + " to " + addresses[0].getHostAddress() + " using mDNS");
                return addresses[0];
            }
        }

        Log.w(TAG, "resolveMdnsName: Failed to resolve " + domain + " using mDNS");
        return null;
    }

    public void close() {
        if (jmdns != null) {
            try {
                jmdns.close();
            } catch (IOException e) {
                Log.e(TAG, "close: Error closing JmDNS", e);
            }
        }
    }
}