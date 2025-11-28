import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLParameters;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;

public class SecureHttpsRequest {

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            throw new IllegalArgumentException("Usage: <url> <truststorePath> <truststorePassword>");
        }

        String urlString = args[0];
        Path trustStorePath = Path.of(args[1]);
        char[] trustStorePassword = args[2].toCharArray();

        if (!urlString.toLowerCase().startsWith("https://")) {
            throw new IllegalArgumentException("URL must begin with https://");
        }
        if (!Files.exists(trustStorePath) || !Files.isReadable(trustStorePath)) {
            throw new IllegalArgumentException("Truststore file is not readable.");
        }

        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (var tsStream = Files.newInputStream(trustStorePath)) {
            trustStore.load(tsStream, trustStorePassword);
        }

        TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), SecureRandom.getInstanceStrong());

        URL url = new URL(urlString);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();

        HostnameVerifier verifier = HttpsURLConnection.getDefaultHostnameVerifier();
        conn.setHostnameVerifier(verifier);
        conn.setSSLSocketFactory(sslContext.getSocketFactory());

        conn.setRequestMethod("GET");
        conn.setConnectTimeout(10_000);
        conn.setReadTimeout(10_000);
        conn.setDoOutput(true);
        conn.setInstanceFollowRedirects(false);

        SSLParameters params = sslContext.getDefaultSSLParameters();
        params.setProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
        conn.setSSLSocketFactory(new RestrictedProtocolFactory(
                sslContext.getSocketFactory(), params.getProtocols()));

        try (OutputStream out = conn.getOutputStream()) {
            out.write(new byte[0]);
        }

        try (BufferedReader br =
                     new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            String line;
            while ((line = br.readLine()) != null) {
                System.out.println(line);
            }
        }

        java.util.Arrays.fill(trustStorePassword, '\0');
    }

    private static final class RestrictedProtocolFactory
            extends javax.net.ssl.SSLSocketFactory {

        private final javax.net.ssl.SSLSocketFactory delegate;
        private final String[] protocols;

        RestrictedProtocolFactory(javax.net.ssl.SSLSocketFactory delegate, String[] protocols) {
            this.delegate = delegate;
            this.protocols = protocols;
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return delegate.getDefaultCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return delegate.getSupportedCipherSuites();
        }

        @Override
        public java.net.Socket createSocket(java.net.Socket s, String h, int p, boolean a)
                throws java.io.IOException {
            java.net.Socket socket = delegate.createSocket(s, h, p, a);
            configure(socket);
            return socket;
        }

        @Override
        public java.net.Socket createSocket(String h, int p) throws java.io.IOException {
            java.net.Socket socket = delegate.createSocket(h, p);
            configure(socket);
            return socket;
        }

        @Override
        public java.net.Socket createSocket(String h, int p, java.net.InetAddress lh, int lp)
                throws java.io.IOException {
            java.net.Socket socket = delegate.createSocket(h, p, lh, lp);
            configure(socket);
            return socket;
        }

        @Override
        public java.net.Socket createSocket(java.net.InetAddress h, int p)
                throws java.io.IOException {
            java.net.Socket socket = delegate.createSocket(h, p);
            configure(socket);
            return socket;
        }

        @Override
        public java.net.Socket createSocket(java.net.InetAddress h, int p,
                                            java.net.InetAddress lh, int lp)
                throws java.io.IOException {
            java.net.Socket socket = delegate.createSocket(h, p, lh, lp);
            configure(socket);
            return socket;
        }

        private void configure(java.net.Socket socket) {
            if (socket instanceof javax.net.ssl.SSLSocket) {
                javax.net.ssl.SSLSocket ssl = (javax.net.ssl.SSLSocket) socket;
                ssl.setEnabledProtocols(protocols);
            }
        }
    }
}
