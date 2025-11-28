import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

public class SecureHttpsClientWithClientCert {

    /**
     * Usage (example):
     * java SecureHttpsClientWithClientCert \
     *   "https://somehost.dk:3049" \
     *   "/path/to/client-keystore.jks" \
     *   "keystorePassword" \
     *   "/path/to/truststore.jks" \
     *   "truststorePassword"
     */
    public static void main(String[] args) throws Exception {
        if (args.length != 5) {
            System.err.println("Usage: java SecureHttpsClientWithClientCert <url> <keystorePath> <keystorePassword> <truststorePath> <truststorePassword>");
            System.exit(1);
        }

        String urlString = args[0];
        String keyStorePath = args[1];
        String keyStorePassword = args[2];
        String trustStorePath = args[3];
        String trustStorePassword = args[4];

        validateInput(urlString, keyStorePath, keyStorePassword, trustStorePath, trustStorePassword);

        SSLContext sslContext = createSslContext(
                keyStorePath,
                keyStorePassword.toCharArray(),
                trustStorePath,
                trustStorePassword.toCharArray()
        );

        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

        URL url = new URL(urlString);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();

        // Use default hostname verifier (performs proper hostname verification)
        HostnameVerifier defaultVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
        conn.setHostnameVerifier(defaultVerifier);

        conn.setSSLSocketFactory(sslSocketFactory);

        // Safe HTTP settings
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(10_000);
        conn.setReadTimeout(10_000);
        conn.setInstanceFollowRedirects(false);

        // Disable HTTP caching at client side
        conn.setUseCaches(false);

        // Restrict protocols and ciphers to secure ones where possible
        SSLParameters sslParameters = sslContext.getDefaultSSLParameters();
        String[] secureProtocols = selectSecureProtocols(sslParameters.getProtocols());
        if (secureProtocols != null && secureProtocols.length > 0) {
            sslParameters.setProtocols(secureProtocols);
        }
        conn.setSSLSocketFactory(new RestrictedProtocolSSLSocketFactory(sslSocketFactory, secureProtocols));

        int statusCode;
        try (InputStream in = conn.getInputStream()) {
            statusCode = conn.getResponseCode();
            byte[] buffer = new byte[4096];
            while (in.read(buffer) != -1) {
                // Consume response (in a real client you would process it)
            }
        }

        System.out.println("HTTPS request completed with status code: " + statusCode);
    }

    private static void validateInput(String url,
                                      String keyStorePath,
                                      String keyStorePassword,
                                      String trustStorePath,
                                      String trustStorePassword) throws Exception {
        if (url == null || url.isBlank() || !url.toLowerCase().startsWith("https://")) {
            throw new IllegalArgumentException("URL must be a non-empty HTTPS URL.");
        }

        validateFilePath(keyStorePath, "Keystore path");
        validateFilePath(trustStorePath, "Truststore path");

        if (keyStorePassword == null || keyStorePassword.isEmpty()) {
            throw new IllegalArgumentException("Keystore password must not be empty.");
        }

        if (trustStorePassword == null || trustStorePassword.isEmpty()) {
            throw new IllegalArgumentException("Truststore password must not be empty.");
        }
    }

    private static void validateFilePath(String path, String label) throws Exception {
        if (path == null || path.isBlank()) {
            throw new IllegalArgumentException(label + " must not be empty.");
        }
        File f = new File(path);
        if (!f.isFile() || !f.canRead()) {
            throw new IllegalArgumentException(label + " must point to a readable file: " + path);
        }
    }

    private static SSLContext createSslContext(String keyStorePath,
                                               char[] keyStorePassword,
                                               String trustStorePath,
                                               char[] trustStorePassword) throws Exception {
        // Load client key material (private key + certificate chain)
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream keyStoreStream = new FileInputStream(keyStorePath)) {
            keyStore.load(keyStoreStream, keyStorePassword);
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, keyStorePassword);

        // Load trust store (server certificates / CA)
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (FileInputStream trustStoreStream = new FileInputStream(trustStorePath)) {
            trustStore.load(trustStoreStream, trustStorePassword);
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        // Create SSL context with secure random
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), SecureRandom.getInstanceStrong());

        // Clear password arrays
        Arrays.fill(keyStorePassword, '\0');
        Arrays.fill(trustStorePassword, '\0');

        return sslContext;
    }

    /**
     * Choose secure TLS protocols from the supported set.
     */
    private static String[] selectSecureProtocols(String[] supported) {
        if (supported == null) {
            return null;
        }
        List<String> preferred = Arrays.asList("TLSv1.3", "TLSv1.2");
        return Arrays.stream(supported)
                .filter(preferred::contains)
                .toArray(String[]::new);
    }

    /**
     * Wrapper SSLSocketFactory that restricts enabled protocols on created sockets.
     */
    private static final class RestrictedProtocolSSLSocketFactory extends SSLSocketFactory {
        private final SSLSocketFactory delegate;
        private final String[] enabledProtocols;

        RestrictedProtocolSSLSocketFactory(SSLSocketFactory delegate, String[] enabledProtocols) {
            this.delegate = delegate;
            this.enabledProtocols = enabledProtocols;
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
        public java.net.Socket createSocket(java.net.Socket s, String host, int port, boolean autoClose)
                throws java.io.IOException {
            java.net.Socket socket = delegate.createSocket(s, host, port, autoClose);
            configureProtocols(socket);
            return socket;
        }

        @Override
        public java.net.Socket createSocket(String host, int port) throws java.io.IOException {
            java.net.Socket socket = delegate.createSocket(host, port);
            configureProtocols(socket);
            return socket;
        }

        @Override
        public java.net.Socket createSocket(String host, int port, java.net.InetAddress localHost, int localPort)
                throws java.io.IOException {
            java.net.Socket socket = delegate.createSocket(host, port, localHost, localPort);
            configureProtocols(socket);
            return socket;
        }

        @Override
        public java.net.Socket createSocket(java.net.InetAddress host, int port) throws java.io.IOException {
            java.net.Socket socket = delegate.createSocket(host, port);
            configureProtocols(socket);
            return socket;
        }

        @Override
        public java.net.Socket createSocket(java.net.InetAddress address, int port,
                                            java.net.InetAddress localAddress, int localPort)
                throws java.io.IOException {
            java.net.Socket socket = delegate.createSocket(address, port, localAddress, localPort);
            configureProtocols(socket);
            return socket;
        }

        private void configureProtocols(java.net.Socket socket) {
            if (enabledProtocols != null && socket instanceof javax.net.ssl.SSLSocket) {
                javax.net.ssl.SSLSocket sslSocket = (javax.net.ssl.SSLSocket) socket;
                sslSocket.setEnabledProtocols(enabledProtocols);
            }
        }
    }
}
