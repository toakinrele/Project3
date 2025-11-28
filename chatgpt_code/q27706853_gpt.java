import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.HostnameVerifier;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Objects;

public final class LocalhostTrustedRequest {

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            throw new IllegalArgumentException("Usage: <https-url> <truststore-path> <truststore-password>");
        }

        String httpsUrl = args[0];
        Path trustStorePath = Path.of(args[1]);
        char[] trustStorePassword = args[2].toCharArray();

        validateInputs(httpsUrl, trustStorePath, trustStorePassword);

        SSLContext sslContext = createSslContext(trustStorePath, trustStorePassword);

        HttpsURLConnection connection = openSecureConnection(httpsUrl, sslContext);

        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(connection.getInputStream())))
        {
            String line;
            while ((line = br.readLine()) != null) {
                System.out.println(line);
            }
        }

        zeroCharArray(trustStorePassword);
    }

    private static void validateInputs(String url, Path trustStorePath, char[] password) throws Exception {
        Objects.requireNonNull(url);
        Objects.requireNonNull(password);

        if (!url.toLowerCase().startsWith("https://")) {
            throw new IllegalArgumentException("URL must be HTTPS.");
        }

        if (!Files.exists(trustStorePath) || !Files.isReadable(trustStorePath)) {
            throw new IllegalArgumentException("Truststore not readable.");
        }

        if (password.length == 0) {
            throw new IllegalArgumentException("Empty password not allowed.");
        }
    }

    private static SSLContext createSslContext(Path trustStorePath, char[] trustStorePassword)
            throws Exception {

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());

        try (var in = Files.newInputStream(trustStorePath)) {
            trustStore.load(in, trustStorePassword);
        }

        TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), SecureRandom.getInstanceStrong());

        return sslContext;
    }

    private static HttpsURLConnection openSecureConnection(String httpsUrl, SSLContext sslContext)
            throws Exception {

        URL url = new URL(httpsUrl);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();

        HostnameVerifier verifier = HttpsURLConnection.getDefaultHostnameVerifier();
        conn.setHostnameVerifier(verifier);

        conn.setSSLSocketFactory(sslContext.getSocketFactory());
        conn.setConnectTimeout(10_000);
        conn.setReadTimeout(10_000);

        return conn;
    }

    private static void zeroCharArray(char[] arr) {
        if (arr != null) {
            java.util.Arrays.fill(arr, '\0');
        }
    }
}
