import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SecureHmacExample {

    // Usage:
    // java SecureHmacExample "qnscAdgRlkIhAUPY44oiexBKtQbGY0orf7OV1I50" "foo"
    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            throw new IllegalArgumentException("Expected: <key> <message>");
        }

        String keyInput = args[0];
        String messageInput = args[1];

        if (keyInput.isBlank() || messageInput.isBlank()) {
            throw new IllegalArgumentException("Key and message must be non-empty.");
        }

        // Python example uses HMAC-SHA1 (RFC 2104)
        String algorithm = "HmacSHA1";

        // Create a proper SecretKeySpec using UTF-8 bytes
        SecretKeySpec keySpec = new SecretKeySpec(
                keyInput.getBytes(StandardCharsets.UTF_8),
                algorithm
        );

        // Create and initialize Mac instance
        Mac mac = Mac.getInstance(algorithm);
        mac.init(keySpec);

        // Compute the HMAC
        byte[] hmacBytes = mac.doFinal(messageInput.getBytes(StandardCharsets.UTF_8));

        // Base64-encode the result using Java's safe Base64 encoder
        String hmacBase64 = Base64.getEncoder().encodeToString(hmacBytes);

        System.out.println(hmacBase64);
    }
}
