import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

public class SecureAesInterop {

    private static final int KEY_SIZE_BITS = 256;
    private static final int ITERATIONS = 100_000;
    private static final int SALT_LENGTH_BYTES = 16;
    private static final int IV_LENGTH_BYTES = 16;
    private static final String KDF_ALG = "PBKDF2WithHmacSHA256";
    private static final String AES_ALG = "AES";
    private static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";

    public static void main(String[] args) throws Exception {
        String password = "MyDifficultPassw";
        String plaintext = "tryToEncrypt";

        if (password == null || password.isBlank()) {
            throw new IllegalArgumentException("Password must not be empty.");
        }
        if (plaintext == null) {
            throw new IllegalArgumentException("Plaintext must not be null.");
        }

        byte[] salt = generateRandomBytes(SALT_LENGTH_BYTES);
        byte[] iv = generateRandomBytes(IV_LENGTH_BYTES);

        SecretKey key = deriveKey(password.toCharArray(), salt);

        byte[] ciphertext = encrypt(plaintext.getBytes(StandardCharsets.UTF_8), key, iv);
        String saltHex = toHex(salt);
        String ivHex = toHex(iv);
        String cipherHex = toHex(ciphertext);

        System.out.println("SALT  (hex): " + saltHex);
        System.out.println("IV    (hex): " + ivHex);
        System.out.println("CIPH  (hex): " + cipherHex);

        String decrypted = new String(decrypt(ciphertext, key, iv), StandardCharsets.UTF_8);
        System.out.println("DECRYPTED: " + decrypted);

        zeroCharArray(password.toCharArray());
        zeroByteArray(salt);
        zeroByteArray(iv);
        zeroSecretKey(key);
    }

    private static byte[] encrypt(byte[] plaintext, SecretKey key, byte[] iv)
            throws GeneralSecurityException {
        if (plaintext == null || plaintext.length == 0) {
            throw new IllegalArgumentException("Plaintext must not be empty.");
        }
        if (iv == null || iv.length != IV_LENGTH_BYTES) {
            throw new IllegalArgumentException("Invalid IV length.");
        }

        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(plaintext);
    }

    private static byte[] decrypt(byte[] ciphertext, SecretKey key, byte[] iv)
            throws GeneralSecurityException {
        if (ciphertext == null || ciphertext.length == 0) {
            throw new IllegalArgumentException("Ciphertext must not be empty.");
        }
        if (iv == null || iv.length != IV_LENGTH_BYTES) {
            throw new IllegalArgumentException("Invalid IV length.");
        }

        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(ciphertext);
    }

    private static SecretKey deriveKey(char[] password, byte[] salt)
            throws GeneralSecurityException {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password must not be empty.");
        }
        if (salt == null || salt.length != SALT_LENGTH_BYTES) {
            throw new IllegalArgumentException("Invalid salt length.");
        }

        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_SIZE_BITS);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALG);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        SecretKey key = new SecretKeySpec(keyBytes, AES_ALG);
        zeroCharArray(spec.getPassword());
        zeroByteArray(keyBytes);
        return key;
    }

    private static byte[] generateRandomBytes(int length) throws GeneralSecurityException {
        if (length <= 0) {
            throw new IllegalArgumentException("Length must be positive.");
        }
        byte[] bytes = new byte[length];
        SecureRandom.getInstanceStrong().nextBytes(bytes);
        return bytes;
    }

    private static String toHex(byte[] buf) {
        if (buf == null) {
            return "";
        }
        StringBuilder result = new StringBuilder(buf.length * 2);
        for (byte b : buf) {
            int v = b & 0xFF;
            if (v < 16) {
                result.append('0');
            }
            result.append(Integer.toHexString(v).toUpperCase());
        }
        return result.toString();
    }

    @SuppressWarnings("unused")
    private static byte[] fromHex(String hex) {
        if (hex == null || hex.length() == 0 || hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must be non-empty and even length.");
        }
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(hex.charAt(i), 16);
            int lo = Character.digit(hex.charAt(i + 1), 16);
            if (hi == -1 || lo == -1) {
                throw new IllegalArgumentException("Invalid hex character.");
            }
            out[i / 2] = (byte) ((hi << 4) + lo);
        }
        return out;
    }

    private static void zeroCharArray(char[] data) {
        if (data != null) {
            Arrays.fill(data, '\0');
        }
    }

    private static void zeroByteArray(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }

    private static void zeroSecretKey(SecretKey key) {
        if (key != null) {
            byte[] encoded = key.getEncoded();
            if (encoded != null) {
                zeroByteArray(encoded);
            }
        }
    }
}
