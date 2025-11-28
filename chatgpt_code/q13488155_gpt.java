import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Objects;

public class SecureHtmlFolderCrypto {

    private static final String AES_ALG = "AES";
    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int AES_KEY_BITS = 256;
    private static final int PBKDF2_ITERATIONS = 100_000;
    private static final int SALT_LENGTH_BYTES = 16;
    private static final int IV_LENGTH_BYTES = 12;

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            throw new IllegalArgumentException(
                    "Usage: <encrypt|decrypt> <inputDir> <outputDir> <password>");
        }

        String mode = args[0].trim().toLowerCase();
        Path inputDir = Paths.get(args[1]);
        Path outputDir = Paths.get(args[2]);
        char[] password = args[3].toCharArray();

        validateDirectories(inputDir, outputDir);
        if (!"encrypt".equals(mode) && !"decrypt".equals(mode)) {
            throw new IllegalArgumentException("Mode must be 'encrypt' or 'decrypt'.");
        }

        try {
            if ("encrypt".equals(mode)) {
                encryptFolder(inputDir, outputDir, password);
            } else {
                decryptFolder(inputDir, outputDir, password);
            }
        } finally {
            zeroCharArray(password);
        }
    }

    private static void validateDirectories(Path inputDir, Path outputDir) throws IOException {
        Objects.requireNonNull(inputDir);
        Objects.requireNonNull(outputDir);
        if (!Files.isDirectory(inputDir)) {
            throw new IllegalArgumentException("Input path must be an existing directory.");
        }
        if (!Files.exists(outputDir)) {
            Files.createDirectories(outputDir);
        } else if (!Files.isDirectory(outputDir)) {
            throw new IllegalArgumentException("Output path must be a directory.");
        }
    }

    private static void encryptFolder(Path inputDir, Path outputDir, char[] password)
            throws IOException, GeneralSecurityException {
        try (SecureRandom rng = SecureRandom.getInstanceStrong()) {
            Files.walk(inputDir)
                    .filter(p -> Files.isRegularFile(p) && p.toString().toLowerCase().endsWith(".html"))
                    .forEach(p -> {
                        try {
                            Path relative = inputDir.relativize(p);
                            Path target = outputDir.resolve(relative.toString() + ".enc");
                            Files.createDirectories(target.getParent());
                            encryptFile(p, target, password, rng);
                        } catch (Exception e) {
                            throw new RuntimeException("Failed to encrypt file: " + p, e);
                        }
                    });
        }
    }

    private static void decryptFolder(Path inputDir, Path outputDir, char[] password)
            throws IOException, GeneralSecurityException {
        Files.walk(inputDir)
                .filter(p -> Files.isRegularFile(p) && p.toString().toLowerCase().endsWith(".enc"))
                .forEach(p -> {
                    try {
                        Path relative = inputDir.relativize(p);
                        String originalName = relative.toString();
                        if (originalName.toLowerCase().endsWith(".html.enc")) {
                            originalName = originalName.substring(0, originalName.length() - 4);
                        } else {
                            originalName = originalName.substring(0, originalName.length() - 4) + ".html";
                        }
                        Path target = outputDir.resolve(originalName);
                        Files.createDirectories(target.getParent());
                        decryptFile(p, target, password);
                    } catch (Exception e) {
                        throw new RuntimeException("Failed to decrypt file: " + p, e);
                    }
                });
    }

    private static void encryptFile(Path inputFile, Path outputFile, char[] password, SecureRandom rng)
            throws IOException, GeneralSecurityException {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        byte[] iv = new byte[IV_LENGTH_BYTES];
        rng.nextBytes(salt);
        rng.nextBytes(iv);

        SecretKey key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        try (BufferedInputStream in = new BufferedInputStream(Files.newInputStream(inputFile));
             BufferedOutputStream out = new BufferedOutputStream(Files.newOutputStream(outputFile,
                     StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING))) {

            out.write(salt);
            out.write(iv);

            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                byte[] enc = cipher.update(buffer, 0, read);
                if (enc != null && enc.length > 0) {
                    out.write(enc);
                }
            }
            byte[] finalBytes = cipher.doFinal();
            if (finalBytes != null && finalBytes.length > 0) {
                out.write(finalBytes);
            }
            out.flush();
        } finally {
            zeroByteArray(salt);
            zeroByteArray(iv);
            zeroSecretKey(key);
        }
    }

    private static void decryptFile(Path inputFile, Path outputFile, char[] password)
            throws IOException, GeneralSecurityException {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        byte[] iv = new byte[IV_LENGTH_BYTES];

        try (BufferedInputStream in = new BufferedInputStream(Files.newInputStream(inputFile))) {
            if (in.read(salt) != SALT_LENGTH_BYTES) {
                throw new IllegalStateException("Invalid file format (salt).");
            }
            if (in.read(iv) != IV_LENGTH_BYTES) {
                throw new IllegalStateException("Invalid file format (iv).");
            }

            SecretKey key = deriveKey(password, salt);
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);

            try (BufferedOutputStream out = new BufferedOutputStream(Files.newOutputStream(outputFile,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING))) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = in.read(buffer)) != -1) {
                    byte[] dec = cipher.update(buffer, 0, read);
                    if (dec != null && dec.length > 0) {
                        out.write(dec);
                    }
                }
                byte[] finalBytes = cipher.doFinal();
                if (finalBytes != null && finalBytes.length > 0) {
                    out.write(finalBytes);
                }
                out.flush();
            } finally {
                zeroSecretKey(key);
            }
        } finally {
            zeroByteArray(salt);
            zeroByteArray(iv);
        }
    }

    private static SecretKey deriveKey(char[] password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, AES_KEY_BITS);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] encoded = factory.generateSecret(spec).getEncoded();
        SecretKey key = new SecretKeySpec(encoded, AES_ALG);
        zeroCharArray(spec.getPassword());
        zeroByteArray(encoded);
        return key;
    }

    private static void zeroCharArray(char[] array) {
        if (array != null) {
            java.util.Arrays.fill(array, '\0');
        }
    }

    private static void zeroByteArray(byte[] array) {
        if (array != null) {
            java.util.Arrays.fill(array, (byte) 0);
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

    public static String decryptHtmlToString(Path encryptedFile, char[] password) throws Exception {
        Path tempFile = Files.createTempFile("decrypted_html_", ".html");
        try {
            decryptFile(encryptedFile, tempFile, password);
            byte[] bytes = Files.readAllBytes(tempFile);
            return new String(bytes, StandardCharsets.UTF_8);
        } finally {
            Files.deleteIfExists(tempFile);
            zeroCharArray(password);
        }
    }
}
