import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;

public final class ListAvailableHashAlgorithms {

    public static void main(String[] args) {
        Set<String> algorithms = new TreeSet<>();

        Security.getProviders().forEach(provider ->
                provider.getServices().forEach(service -> {
                    if ("MessageDigest".equalsIgnoreCase(service.getType())) {
                        String alg = service.getAlgorithm();
                        if (alg != null && !alg.isBlank()) {
                            algorithms.add(alg.toUpperCase());
                        }
                    }
                })
        );

        for (String alg : algorithms) {
            if (isDigestSupported(alg)) {
                System.out.println(alg);
            }
        }
    }

    private static boolean isDigestSupported(String algorithm) {
        try {
            MessageDigest.getInstance(algorithm);
            return true;
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }
}
