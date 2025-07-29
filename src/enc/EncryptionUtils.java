package enc;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.security.KeyPair;

public class EncryptionUtils {
    public static byte[] generateSalt(int length) {
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[length];
        sr.nextBytes(salt);
        return salt;
    }
    
    public static String[] passwordHashString(String plainPassword) {

        try {
            // Generate a random salt
            byte[] salt = EncryptionUtils.generateSalt(16);

            // Combine password and salt
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] hashedPassword = md.digest(plainPassword.getBytes("UTF-8"));

            // Encode salt and hash to Base64 for storage
            String saltBase64 = Base64.getEncoder().encodeToString(salt);
            String hashBase64 = Base64.getEncoder().encodeToString(hashedPassword);

            return new String[]{saltBase64, hashBase64};
        } catch (Exception e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }
    public static String hashedPasswordWithSalt(String plainPassword, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt.getBytes("UTF-8"));
            byte[] hashedPassword = md.digest(plainPassword.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(hashedPassword);
        } catch (Exception e) {
            throw new RuntimeException("Error hashing password with salt", e);
        }
    }
    public static KeyPair generateKeyPair() {
        try {
            java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Error generating key pair", e);
        }
    }
}
