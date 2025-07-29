package enc;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import java.security.KeyFactory;
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

    public static String decryptWithPrivateKey(String encryptedMsg, PrivateKey privateKey) {
        try {
            // Decrypt the message using the private key
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMsg));
            return new String(decryptedBytes, "UTF-8");
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting message with private key", e);
        }
    }

    public static PublicKey decodePublicKey(String pkBase64) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(pkBase64);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            throw new RuntimeException("Error decoding public key", e);
        }
    }

    public static String encryptWithPublicKey(String message, PublicKey targetPublicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, targetPublicKey);
            byte[] encryptedBytes = cipher.doFinal(message.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting message with public key", e);
        }
    }
}
