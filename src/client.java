import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import enc.EncryptionUtils; // You must implement these methods in your EncryptionUtils class

public class Client {
    private static KeyPair keyPair;
    private static String sessionID = null;
    private static String username = null;
    private static Map<String, PublicKey> userPublicKeys = new HashMap<>(); // Cache for public keys
    private String line = null;
    private static volatile String pendingSessionID = null;
    private static volatile String pendingPublicKeyBase64 = null;

    // Save private key to file
    private static void savePrivateKeyToFile(String username, PrivateKey privateKey) throws Exception {
        FileOutputStream fos = new FileOutputStream(username + ".key");
        fos.write(privateKey.getEncoded());
        fos.close();
    }

    // Load private key from file
    private static PrivateKey loadPrivateKeyFromFile(String username) throws Exception {
        File file = new File(username + ".key");
        if (!file.exists()) return null;
        FileInputStream fis = new FileInputStream(file);
        byte[] keyBytes = new byte[(int) file.length()];
        fis.read(keyBytes);
        fis.close();
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public static void main(String[] args) {
        String serverAddress = "localhost";
        int port = 12345;
        try (Scanner scanner = new Scanner(System.in);
             Socket socket = new Socket(serverAddress, port);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

            System.out.println("Connected to server at " + serverAddress + ":" + port);

            // Thread to listen for server messages
            Thread listener = new Thread(() -> {
                try {
                    String line;
                    while ((line = in.readLine()) != null) {
                        // Split type and payload
                        String[] parts = line.split(":", 2);
                        String type = parts[0];
                        String payload = parts.length > 1 ? parts[1] : "";

                        switch (type) {
                            case "user_message":
                                // Format: username:encryptedMessage
                                String[] msgParts = payload.split(":", 2);
                                if (msgParts.length == 2) {
                                    String fromUser = msgParts[0];
                                    String encryptedMsg = msgParts[1];
                                    try {
                                        if (keyPair != null && keyPair.getPrivate() != null) {
                                            String decrypted = EncryptionUtils.decryptWithPrivateKey(encryptedMsg, keyPair.getPrivate());
                                            System.out.println("[Message from " + fromUser + "] " + decrypted);
                                        } else {
                                            System.out.println("[Message from " + fromUser + "] (Cannot decrypt)");
                                        }
                                    } catch (Exception ex) {
                                        System.out.println("[Message from " + fromUser + "] (Decryption failed) : " + ex.getMessage());
                                    }
                                }
                                break;
                            case "server_response":
                                System.out.println("[Server] " + payload);
                                if (payload.startsWith("login_ok,sessionID:")) {
                                    synchronized (Client.class) {
                                        pendingSessionID = payload.split("sessionID:")[1];
                                        Client.class.notifyAll();
                                    }
                                } else if (payload.startsWith("fetch_ok,publicKey:")) {
                                    synchronized (Client.class) {
                                        String[] pkParts = payload.split("publicKey:");
                                        if (pkParts.length > 1) {
                                            pendingPublicKeyBase64 = pkParts[1].trim();
                                            Client.class.notifyAll();
                                        }
                                    }
                                }
                                break;
                            default:
                                System.out.println("[Server] " + line);
                                break;
                        }
                    }
                } catch (Exception e) {
                    System.out.println("[Client] Connection closed.");
                }
            });
            listener.setDaemon(true);
            listener.start();

            // Main menu loop
            while (true) {
                System.out.println("\nChoose: [1] Register  [2] Login  [3] Send Message  [4] Quit");
                String choice = scanner.nextLine().trim();

                if (choice.equals("1")) {
                    // Register
                    System.out.print("Username: ");
                    username = scanner.nextLine().trim();
                    System.out.print("Password: ");
                    String password = scanner.nextLine().trim();

                    keyPair = EncryptionUtils.generateKeyPair();
                    String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

                    // Save private key to file
                    try {
                        savePrivateKeyToFile(username, keyPair.getPrivate());
                    } catch (Exception e) {
                        System.out.println("[Client] Failed to save private key: " + e.getMessage());
                    }

                    String regMsg = String.format("type:register,username:%s,password:%s,publicKey:%s", username, password, publicKeyBase64);
                    out.println(regMsg);

                } else if (choice.equals("2")) {
                    // Login
                    System.out.print("Username: ");
                    username = scanner.nextLine().trim();
                    System.out.print("Password: ");
                    String password = scanner.nextLine().trim();

                    // Try to load private key from file
                    try {
                        PrivateKey privKey = loadPrivateKeyFromFile(username);
                        if (privKey != null) {
                            // Reconstruct keyPair with null public key (not needed for decryption)
                            keyPair = new KeyPair(null, privKey);
                        } else {
                            System.out.println("[Client] No private key found for this user. You must register first.");
                        }
                    } catch (Exception e) {
                        System.out.println("[Client] Failed to load private key: " + e.getMessage());
                    }

                    String loginMsg = String.format("type:login,username:%s,password:%s", username, password);
                    out.println(loginMsg);

                    // Wait for sessionID from listener
                    synchronized (Client.class) {
                        while (pendingSessionID == null) {
                            Client.class.wait();
                        }
                        sessionID = pendingSessionID;
                        pendingSessionID = null;
                        System.out.println("[Client] SessionID set.");
                    }

                } else if (choice.equals("3")) {
                    // Send message
                    if (sessionID == null) {
                        System.out.println("[Client] You must login first.");
                        continue;
                    }
                    System.out.print("Target username: ");
                    String targetUser = scanner.nextLine().trim();
                    System.out.print("Message: ");
                    String message = scanner.nextLine().trim();

                    // Get target user's public key (in a real app, fetch from server or cache)
                    PublicKey targetPublicKey = userPublicKeys.get(targetUser);
                    if (targetPublicKey == null) {
                        System.out.println("[Client] Fetching public key for " + targetUser + "...");
                        pendingPublicKeyBase64 = null;
                        out.println("type:get_public_key,username:" + targetUser);
                        synchronized (Client.class) {
                            while (pendingPublicKeyBase64 == null) {
                                Client.class.wait();
                            }
                            String pkBase64 = pendingPublicKeyBase64;
                            pendingPublicKeyBase64 = null;
                            targetPublicKey = EncryptionUtils.decodePublicKey(pkBase64);
                            userPublicKeys.put(targetUser, targetPublicKey);
                        }
                    }

                    String encryptedMsg = EncryptionUtils.encryptWithPublicKey(message, targetPublicKey);
                    String msg = String.format("type:message,sessionID:%s,targetUsername:%s,message:%s", sessionID, targetUser, encryptedMsg);
                    out.println(msg);

                } else if (choice.equals("4") || choice.equalsIgnoreCase("/quit")) {
                    out.println("type:logout");
                    break;
                } else {
                    System.out.println("Invalid choice.");
                }
            }

            System.out.println("[Client] Disconnected.");
        } catch (Exception e) {
            System.out.println("[Client] Error: " + e.getMessage());
        }
    }
}