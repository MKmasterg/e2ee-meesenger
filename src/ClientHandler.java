import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import enc.EncryptionUtils;

public class ClientHandler implements Runnable {
    private Socket socket;
    private String dbUrl;
    private BufferedReader in;
    private PrintWriter out;
    private String username;
    private ConcurrentHashMap<String, ClientHandler> clients;

    public ClientHandler(Socket socket, String dbUrl, ConcurrentHashMap<String, ClientHandler> clients) {
        this.socket = socket;
        this.dbUrl = dbUrl;
        this.clients = clients;
    }
    private Map<String, String> parseMessage(String line) {
            Map<String, String> map = new ConcurrentHashMap<>();
            if (line == null || line.trim().isEmpty()) return map;
            String[] pairs = line.split(",");
            for (String pair : pairs) {
                String[] kv = pair.split(":", 2);
                if (kv.length == 2) {
                    map.put(kv[0].trim(), kv[1].trim());
                }
            }
            return map;
    }
    
    // Helper to send a message to this client
    private void sendMessageToClient(String message) {
        out.println(message);
    }
    
    @Override
    public void run() {
        try (Connection conn = DriverManager.getConnection(dbUrl)) {
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);

            boolean authenticated = false;
            String sessionID = null;

            // 1. Require session validation or login/register before anything else
            while (!authenticated) {
                String line = in.readLine();
                if (line == null) break;
                Map<String, String> msg = parseMessage(line);
                String type = msg.get("type");

                if ("session".equals(type)) {
                    sessionID = msg.get("sessionID");
                    if (sessionID != null && db.server.Utils.validateSession(sessionID)) {
                        // Session valid, get username from session
                        this.username = getUsernameFromSession(sessionID);
                        clients.put(username, this);
                        sendMessageToClient("session_ok");
                        authenticated = true;
                        System.out.println("[Server] " + username + " authenticated via session.");
                    } else {
                        sendMessageToClient("invalid_session");
                        System.out.println("[Server] Invalid session attempt.");
                    }
                } else if ("login".equals(type)) {
                    sessionID = handleLogin(msg);
                    if (sessionID != null) {
                        this.username = msg.get("username");
                        clients.put(username, this);
                        sendMessageToClient("login_ok,sessionID:" + sessionID);
                        authenticated = true;
                        System.out.println("[Server] " + username + " logged in.");
                    } else {
                        sendMessageToClient("login_failed");
                        System.out.println("[Server] Login failed for user: " + msg.get("username"));
                    }
                } else if ("register".equals(type)) {
                    boolean regOk = handleRegister(msg);
                    if (regOk) {
                        sendMessageToClient("register_ok");
                        System.out.println("[Server] New user registered: " + msg.get("username"));
                    } else {
                        sendMessageToClient("register_failed");
                        System.out.println("[Server] Registration failed for user: " + msg.get("username"));
                    }
                } else {
                    sendMessageToClient("Please login, register, or provide a session.");
                }
            }

            // 2. Authenticated: handle messages
            while (authenticated) {
                String line = in.readLine();
                if (line == null) break;
                Map<String, String> msg = parseMessage(line);
                String type = msg.get("type");

                switch (type) {
                    case "message":
                        handleMessage(msg);
                        break;
                    case "logout":
                        sendMessageToClient("logout_ok");
                        System.out.println("[Server] " + username + " logged out.");
                        authenticated = false;
                        break;
                    default:
                        sendMessageToClient("Unknown command.");
                        System.out.println("[Server] Unknown command from " + username + ": " + type);
                }
            }
        } catch (Exception e) {
            System.out.println("[Server] Error: " + e.getMessage());
        } finally {
            if (username != null) {
                clients.remove(username);
                System.out.println("[Server] " + username + " disconnected.");
            }
        }
    }

    // Helper to get username from sessionID
    private String getUsernameFromSession(String sessionID) {
        try {
            return db.server.Utils.getUsernameBySession(sessionID);
        } catch (Exception e) {
            return null;
        }
    }

    private void handleMessage(Map<String, String> msg) {
        String sessionID = msg.get("sessionID");
        String targetUsername = msg.get("targetUsername");
        String encryptedMessage = msg.get("message");

        if (sessionID == null || targetUsername == null || encryptedMessage == null) {
            sendMessageToClient("Invalid message format.");
            System.out.println("[Server] Invalid message format from " + username);
            return;
        }

        // Validate session and check if target user is online
        try {
            boolean validSession = db.server.Utils.validateSession(sessionID);
            if (!validSession) {
                sendMessageToClient("Invalid session.");
                System.out.println("[Server] Invalid session for message from " + username);
                return;
            }

            ClientHandler targetHandler = clients.get(targetUsername);
            if (targetHandler != null) {
                // Forward the encrypted message to the target user
                targetHandler.sendMessageToClient(username + ":" + encryptedMessage);
                sendMessageToClient("Message delivered.");
                System.out.println("[Server] Message from " + username + " delivered to " + targetUsername);
            } else {
                sendMessageToClient("User not online.");
                System.out.println("[Server] User " + targetUsername + " not online for message from " + username);
            }
        } catch (Exception e) {
            sendMessageToClient("Error handling message: " + e.getMessage());
            System.out.println("[Server] Error handling message from " + username + ": " + e.getMessage());
        }
    }

    private String handleLogin(Map<String, String> msg) {
        String username = msg.get("username");
        String password = msg.get("password");

        if (username == null || password == null) {
            out.println("Invalid login data.");
            return null;
        }

        String sessionID = null;

        try {
            sessionID = db.server.Utils.loginUser(username, password);
            return sessionID;
        } catch (Exception e) {
            out.println("Error during login: " + e.getMessage());
        }
        return null;
    }

    private boolean handleRegister(Map<String, String> msg) {
        String username = msg.get("username");
        String password = msg.get("password");

        if (username == null || password == null) {
            out.println("Invalid registration data.");
            return false;
        }

        String[] passwordHashed = EncryptionUtils.passwordHashString(password);
        String saltBase64 = passwordHashed[0];
        String passwordHashBase64 = passwordHashed[1];
        KeyPair publicKey = EncryptionUtils.generateKeyPair();

        try {
            db.server.Utils.registerUser(username, passwordHashBase64, saltBase64, publicKey.getPublic().toString());
            return true;
        } catch (Exception e) {
            out.println("Error registering user: " + e.getMessage());
            return false;
        }
    }


}