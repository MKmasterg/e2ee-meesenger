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
    
    @Override
    public void run() {
        try (Connection conn = DriverManager.getConnection(dbUrl)) {
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);

            while (true) {
                String line = in.readLine();
                if (line == null) break;

                // Expecting basic JSON-like format (manual parsing for now)
                Map<String, String> msg = parseMessage(line);
                String type = msg.get("type");

                switch (type) {
                    case "register":
                        handleRegister(msg);
                        break;
                    case "login":
                        handleLogin(msg);
                        break;
                    case "get_key":
                        handleGetKey(msg);
                        break;
                    case "message":
                        handleMessage(msg);
                        break;
                    default:
                        out.println("Unknown command.");
                }
            }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        } finally {
            if (username != null) {
                clients.remove(username);
                System.out.println(username + " disconnected.");
            }
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

    private void handleRegister(Map<String, String> msg) {
        String username = msg.get("username");
        String password = msg.get("password");

        if (username == null || password == null) {
            out.println("Invalid registration data.");
            return;
        }

        String[] passwordHashed = EncryptionUtils.passwordHashString(password);
        String saltBase64 = passwordHashed[0];
        String passwordHashBase64 = passwordHashed[1];
        KeyPair publicKey = EncryptionUtils.generateKeyPair();

        // Register
        try {
            db.server.Utils.registerUser(username, passwordHashBase64, saltBase64, publicKey.getPublic().toString());
        } catch (Exception e) {
            out.println("Error registering user: " + e.getMessage());
        }
    }


}