package db.server;

import java.sql.*;
import java.util.HashMap;
import java.util.Map;

public class Utils {
    private static final String DB_URL = "jdbc:sqlite:e2ee-messenger.db";
    private static final long SESSION_DURATION_MS = 30 * 60 * 1000; // 30 minutes

    // Simple session store: sessionId -> [username, expirationTime]
    private static final Map<String, SessionInfo> sessions = new HashMap<>();

    private static class SessionInfo {
        String username;
        long expiresAt;
        SessionInfo(String username, long expiresAt) {
            this.username = username;
            this.expiresAt = expiresAt;
        }
    }

    // Connect to SQLite database
    public static Connection connect() throws SQLException {
        return DriverManager.getConnection(DB_URL);
    }

    // Create users table
    public static void createUsersTable() {
        String sql = "CREATE TABLE IF NOT EXISTS users (" +
                     "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                     "username TEXT UNIQUE NOT NULL," +
                     "password TEXT NOT NULL," +
                     "info TEXT" +
                     ");";
        try (Connection conn = connect();
             Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // Insert a new user with password hash (base64), salt (base64), and public key
    public static boolean addUser(String username, String passwordHashBase64, String saltBase64, String publicKeyBase64) {
        String sql = "INSERT INTO users(username, passwordhashed, salt, publickey) VALUES (?, ?, ?, ?)";
        try (Connection conn = connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            pstmt.setString(2, passwordHashBase64);
            pstmt.setString(3, saltBase64);
            pstmt.setString(4, publicKeyBase64);
            pstmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void registerUser(String username, String passwordHashBase64, String saltBase64, String publicKeyBase64) throws Exception {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be empty.");
        }
        if (passwordHashBase64 == null || passwordHashBase64.isEmpty() ||
            saltBase64 == null || saltBase64.isEmpty() ||
            publicKeyBase64 == null || publicKeyBase64.isEmpty()) {
            throw new IllegalArgumentException("Password, salt, and public key must be provided.");
        }
        // Check if user already exists
        String checkSql = "SELECT 1 FROM users WHERE username = ?";
        try (Connection conn = connect();
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            checkStmt.setString(1, username);
            try (ResultSet rs = checkStmt.executeQuery()) {
                if (rs.next()) {
                    throw new IllegalStateException("Username already exists.");
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
            throw new Exception("Database error during user check.", e);
        }
        // Try to add user
        boolean success = addUser(username, passwordHashBase64, saltBase64, publicKeyBase64);
        if (!success) {
            throw new Exception("Failed to register user due to database error.");
        }
    }

    public static String loginUser(String username, String password) throws Exception {
        String[] stored = getPasswordAndSalt(username);
        if (stored == null) {
            throw new IllegalArgumentException("User not found.");
        }
        String passwordHash = stored[0];
        String salt = stored[1];
        // Hash the provided password with the stored salt
        String hashedInput = enc.EncryptionUtils.hashedPasswordWithSalt(password, salt);
        if (hashedInput.equals(passwordHash)) {
            return createSession(username);
        }
        throw new IllegalArgumentException("Invalid password.");
    }
    public static String[] getPasswordAndSalt(String username) {
        String sql = "SELECT passwordhashed, salt FROM users WHERE username = ?";
        try (Connection conn = connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    String passwordHash = rs.getString("passwordhashed");
                    String salt = rs.getString("salt");
                    return new String[] { passwordHash, salt };
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    // Create a session for a user (returns sessionId)
    public static String createSession(String username) {
        String sessionId = java.util.UUID.randomUUID().toString();
        long expiresAt = System.currentTimeMillis() + SESSION_DURATION_MS;
        sessions.put(sessionId, new SessionInfo(username, expiresAt));
        return sessionId;
    }

    // Validate session and return username if valid, else null
    public static boolean validateSession(String sessionId) {
        SessionInfo info = sessions.get(sessionId);
        if (info != null && info.expiresAt > System.currentTimeMillis()) {
            return true;
        }
        sessions.remove(sessionId); // Remove expired session
        return false;
    }

    public static String getPublicKeyIfSessionValid(String sessionId, String targetUsername) throws Exception {
        boolean currentUser = validateSession(sessionId);
        if (!currentUser) {
            throw new IllegalArgumentException("Invalid or expired session.");
        }
        String sql = "SELECT publickey FROM users WHERE username = ?";
        try (Connection conn = connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, targetUsername);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("publickey");
                } else {
                    throw new IllegalArgumentException("Target user does not exist.");
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
            throw new Exception("Database error during public key retrieval.", e);
        }
    }
}
