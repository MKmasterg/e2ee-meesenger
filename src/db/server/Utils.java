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
    public static String validateSession(String sessionId) {
        SessionInfo info = sessions.get(sessionId);
        if (info != null && info.expiresAt > System.currentTimeMillis()) {
            return info.username;
        }
        sessions.remove(sessionId); // Remove expired session
        return null;
    }

    public static String getPublicKeyIfSessionValid(String sessionId, String targetUsername) {
        String currentUser = validateSession(sessionId);
        if (currentUser == null) {
            return null;
        }
        String sql = "SELECT publickey FROM users WHERE username = ?";
        try (Connection conn = connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, targetUsername);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("publickey");
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }
}
