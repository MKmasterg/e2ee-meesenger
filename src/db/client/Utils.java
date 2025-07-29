package db.client;

import java.sql.*;

public class Utils {
    private static final String DB_URL = "jdbc:sqlite:client_messages.db";

    // Connect to local SQLite database
    public static Connection connect() throws SQLException {
        return DriverManager.getConnection(DB_URL);
    }

    // Create tables for received and sent messages
    public static void createTables() {
        String receivedTable = "CREATE TABLE IF NOT EXISTS received_messages (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "from_user TEXT NOT NULL," +
                "body TEXT NOT NULL," +
                "date_sent TEXT NOT NULL" +
                ");";
        String sentTable = "CREATE TABLE IF NOT EXISTS sent_messages (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "to_user TEXT NOT NULL," +
                "body TEXT NOT NULL," +
                "date_sent TEXT NOT NULL" +
                ");";
        try (Connection conn = connect();
             Statement stmt = conn.createStatement()) {
            stmt.execute(receivedTable);
            stmt.execute(sentTable);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // Save a received message (encrypted body)
    public static void saveReceivedMessage(String fromUser, String body, String dateSent) {
        String sql = "INSERT INTO received_messages(from_user, body, date_sent) VALUES (?, ?, ?)";
        try (Connection conn = connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, fromUser);
            pstmt.setString(2, body);
            pstmt.setString(3, dateSent);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // Save a sent message (encrypted body)
    public static void saveSentMessage(String toUser, String body, String dateSent) {
        String sql = "INSERT INTO sent_messages(to_user, body, date_sent) VALUES (?, ?, ?)";
        try (Connection conn = connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, toUser);
            pstmt.setString(2, body);
            pstmt.setString(3, dateSent);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
