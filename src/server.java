import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ConcurrentHashMap;

public class Server {
    private static final int PORT = 12345;
    private static final String DB_URL = "jdbc:sqlite:users.db";

    // Map of currently connected clients
    private static ConcurrentHashMap<String, ClientHandler> clients = new ConcurrentHashMap<>();

    public static void main(String[] args) throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server started on port " + PORT);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                new Thread(new ClientHandler(clientSocket, DB_URL, clients)).start();
            }
        }
    }
}
