# E2EE Messenger

A simple end-to-end encrypted (E2EE) messenger written in Java. This project demonstrates secure user registration, authentication, and encrypted messaging using RSA public/private key cryptography and password hashing with salt.

## Features

- User registration with salted password hashing and RSA key pair generation
- User authentication with session management
- Public key retrieval for secure message encryption
- End-to-end encrypted messaging between online users (server only would relay the encrypted messages)
- SQLite database for user and session storage

## Project Structure

- `src/`
  - `Server.java` — Starts the server and listens for client connections
  - `ClientHandler.java` — Handles each client connection and protocol logic
  - `Client.java` — Command-line client for interacting with the server
  - `db/server/Utils.java` — Database and session utilities
  - `enc/EncryptionUtils.java` — Cryptographic utilities (hashing, key generation, encryption/decryption)

## Getting Started

1. **Build**  
   Compile all Java files in the `src` directory.  
   Example:
   ```sh
   javac -cp lib/sqlite-jdbc-3.50.3.0.jar src/**/*.java
   ```
   **Note:** Ensure you have the SQLite JDBC driver in the `lib/` directory or the directory where the driver is located.

2. **Run the Server**  
   ```sh
   java -cp "lib/sqlite-jdbc-3.50.3.0.jar;src" Server
   ```

3. **Run the Client**  
   ```sh
   java -cp "lib/sqlite-jdbc-3.50.3.0.jar;src" Client
   ```

## Notes

- Each user generates and stores their private key locally (`<username>.key`).
- The server never sees or stores user private keys.
- Only online users can receive messages in real time.

## Requirements

- Java 8 or higher
- [sqlite-jdbc](https://github.com/xerial/sqlite-jdbc)

## License
This project is for educational purposes.

Distributed under the [MIT License](LICENSE).
