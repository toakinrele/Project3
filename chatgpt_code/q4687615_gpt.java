import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Objects;

public class SecureFileTransfer {

    // ---------------------- SERVER ----------------------
    public static class FileServer {
        private final int port;
        private final Path baseDirectory;

        public FileServer(int port, Path baseDirectory) {
            if (port <= 0 || port > 65535) throw new IllegalArgumentException("Invalid port.");
            Objects.requireNonNull(baseDirectory);
            this.port = port;
            this.baseDirectory = baseDirectory;
        }

        public void start() throws Exception {
            if (!Files.isDirectory(baseDirectory)) {
                throw new IllegalArgumentException("Base directory must exist.");
            }

            try (ServerSocket serverSocket = new ServerSocket(port)) {
                while (true) {
                    try (Socket socket = serverSocket.accept()) {
                        handleClient(socket);
                    }
                }
            }
        }

        private void handleClient(Socket socket) throws Exception {
            try (
                DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
                DataOutputStream out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()))
            ) {
                String command = in.readUTF();
                if ("UPLOAD".equals(command)) {
                    receiveFile(in, out);
                } else if ("DOWNLOAD".equals(command)) {
                    sendFile(in, out);
                }
            }
        }

        private void receiveFile(DataInputStream in, DataOutputStream out) throws Exception {
            String fileName = sanitize(in.readUTF());
            long fileSize = in.readLong();

            if (fileSize < 0 || fileSize > (1024L * 1024L * 1024L)) {
                throw new IllegalArgumentException("Invalid file size.");
            }

            Path target = baseDirectory.resolve(fileName);
            try (OutputStream fileOut = new BufferedOutputStream(
                    Files.newOutputStream(target, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING))) {

                byte[] buffer = new byte[8192];
                long remaining = fileSize;
                while (remaining > 0) {
                    int read = in.read(buffer, 0, (int) Math.min(buffer.length, remaining));
                    if (read == -1) throw new IllegalStateException("Unexpected end of stream.");
                    fileOut.write(buffer, 0, read);
                    remaining -= read;
                }
            }

            out.writeUTF("UPLOAD_OK");
            out.flush();
        }

        private void sendFile(DataInputStream in, DataOutputStream out) throws Exception {
            String fileName = sanitize(in.readUTF());
            Path filePath = baseDirectory.resolve(fileName);

            if (!Files.isRegularFile(filePath)) {
                out.writeUTF("ERROR_NOT_FOUND");
                out.flush();
                return;
            }

            long fileSize = Files.size(filePath);
            out.writeUTF("DOWNLOAD_OK");
            out.writeLong(fileSize);

            try (InputStream fileIn = new BufferedInputStream(Files.newInputStream(filePath))) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = fileIn.read(buffer)) != -1) {
                    out.write(buffer, 0, read);
                }
            }

            out.flush();
        }

        private String sanitize(String name) {
            if (name == null || name.isBlank() || name.contains("..") || name.contains("/") || name.contains("\\")) {
                throw new IllegalArgumentException("Invalid filename.");
            }
            return name;
        }

        public static void main(String[] args) throws Exception {
            if (args.length != 2) throw new IllegalArgumentException("Usage: <port> <directory>");
            int port = Integer.parseInt(args[0]);
            Path dir = Path.of(args[1]);
            new FileServer(port, dir).start();
        }
    }

    // ---------------------- CLIENT ----------------------
    public static class FileClient {
        private final String host;
        private final int port;

        public FileClient(String host, int port) {
            if (host == null || host.isBlank()) throw new IllegalArgumentException("Invalid host.");
            if (port <= 0 || port > 65535) throw new IllegalArgumentException("Invalid port.");
            this.host = host;
            this.port = port;
        }

        public void uploadFile(Path filePath, String remoteName) throws Exception {
            if (!Files.isRegularFile(filePath)) throw new IllegalArgumentException("File does not exist.");
            remoteName = sanitize(remoteName);

            long fileSize = Files.size(filePath);

            try (Socket socket = new Socket(host, port);
                 DataOutputStream out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
                 DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
                 InputStream fileIn = new BufferedInputStream(Files.newInputStream(filePath))) {

                out.writeUTF("UPLOAD");
                out.writeUTF(remoteName);
                out.writeLong(fileSize);

                byte[] buffer = new byte[8192];
                int read;
                while ((read = fileIn.read(buffer)) != -1) {
                    out.write(buffer, 0, read);
                }
                out.flush();

                String response = in.readUTF();
                if (!"UPLOAD_OK".equals(response)) throw new IllegalStateException(response);
            }
        }

        public void downloadFile(String remoteName, Path localTarget) throws Exception {
            remoteName = sanitize(remoteName);

            try (Socket socket = new Socket(host, port);
                 DataOutputStream out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
                 DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()))) {

                out.writeUTF("DOWNLOAD");
                out.writeUTF(remoteName);
                out.flush();

                String status = in.readUTF();
                if (!"DOWNLOAD_OK".equals(status)) {
                    throw new IllegalStateException(status);
                }

                long size = in.readLong();
                if (size < 0 || size > (1024L * 1024L * 1024L)) {
                    throw new IllegalArgumentException("Invalid file size.");
                }

                try (OutputStream fileOut = new BufferedOutputStream(
                        Files.newOutputStream(localTarget, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING))) {
                    byte[] buffer = new byte[8192];
                    long remaining = size;
                    while (remaining > 0) {
                        int read = in.read(buffer, 0, (int) Math.min(buffer.length, remaining));
                        if (read == -1) throw new IllegalStateException("Unexpected end of stream.");
                        fileOut.write(buffer, 0, read);
                        remaining -= read;
                    }
                }
            }
        }

        private String sanitize(String name) {
            if (name == null || name.isBlank() || name.contains("..") || name.contains("/") || name.contains("\\")) {
                throw new IllegalArgumentException("Invalid filename.");
            }
            return name;
        }

        public static void main(String[] args) throws Exception {
            if (args.length != 4) {
                throw new IllegalArgumentException("Usage: <host> <port> <upload|download> <file>");
            }

            FileClient client = new FileClient(args[0], Integer.parseInt(args[1]));
            String mode = args[2];

            if ("upload".equalsIgnoreCase(mode)) {
                client.uploadFile(Path.of(args[3]), Path.of(args[3]).getFileName().toString());
            } else if ("download".equalsIgnoreCase(mode)) {
                client.downloadFile(args[3], Path.of(args[3]));
            } else {
                throw new IllegalArgumentException("Invalid mode.");
            }
        }
    }
}
