from cryptography.hazmat.primitives import serialization
import threading

class Server:
    def __init__(self):
        """Initialize the server with user and message storage and a threading lock for synchronization."""
        self.users = {}
        self.messages = {}
        self.lock = threading.Lock()

    def register_user(self, phone_number, public_key_pem):
        """Register a user with their phone number and public key.

        Args:
            phone_number (str): The phone number of the user.
            public_key_pem (bytes): The PEM-encoded public key of the user.

        Raises:
            ValueError: If the user is already registered.
        """
        with self.lock:
            if phone_number in self.users:
                raise ValueError("User already registered")
            self.users[phone_number] = serialization.load_pem_public_key(public_key_pem)
            print(f"User {phone_number} registered successfully.")

    def store_message(self, recipient_phone, message_data):
        """Store an encrypted message for a specific recipient, limiting to two messages.

        Args:
            recipient_phone (str): The phone number of the recipient.
            message_data (dict): The encrypted message data.
        """
        with self.lock:
            if recipient_phone not in self.messages:
                self.messages[recipient_phone] = []
            if len(self.messages[recipient_phone]) >= 2:
                self.messages[recipient_phone].pop(0)  # Remove the oldest message
            self.messages[recipient_phone].append(message_data)

    def retrieve_messages(self, phone_number):
        """Retrieve all messages for a specific phone number.

        Args:
            phone_number (str): The phone number of the recipient.

        Returns:
            list: A list of messages for the recipient.
        """
        with self.lock:
            return self.messages.pop(phone_number, [])

    def handle_client(self, client_socket):
        """Handle communication with a connected client (placeholder for actual logic).

        Args:
            client_socket (socket.socket): The client socket connection.
        """
        pass

    def start_server(self, host, port):
        """Start the server and listen for incoming connections.

        Args:
            host (str): The host address to bind the server to.
            port (int): The port number to listen on.
        """
        import socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"Server started on {host}:{port}")

        while True:
            client_socket, addr = server_socket.accept()
            print(f"Connection from {addr}")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()

