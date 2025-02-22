# main.py
from server import Server
from client import Client

def main():
    """Main function to demonstrate the secure messaging system."""
    server = Server()

    # Start the server in a separate thread
    import threading
    server_thread = threading.Thread(target=server.start_server, args=("127.0.0.1", 65432))
    server_thread.daemon = True
    server_thread.start()

    # User Registration
    alice = Client("123456789")
    bob = Client("987654321")

    server.register_user(alice.phone_number, alice.get_public_key_pem())
    server.register_user(bob.phone_number, bob.get_public_key_pem())

    # Alice sends a message to Bob
    message = b"Hello, Bob!"
    alice.send_by_secure_channel(server, bob.phone_number, message)

    # Bob retrieves and decrypts the message
    messages = server.retrieve_messages(bob.phone_number)
    for message_data in messages:
        decrypted_message = bob.decrypt_message(
            message_data["encrypted_session_key"],
            message_data["iv"],
            message_data["encrypted_message"],
            message_data["hmac"]
        )
        print(f"Bob received message: {decrypted_message.decode()}")

if __name__ == "__main__":
    main()
