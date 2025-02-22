# client.py
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
import os

class Client:
    def __init__(self, phone_number):
        """Initialize the client with a phone number and generate RSA key pair.

        Args:
            phone_number (str): The phone number of the client.
        """
        self.phone_number = phone_number
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    def get_public_key_pem(self):
        """Retrieve the public key in PEM format.

        Returns:
            bytes: The PEM-encoded public key.
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def create_hmac(self, key, data):
        """Create an HMAC for the given data using the provided key.

        Args:
            key (bytes): The key for the HMAC.
            data (bytes): The data to authenticate.

        Returns:
            bytes: The generated HMAC.
        """
        hmac = HMAC(key, hashes.SHA256())
        hmac.update(data)
        return hmac.finalize()

    def verify_hmac(self, key, data, hmac_to_verify):
        """Verify an HMAC for the given data.

        Args:
            key (bytes): The key for the HMAC.
            data (bytes): The data to authenticate.
            hmac_to_verify (bytes): The HMAC to verify.

        Raises:
            cryptography.exceptions.InvalidSignature: If the HMAC is invalid.
        """
        hmac = HMAC(key, hashes.SHA256())
        hmac.update(data)
        hmac.verify(hmac_to_verify)

    def encrypt_message(self, recipient_public_key, message):
        """Encrypt a message using AES and RSA for the session key.

        Args:
            recipient_public_key: The recipient's RSA public key.
            message (bytes): The plaintext message.

        Returns:
            tuple: Encrypted session key, IV, encrypted message, and HMAC.
        """
        session_key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padded_message = message + b' ' * (16 - len(message) % 16)
        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

        encrypted_session_key = recipient_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        hmac = self.create_hmac(session_key, encrypted_message)
        return encrypted_session_key, iv, encrypted_message, hmac

    def decrypt_message(self, encrypted_session_key, iv, encrypted_message, hmac):
        """Decrypt an encrypted message.

        Args:
            encrypted_session_key (bytes): The encrypted session key.
            iv (bytes): The initialization vector.
            encrypted_message (bytes): The encrypted message.
            hmac (bytes): The HMAC of the message.

        Returns:
            bytes: The decrypted plaintext message.

        Raises:
            cryptography.exceptions.InvalidSignature: If the HMAC verification fails.
        """
        session_key = self.private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        self.verify_hmac(session_key, encrypted_message, hmac)

        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
        return padded_message.rstrip(b' ')

    def send_by_secure_channel(self, server, recipient_phone, message):
        """Send a message securely via the server.

        Args:
            server (Server): The server instance.
            recipient_phone (str): The recipient's phone number.
            message (bytes): The plaintext message to send.

        Prints:
            The encrypted and authentication steps of the message.
        """
        recipient_public_key = server.users.get(recipient_phone)
        if not recipient_public_key:
            raise ValueError("Recipient not found")

        encrypted_session_key, iv, encrypted_message, hmac = self.encrypt_message(
            recipient_public_key, message
        )

        print("Session key and message successfully encrypted.")

        message_data = {
            "encrypted_session_key": encrypted_session_key,
            "iv": iv,
            "encrypted_message": encrypted_message,
            "hmac": hmac
        }
        server.store_message(recipient_phone, message_data)
        print("Message stored on server.")
