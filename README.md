# Secure End-to-End Messaging Protocol

## Overview
This project implements a secure end-to-end messaging protocol that ensures confidentiality, integrity, and authenticity of messages, even when recipients are temporarily offline. The protocol is designed to resist Man-in-the-Middle (MITM) attacks and employs cryptographic techniques for secure key exchange, message encryption, and integrity verification.

## Encryption and Key Management
- **Symmetric Encryption**: Messages are encrypted using AES-256 in CBC mode to ensure strong confidentiality.
- **Asymmetric Encryption**: RSA is used for key exchange, where each user has a unique key pair (private and public key).
- **Message Authentication**: An HMAC (Hash-based Message Authentication Code) is used to verify message integrity and authenticity.

## Registration Process
1. A new user generates an RSA key pair.
2. The public key is sent to the server along with the user’s phone number.
3. The server verifies the identity using a 6-digit authentication code sent via a secure channel.
4. Upon successful verification, the public key is stored in a database linked to the phone number.

## Secure Messaging Flow
1. **Key Exchange:**
   - When a user initiates a chat, a unique symmetric session key is generated.
   - The session key is encrypted with the recipient’s public key and sent alongside the first encrypted message.
2. **Message Encryption and Transmission:**
   - Messages are encrypted using AES-256-CBC with an initialization vector (IV) to ensure randomness.
   - An HMAC is computed and attached to the message to prevent tampering.
3. **Message Decryption and Integrity Check:**
   - The recipient decrypts the session key with their private key (only for the first message).
   - Subsequent messages are decrypted using the session key.
   - The HMAC is verified to ensure message integrity and authenticity.

## Server-Side Data Structure
- **User Table:**
  - Stores phone numbers and their associated public keys.
- **Message Queue:**
  - Each user has a limited queue (up to two messages stored temporarily).
  - Older messages are deleted when new ones arrive.

## Implementation Notes
- The server is implemented in Python with multithreading support for concurrent clients.
- Messages are stored temporarily to support asynchronous communication.
- The system does not maintain historical messages beyond the last two per user.
- No group messaging or complex user management features are included.
- The project uses the `pycryptodome` library for cryptographic operations, ensuring high-security encryption and key management.

This project was built as part of an advanced systems security assignment, focusing on practical cryptographic implementations and real-world security considerations.

## Installation and Setup
### Prerequisites
- Python 3.x installed on your system
- `pip` for managing dependencies
- Required Python libraries: `pycryptodome` for encryption, `socket` for networking, and `threading` for concurrency

### Installation Steps
1. **Clone the Repository**
   ```sh
   git clone <repository-url>
   cd <project-folder>
   ```
2. **Install Dependencies**
   ```sh
   pip install -r requirements.txt
   ```
3. **Run the Server**
   ```sh
   python server.py
   ```
4. **Run the Client**
   ```sh
   python client.py
   ```

### Configuration
- Modify `server.py` to change default ports or data storage settings.
- Ensure the server is running before starting the client.
- Register users before attempting to send messages.

This setup ensures a fully functional encrypted messaging system with secure end-to-end encryption and user authentication.

## Setting Up in PyCharm
1. **Open PyCharm** and select **"Open"** to navigate to the cloned repository folder.
2. Ensure you have a virtual environment set up:
   - Open **Terminal** in PyCharm and run:
     ```sh
     python -m venv venv
     source venv/bin/activate  # On macOS/Linux
     venv\Scripts\activate  # On Windows
     ```
3. **Install dependencies** in the virtual environment:
   ```sh
   pip install -r requirements.txt
   ```
4. **Run the server** by opening `server.py` and clicking the **Run** button.
5. **Run the client** in a separate PyCharm window or tab.

This ensures a streamlined development and debugging experience using PyCharm.
