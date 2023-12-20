import socket
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

MAX_LOGIN_ATTEMPTS = 3
EXIT_MESSAGE = "EXIT!"

def generate_key(password):
    # Use a key derivation function (KDF) to generate a key from the password
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), b'salt', 100000)
    return key[:16]  # Use the first 16 bytes as the key (128 bits)

def generate_iv():
    # Generate a random Initialization Vector (IV)
    return get_random_bytes(AES.block_size)

def encrypt_message(message, key):
    # Encrypt a message using AES encryption in CBC mode with an Initialization Vector (IV)
    iv = generate_iv()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(message.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_message)
    return iv + ciphertext

def decrypt_message(ciphertext, key):
    # Decrypt a message using AES decryption in CBC mode with an Initialization Vector (IV)
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return decrypted_message.decode('utf-8')

def run_client():
    # Create a socket object
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Server configuration
    server_ip = "127.0.0.1"  # Replace with the server's IP address
    server_port = 8000  # Replace with the server's port number

    # Establish connection with the server
    client.connect((server_ip, server_port))

    # Receive the shared password from the server
    received_password = client.recv(1024)
    shared_password = input("Alice, enter the shared password: ")

    # Send the shared password to the server
    client.send(shared_password.encode('utf-8'))

    while True:
        # Alice's message
        alice_message = input("Alice, enter your message (type EXIT! to exit): ")
        if alice_message == EXIT_MESSAGE:
            # Send the exit message to close the connection
            client.send(EXIT_MESSAGE.encode("utf-8"))
            break

        # Encrypt Alice's message
        encrypted_message = encrypt_message(alice_message, generate_key(shared_password))

        # Send the encrypted message to the server
        client.send(encrypted_message)

        # Receive encrypted reply from Bob
        encrypted_reply = client.recv(1024)
        if not encrypted_reply:
            break

        # Decrypt the reply
        decrypted_reply = decrypt_message(encrypted_reply, generate_key(shared_password))

        # Print the decrypted reply
        print(f"Alice received: {encrypted_reply}")
        print(f"Decrypted reply: {decrypted_reply}")

    # Close the client socket
    client.close()
    print("Connection to Bob closed")

if __name__ == "__main__":
    run_client()
