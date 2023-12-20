import socket
import threading
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

def handle_client(client_socket, shared_password):
    # Send the shared password to the client securely
    encrypted_password = encrypt_message(shared_password, generate_key(shared_password))
    client_socket.send(encrypted_password)

    # Receive the shared password from the client
    received_password = client_socket.recv(1024)
    shared_key = generate_key(received_password.decode('utf-8'))

    while True:
        # Receive encrypted message from the client
        encrypted_message = client_socket.recv(1024)
        if not encrypted_message:
            break

        # Check if the received message is the exit message
        if encrypted_message == EXIT_MESSAGE.encode('utf-8'):
            break

        # Decrypt the message
        decrypted_message = decrypt_message(encrypted_message, shared_key)

        # Print the decrypted message
        print(f"Bob received: {encrypted_message}")
        print(f"Decrypted message: {decrypted_message}")

        # Bob's reply
        bob_reply = input("Bob, enter your reply (type EXIT! to exit): ")
        if bob_reply == EXIT_MESSAGE:
            break

        # Encrypt Bob's reply
        encrypted_reply = encrypt_message(bob_reply, shared_key)

        # Send the encrypted reply to Alice
        client_socket.send(encrypted_reply)

    # Close the client socket
    client_socket.close()
    print("Connection to Alice closed")

def run_server():
    # Create a socket object
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Server configuration
    server_ip = "127.0.0.1"
    port = 8000

    # Bind the socket to a specific address and port
    server.bind((server_ip, port))
    
    # Listen for incoming connections
    server.listen(0)
    print(f"Listening on {server_ip}:{port}")

    # Accept incoming connections
    client_socket, client_address = server.accept()
    print(f"Accepted connection from {client_address[0]}:{client_address[1]}")

    # Get shared password from Bob
    shared_password = input("Bob, enter the shared password: ")

    # Start a thread to handle the communication with Alice
    alice_thread = threading.Thread(target=handle_client, args=(client_socket, shared_password))
    alice_thread.start()

# Run the server
run_server()

