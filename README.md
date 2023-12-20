# Encrypted-Messaging-Project
Final Project for my Computer Security class (CS 4173)

This project is a basic implementation of a secure point-to-point messaging system. 


## **Objectives**

1. **Secure Message Exchange:**
   - Enable secure messaging between two parties, Alice and Bob, over the internet.

2. **Password-Based Encryption:**
   - Implement a password-based encryption system where Alice and Bob share a common password for secure message exchange.

3. **Strong Encryption:**
   - Utilize 128-bit AES encryption to ensure a high level of security.

4. **Padding Mechanism:**
   - Implement a padding mechanism to standardize the length of encrypted messages, enhancing system security.

5. **Connection Setup with Socket Programming:**
   - Establish an initial connection setup between Alice and Bob using socket/network programming, simulating internet communication.

6. **Message Uniqueness:**
   - Ensure that repeated messages generate different ciphertexts for enhanced security.

7. **Key Management System:**
   - Implement a key management mechanism to regularly update the encryption key shared between Alice and Bob, mitigating potential risks associated with long-term key usage.

## **System Architecture**

The system adopts a client-server architecture, where the server acts as a centralized hub managing the secure communication channel. The process involves connection establishment, key exchange, and secure message transmission.

## **Encryption (AES)**

AES encryption, operating on 128-bit blocks, is used for securing messages. The Crypto.Cipher module from the pycryptodome library is leveraged for efficient implementation.

## **Key Derivation**

The shared password undergoes key derivation using PBKDF2-HMAC to transform it into a secure encryption key. Additionally, an Initialization Vector (IV) is introduced to add randomness and ensure different ciphertexts for identical messages.

## **Sample Interaction**

Screenshots included in the repo show a simple walkthrough of the code running. The setup is two separate terminals, one running server.py and the other running client.py to represent 

The server starts running and listening for a connection. It then accepts the connection from the client terminal. Bob sets the shared password to ‘hello’ which is securely sent to the client. Alice must match Bob’s password that he set for communication to begin. Once she does, she can send the first message - ‘hi’. Bob receives the message and it is decrypted. He responds with ‘hi’ as well. Even though they sent the same message, the ciphertext looks completely different.
Alice responds with ‘bye’. Even though her message is twice as long as her last message, the ciphertexts are the same length. Bob types ‘EXIT!’ and the program completes.

## **Conclusion**

The implemented Python code  creates a secure communication system using AES encryption, providing a secure channel for messages between two parties. Enhancements, such as the addition of a graphical user interface, could further improve the user experience.
