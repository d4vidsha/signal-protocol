import time
import threading
from x3dh import X3DH
from x3dh import Client
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, x25519 as Curve25519
from cryptography.hazmat.backends import default_backend
from doublerachet import DoubleRachet

# Shared file for communication
shared_fileKDC = "/app/messageKDC.txt"
shared_file = "/app/shared.txt"
private_key_path = "/app/Alice_private_key.pem"

# Global variables for username and target
username = 'Alice'
target = None

def sign_message(private_key, message):
    """
    Sign the message using the provided private key.

    :param private_key: Alice's private key (loaded from PEM file)
    :param message: The plaintext message to sign (as bytes)
    :return: The signature (as bytes)
    """
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def symmetric_encrypt(key, plaintext):
    """
    Encrypt the plaintext using the provided key.

    :param key: The symmetric key to use for encryption
    :param plaintext: The plaintext to encrypt
    :return: The ciphertext
    """
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(b"\x00" * 8),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

# alice private key
with open(private_key_path, "rb") as key_file:
    Alice_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,  # If the key is encrypted, provide the password here.
        backend=default_backend()
    )

def send_messages():
    global username, target
    print("Welcome to the Server,", username)
    target = input("Enter the recipient's username: ")

    while True:
        message = input(f"{username}, enter your message: ")
        signature = sign_message(Alice_private_key, message.encode())
        message_with_signature = f"{message}||{signature.hex()}"
        with open(shared_fileKDC, "a") as f:
            f.write(f"{username}: {message_with_signature}\n")
        break

    serverMesage = None
    while True:
        with open(shared_fileKDC, "r") as f:
            lines = f.readlines()
            for line in lines:
                if line.startswith(f"Server:"):
                    serverMesage = line.strip()
                    # read the key from the message
                    key = serverMesage.split(":")[1]
            if serverMesage:
                break
        time.sleep(1)

    print(("received key: ", key))
    alice_dh_key_pair = Curve25519.generate_private_key()
    alice_dh_public_key = alice_dh_key_pair.public_key()
    while True:
        with open(shared_file, "a") as f:
            message = "Alice dh public key: " + alice_dh_public_key
            cipher = symmetric_encrypt(key.encode(), message.encode())
            f.write(f"{username}: {cipher.hex()}\n")
        print(f"{username} sent: {message}")
        break
    
    print("send dh key to Bob")

    alice.RatchetInitBob(key, alice_dh_key_pair)
    while True:
        message = input(f"{username}, enter your message: ")
        header, ciphertext = alice.RatchetEncrypt(message, ad)
        ciphertext = header + "||" + ciphertext
        with open(shared_file, "a") as f:
            f.write(f"{username}: {ciphertext}\n")
        print(f"{username} sent: {message}")

def listen_for_messages():
    last_seen = 0
    while True:
        with open(shared_file, "r") as f:
            lines = f.readlines()
            # Print new messages that Bob hasn't seen yet
            for line in lines[last_seen:]:
                if line.startswith("Bob:"):
                    ciphertext = line.split(":")[1]
                    header, ciphertext = ciphertext.split("||")
                    decrypted_message = alice.RatchetDecrypt(header, ciphertext, ad)
                    print(f"{username} received: {decrypted_message}")
            last_seen = len(lines)
        time.sleep(1)

if __name__ == '__main__':
    ad = "Alice and Bob"
    alice = Client("Alice")
    aliceCommunicator = DoubleRachet()
    threading.Thread(target=send_messages, daemon=True).start()
    listen_for_messages()
