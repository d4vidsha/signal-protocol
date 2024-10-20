import argparse
import os
import logging
import sys
import threading
import time
from x3dh import X3DH
from x3dh import Client
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, x25519 as Curve25519
from cryptography.hazmat.backends import default_backend
from doublerachet import DoubleRachet, Header
import base64

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

    :param key: The symmetric key to use for encryption (must be 16, 24, or 32 bytes)
    :param plaintext: The plaintext to encrypt
    :return: The ciphertext
    """
    # Ensure key is the correct length for AES
    assert len(key) in {16, 24, 32}, "Key must be 16, 24, or 32 bytes long."
    
    # Generate a random nonce (16 bytes)
    nonce = os.urandom(16)

    # Create the Cipher object
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(nonce),
        backend=default_backend()
    )
    
    # Create an encryptor and encrypt the plaintext
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Optionally, store or log the nonce somewhere secure for later use
    return nonce, ciphertext  # Return only the ciphertext

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
        message = input(f"{username}, first message to contact server: ")
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
                    key = serverMesage.split(":")[1].strip()
                    decoded_key = base64.b64decode(key)
                    logging.debug(f"Received key: {decoded_key}")
                    logging.debug("len of key: ", len(decoded_key))
            if serverMesage:
                break
        time.sleep(1)
    with open(shared_fileKDC, "w") as f:
        pass

    Bob_dh_key_pair = Curve25519.X25519PrivateKey.generate()
    Bob_dh_public_key = Bob_dh_key_pair.public_key()
    bob_dh_key_pair_hex = Bob_dh_key_pair.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ).hex()
    while True:
        with open(shared_file, "a") as f:
            message = "Alice dh public key: " + bob_dh_key_pair_hex
            nonce, cipher = symmetric_encrypt(decoded_key, message.encode())
            f.write(f"{username} dh key:  {nonce.hex()}||{cipher.hex()}\n")
        logging.debug(f"{username} dh key:  {nonce.hex()}||{cipher.hex()}\n")
        break
    
    aliceCommunicator.RatchetInitAlice(decoded_key, Bob_dh_public_key)
    aliceCommunicator.print()
    print("Enjoy your chat with Bob!")
    while True:
        message = input(f"{username}: ")
        header, ciphertext = aliceCommunicator.RatchetEncrypt(message, ad)
        #extract header, ciphertext, ad from ciphertext
        nonce, ciphertext, associatedData = ciphertext

        if isinstance(header, Header):
            header_bytes = header.to_bytes()  # Serialize the Header object to bytes
            header_str = header_bytes.hex()  # Convert to hex string

        if isinstance(nonce, bytes):
            nonce_str = nonce.hex()
        else:
            nonce_str = str(nonce)

        if isinstance(ciphertext, bytes):
            ciphertext_str = ciphertext.hex()
        else:
            ciphertext_str = str(ciphertext)
        
        if isinstance(associatedData, bytes):
            associatedData_str = associatedData.hex()
        else:
            associatedData_str = str(associatedData)

        message = f"{header_str}||{nonce_str}||{ciphertext_str}||{associatedData_str}"
        with open(shared_file, "a") as f:
            f.write(f"{username}: {message}\n")

def listen_for_messages():
    last_seen = 0
    while True:
        with open(shared_file, "r") as f:
            lines = f.readlines()
            # print new messages that Bob hasn't seen yet
            for line in lines[last_seen:]:
                if line.startswith("Bob:"):
                    ciphertext = line.split(":")[1]
                    header, nonce, ciphertext, associatedDate = ciphertext.split("||")
                    header = Header.from_bytes(bytes.fromhex(header))
                    nonce = bytes.fromhex(nonce)
                    ciphertext = bytes.fromhex(ciphertext)
                    associatedData = bytes.fromhex(associatedDate)
                    ciphertext = (nonce, ciphertext, associatedData)
                    decrypted_message = aliceCommunicator.RatchetDecrypt(header, ciphertext, ad)
                    decrypted_message = decrypted_message.decode('utf-8')
                    print(f"\rBob: {decrypted_message}                     ")
                    print(f"\r{username}: ", end='')
            last_seen = len(lines)
        time.sleep(1)

if __name__ == '__main__':
    # get all the arguments
    parser = argparse.ArgumentParser(description="Demonstrate Signal Protocol.")
    parser.add_argument(
        "--log",
        type=str,
        choices=["DEBUG", "INFO", "ERROR"],
        default="INFO",
        help="The log level to use.",
    )
    args = parser.parse_args()

    # set up logging
    if args.log == "DEBUG":
        logging_level = logging.DEBUG
        logging_format = "[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"
    elif args.log == "INFO":
        logging_level = logging.INFO
        logging_format = "[%(asctime)s] %(levelname)s: %(message)s"
    elif args.log == "ERROR":
        logging_level = logging.ERROR
        logging_format = "[%(asctime)s] %(levelname)s: %(message)s"

    logging.basicConfig(stream=sys.stderr, level=logging_level, format=logging_format)

    # clear the file
    with open(shared_file, "w") as f:
        pass

    ad = "Alice and Bob"
    alice = Client("Alice")
    aliceCommunicator = DoubleRachet()
    threading.Thread(target=send_messages, daemon=True).start()
    listen_for_messages()
