import argparse
import base64
import sys
import time
import threading
import logging
from x3dh import X3DH
from x3dh import Client
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, x25519 as Curve25519, x25519
from cryptography.hazmat.backends import default_backend
from doublerachet import DoubleRachet, Header

# Shared file for communication
shared_file = "/app/shared.txt"
private_key_path = "/app/Bob_private_key.pem"

# Global variables for username and target
username = 'Bob'
target = None

def sign_message(private_key, message):
    """
    Sign the message using the provided private key.

    :param private_key: Bob's private key (loaded from PEM file)
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

def symmetric_decrypt(key, nonce, ciphertext):
    """
    Decrypt the ciphertext using the provided key and nonce.

    :param key: The symmetric key to use for decryption (must be 16, 24, or 32 bytes)
    :param nonce: The nonce used during encryption (must be 16 bytes)
    :param ciphertext: The ciphertext to decrypt
    :return: The plaintext
    """
    # Ensure key is the correct length for AES
    assert len(key) in {16, 24, 32}, "Key must be 16, 24, or 32 bytes long."
    assert len(nonce) == 16, "Nonce must be 16 bytes long."

    # Create the Cipher object
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(nonce),
        backend=default_backend()
    )

    # Create a decryptor and decrypt the ciphertext
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext
    

# bob private key
with open(private_key_path, "rb") as key_file:
    Bob_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,  # If the key is encrypted, provide the password here.
        backend=default_backend()
    )

def send_messages():
    global username, target
    print("Welcome to the Server,", username)
    # target = input("Enter the recipient's username: ")

    # while True:
    #     message = input(f"{username}, enter your message: ")
    #     signature = sign_message(Bob_private_key, message.encode())
    #     message_with_signature = f"{message}||{signature.hex()}"
    #     with open(shared_fileKDC, "a") as f:
    #         f.write(f"{username}: {message_with_signature}\n")
    #     break

    # serverMesage = None
    # while True:
    #     with open(shared_fileKDC, "r") as f:
    #         lines = f.readlines()
    #         for line in lines:
    #             if line.startswith(f"Server:"):
    #                 serverMesage = line.strip()
    #                 # read the key from the message
    #                 key = serverMesage.split(":")[1]
    #         if serverMesage:
    #             break
    #     time.sleep(1)

    # bob_dh_key_pair = Curve25519.generate_private_key()
    # bob_dh_public_key = bob_dh_key_pair.public_key()
    # while True:
    #     with open(shared_file, "a") as f:
    #         message = "Bob: " + bob_dh_public_key
    #         cipher = symmetric_encrypt(key.encode(), message.encode())
    #         f.write(f"{username}: {cipher.hex()}\n")
            
    #     logging.debug(f"{username} sent: {message}")
    #     break
    
    while True:
        if not bob.connection:
            continue
        message = input(f"{username}: ")

        print(f"\r{username}: {message}")

        header, ciphertext = bobCommunicator.RatchetEncrypt(message, ad)
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
    shared_file_Bob = "/app/sharedInitialMessageBob.txt"
    key = False
    while True:
        with open(shared_file_Bob, "r") as f:
            lines = f.readlines()
            # print new messages that Bob hasn't seen yet
            for line in lines[last_seen:]:
                if line.startswith("Server:"):
                    key = line.split(":")[1].strip()
                    key = base64.b64decode(key)
            if key:
                break
        time.sleep(1)
    # clear the file
    with open(shared_file_Bob, "w") as f:
        pass

    logging.debug(("received key from server: ", key))
    bob_key_pair_key = None
    while True:
        with open(shared_file, "r") as f:
            lines = f.readlines()
            # print new messages that Bob hasn't seen yet
            for line in lines[last_seen:]:
                if line.startswith("Alice dh key:"):
                    nonce, ciphertext = line.split(":")[1].split("||")
                    message = symmetric_decrypt(key, bytes.fromhex(nonce), bytes.fromhex(ciphertext))
                    message = message.decode()
                    bob_key_pair_key_hex = message.split(":")[1].strip()
                    bob_key_pair_key_bytes = bytes.fromhex(bob_key_pair_key_hex)
                    bob_key_pair_key = Curve25519.X25519PrivateKey.from_private_bytes(bob_key_pair_key_bytes)
            if bob_key_pair_key:
                bobCommunicator.RatchetInitBob(key, bob_key_pair_key)
                bobCommunicator.print()
                break
            last_seen = len(lines)
        time.sleep(1)
    
    logging.debug("received dh key from Alice")
    print("Wait for the Alice first message and Enjoy your chat with Alice!")

    while True:
        with open(shared_file, "r") as f:
            lines = f.readlines()
            # print new messages that Bob hasn't seen yet
            for line in lines[last_seen:]:
                if line.startswith("Alice:"):
                    ciphertext = line.split(":")[1]
                    header, nonce, ciphertext, associatedDate = ciphertext.split("||")
                    header = Header.from_bytes(bytes.fromhex(header))
                    nonce = bytes.fromhex(nonce)
                    ciphertext = bytes.fromhex(ciphertext)
                    associatedData = bytes.fromhex(associatedDate)
                    ciphertext = (nonce, ciphertext, associatedData)
                    decrypted_message = bobCommunicator.RatchetDecrypt(header, ciphertext, ad)
                    decrypted_message = decrypted_message.decode('utf-8')
                    print(f"\rAlice: {decrypted_message}                   ")
                    if not bob.connection:
                        bob.setConnection(True)
                        continue
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
    
    ad = "Alice and Bob"
    bob = Client("Bob")
    bobCommunicator = DoubleRachet()
    threading.Thread(target=send_messages, daemon=True).start()
    listen_for_messages()