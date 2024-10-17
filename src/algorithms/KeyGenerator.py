from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

def generate_keys(username):
    # Generate a private key for use in the exchange
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Serialize private key
    private_key_bytes = private_key.private_bytes(
        encryption_algorithm=serialization.NoEncryption(),
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL
    )

    # Save the private key to a file
    with open(f"{username}_private_key.pem", "wb") as f:
        f.write(private_key_bytes)

    # Generate the corresponding public key
    public_key = private_key.public_key()

    # Serialize public key
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save the public key to a file (this is to be stored on the server)
    with open(f"{username}_public_key.pem", "wb") as f:
        f.write(public_key_bytes)

    print(f"Keys generated and saved for {username}.")

if __name__ == "__main__":
    username = input("Enter your username: ")
    generate_keys(username)
