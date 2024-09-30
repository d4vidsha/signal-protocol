from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import x25519 as Curve25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import os
import hmac
import hashlib

class Header:
    def __init__(self, dh_pub_key, pn, n):
        self.dh = dh_pub_key
        self.pn = pn
        self.n = n
    
    def to_bytes(self):
        # Convert the X25519PublicKey to bytes
        if isinstance(self.dh, Curve25519.X25519PublicKey):
            dh_bytes = self.dh.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        else:
            raise TypeError("dh_pub_key must be a X25519PublicKey")

        # Convert pn to bytes
        pn_bytes = str(self.pn).encode('utf-8')

        # Convert n to bytes (use a fixed size, e.g., 4 bytes)
        n_bytes = self.n.to_bytes(4, byteorder='big')  # Ensure it's 4 bytes
        
        # Return concatenated bytes
        return dh_bytes + pn_bytes + n_bytes

class DoubleRachet():
    def __init__(self):
        self.MAX_SKIP = 1000

    def RatchetInitAlice(self, SK, bob_dh_public_key):
        self.DHs = self.generateDH()
        self.DHr = bob_dh_public_key
        self.RK, self.CKs = self.KDF_RK(SK, self.DH(self.DHs, self.DHr)) 
        self.CKr = None
        self.Ns = 0
        self.Nr = 0
        self.PN = 0
        self.MKSKIPPED = {}

    def RatchetInitBob(self, SK, bob_dh_key_pair):
        self.DHs = bob_dh_key_pair
        self.DHr = None
        self.RK = SK
        self.CKs = None
        self.CKr = None
        self.Ns = 0
        self.Nr = 0
        self.PN = 0
        self.MKSKIPPED = {}

    def generateDH(self):
        return Curve25519.X25519PrivateKey.generate()

    def generateNewDH(self):
        self.DHs = self.generateDH()
        self.RK, self.CKs = self.KDF_RK(self.RK, self.DH(self.DHs, self.DHr))
        self.PN = self.Ns
        self.Ns = 0
        self.Nr = 0

    def DH(self, dh_pair, dh_pub):
        try:
            shared_secret = dh_pair.exchange(dh_pub)
        except Exception as e:
            raise ValueError("Invalid public key provided for DH calculation") from e
    
        return shared_secret

    def KDF_RK(self, rk, dh_out):
        if isinstance(rk, str):
            rk = rk.encode('utf-8')
        elif not isinstance(rk, bytes):
            rk = str(rk).encode('utf-8')
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64, 
            salt=rk, 
            info=b'info', 
            backend=default_backend())
        derived_key = hkdf.derive(dh_out)
        return derived_key[:32], derived_key[32:]
    
    def KDF_CK(self, ck):
        new_ck = hashlib.sha256(ck).digest()
        mk = hashlib.sha256(new_ck).digest()
        return new_ck, mk

    def derive_nonce(self, key, length):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=b'nonce-info',
            backend=default_backend()
        )
        return hkdf.derive(key)

    def aes_ctr_encrypt(self, key, plaintext):
        nonce = self.derive_nonce(key, 16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return nonce, ciphertext
    
    def aes_ctr_decrypt(self, key, nonce, ciphertext):
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def ENCRYPT(self, mk, plaintext, associated_data):
        nonce, ciphertext = self.aes_ctr_encrypt(mk, plaintext)
        message_to_authenticate = associated_data + nonce + ciphertext
        auth_tag = self.HMAC_SHA256(mk, message_to_authenticate)
        return nonce, ciphertext, auth_tag

    def DECRYPT(self, mk, ciphertext, associated_data):
        nonce, ciphertext, auth_tag = ciphertext
        message_to_authenticate = associated_data + nonce + ciphertext
        expected_auth_tag = self.HMAC_SHA256(mk, message_to_authenticate)
        if not hmac.compare_digest(auth_tag, expected_auth_tag):
            raise Exception('Authentication failed')
        return self.aes_ctr_decrypt(mk, nonce, ciphertext)

    def HEADER(self, dh_pair, pn, n):
        dh_pub_key = dh_pair.public_key()
        
        return Header(dh_pub_key, pn, n)

    def CONCAT(self, ad, header):
        if not isinstance(header, Header):
            raise TypeError("header must be an instance of Header")

        header_bytes = header.to_bytes()

        if not isinstance(ad, bytes):
            ad = str(ad).encode('utf-8')
        
        ad_length = len(ad).to_bytes(4, byteorder='big')
        
        return ad_length + ad + header_bytes

    def RatchetEncrypt(self, plaintext, AD):
        self.CKs, mk = self.KDF_CK(self.CKs)
        header = self.HEADER(self.DHs, self.PN, self.Ns)
        self.Ns += 1
        return header, self.ENCRYPT(mk, plaintext, self.CONCAT(AD, header))

    def RatchetDecrypt(self, header, ciphertext, AD):
        plaintext = self.TrySkippedMessageKeys(header, ciphertext, AD)
        if plaintext != None:
            return plaintext
        if header.dh != self.DHr:
            self.DHRatchet(header)
            self.SkipMessageKeys(header.pn)
        self.SkipMessageKeys(header.n)
        self.CKr, mk = self.KDF_CK(self.CKr)
        self.Nr += 1
        return self.DECRYPT(mk, ciphertext, self.CONCAT(AD, header))

    def TrySkippedMessageKeys(self, header, ciphertext, AD):
        dh_bytes = header.dh.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        if (dh_bytes, header.n) in self.MKSKIPPED:
            mk = self.MKSKIPPED[dh_bytes, header.n]
            del self.MKSKIPPED[dh_bytes, header.n]
            return self.DECRYPT(mk, ciphertext, self.CONCAT(AD, header))
        else:
            return None

    def SkipMessageKeys(self, until):
        if self.Nr + self.MAX_SKIP < until:
            raise Exception("Message key skipping limit exceeded")
        if self.CKr != None:
            while self.Nr < until:
                self.CKr, mk = self.KDF_CK(self.CKr)
                dh_bytes = self.DHr.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                self.MKSKIPPED[(dh_bytes, self.Nr)] = mk  # Store as bytes
                self.Nr += 1

    def DHRatchet(self, header):
        self.PN = self.Ns
        self.Ns = 0
        self.Nr = 0
        self.DHr = header.dh
        self.RK, self.CKr = self.KDF_RK(self.RK, self.DH(self.DHs, self.DHr))
        # Remove following update if you do not want to generate a new DH key pair like auto update of the DH key pair
        # self.DHs = self.generateDH()
        # self.RK, self.CKs = self.KDF_RK(self.RK, self.DH(self.DHs, self.DHr))

    def HMAC_SHA256(self, key, data):
        return hmac.new(key, data, hashlib.sha256).digest()

def main():
    alice = DoubleRachet()
    bob = DoubleRachet()
    # Bob's initial DH key pair
    bob_dh_key_pair = Curve25519.X25519PrivateKey.generate()
    bob_public_key = bob_dh_key_pair.public_key()

    alice_dh_key_pair = alice.generateDH()

    shared_secret_key = alice.DH(alice_dh_key_pair, bob_public_key)

    # Alice initializes the Ratchet
    alice.RatchetInitAlice(shared_secret_key, bob_public_key)

    # Bob initializes the Ratchet
    bob.RatchetInitBob(shared_secret_key, bob_dh_key_pair)

    # Alice sends a message
    message = b"Hello Bob!"
    ad = b"Associated data"
    header, ciphertext = alice.RatchetEncrypt(message, ad)
    
    # Bob receives and decrypts the message
    decrypted_message = bob.RatchetDecrypt(header, ciphertext, ad)
    print(f"Bob received: {decrypted_message}")

    # Bob generate new DH key and sends a message
    bob.generateNewDH()
    message = b"Hello Alice!"
    ad = b"Associated data"
    header, ciphertext = bob.RatchetEncrypt(message, ad)

    # Alice receives and decrypts the message
    decrypted_message = alice.RatchetDecrypt(header, ciphertext, ad)
    print(f"Alice received: {decrypted_message}")

    # Alice generates a new DH key pair and send a message
    alice.generateNewDH()
    message = b"Hello Bob! Again"
    ad = b"Associated data"
    header, ciphertext = alice.RatchetEncrypt(message, ad)

    # Bob receives and decrypts the message
    decrypted_message = bob.RatchetDecrypt(header, ciphertext, ad)
    print(f"Bob received: {decrypted_message}")

    # Bob sends a message
    message = b"What's up Alice"
    ad = b"Associated data"
    header, ciphertext = bob.RatchetEncrypt(message, ad)

    # Alice receives and decrypts the message
    decrypted_message = alice.RatchetDecrypt(header, ciphertext, ad)
    print(f"Alice received: {decrypted_message}")

    # test out of order message
    message = b"Out of order message"
    ad = b"Associated data"
    header, ciphertext = bob.RatchetEncrypt(message, ad)

    message2 = b"Out of order message 2"
    ad2 = b"Associated data 2"
    header2, ciphertext2 = bob.RatchetEncrypt(message2, ad2)

    # Alice receives and decrypts the message
    decrypted_message = alice.RatchetDecrypt(header2, ciphertext2, ad2)
    print(f"Alice received: {decrypted_message}")

    decrypted_message = alice.RatchetDecrypt(header, ciphertext, ad)
    print(f"Alice received: {decrypted_message}")

    # test out of order message and generate new DH key pair
    message = b"Out of order message"
    ad = b"Associated data"
    header, ciphertext = bob.RatchetEncrypt(message, ad)

    message2 = b"Out of order message 2"
    ad2 = b"Associated data 2"
    header2, ciphertext2 = bob.RatchetEncrypt(message2, ad2)

    bob.generateDH()
    message3 = b"Out of order message 3"
    ad3 = b"Associated data 3"
    header3, ciphertext3 = bob.RatchetEncrypt(message3, ad3)

    # Alice receives and decrypts the message
    decrypted_message = alice.RatchetDecrypt(header3, ciphertext3, ad3)
    print(f"Alice received: {decrypted_message}")

    decrypted_message = alice.RatchetDecrypt(header2, ciphertext2, ad2)
    print(f"Alice received: {decrypted_message}")

    decrypted_message = alice.RatchetDecrypt(header, ciphertext, ad)
    print(f"Alice received: {decrypted_message}")

if __name__ == "__main__":
    main()
