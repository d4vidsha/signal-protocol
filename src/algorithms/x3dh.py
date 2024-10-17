"""
X3DH implmementation.
"""

import os
import logging

from enum import Enum, auto
from collections import deque
from typing import Dict, List, Optional
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class Curve(Enum):
    """
    Types of curves.
    """

    CURVE25519 = auto()
    CURVE448 = auto()


class XKeyPair:
    """
    Keypair.
    """

    def __init__(self, curve: Curve = Curve.CURVE25519):
        self.curve = curve
        if curve == Curve.CURVE25519:
            self.private_key = X25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()
        elif curve == Curve.CURVE448:
            self.private_key = X448PrivateKey.generate()
            self.public_key = self.private_key.public_key()

    def __str__(self):
        string = ""
        string += f"Private key: {self.private_key.private_bytes_raw()[:7]}..."
        string += " || "
        string += f"Public key: {self.public_key.public_bytes_raw()[:7]}..."
        return string


@dataclass
class KeyBase:
    """
    Public key.
    """

    value: bytes


@dataclass
class PublicKey(KeyBase):
    """
    Public key.
    """


@dataclass
class PrivateKey(KeyBase):
    """
    Private key.
    """


@dataclass
class BundleBase:
    """
    A bundle.
    """

    identity_key: X25519PublicKey
    signed_prekey: X25519PublicKey


@dataclass
class Publishable(BundleBase):
    """
    Publishable data.
    """

    one_time_prekeys: List[X25519PublicKey]

    def __repr__(self) -> str:
        """
        The representation is going to be the first byte of every key in
        publishable.
        """
        representation = bytearray()
        representation.extend(self.identity_key.public_bytes_raw()[0:1])
        representation.extend(self.signed_prekey.public_bytes_raw()[0:1])
        for key in self.one_time_prekeys:
            representation.extend(key.public_bytes_raw()[0:1])
        return str(bytes(representation))


@dataclass
class PrekeyBundle(BundleBase):
    """
    A prekey bundle.
    """

    one_time_prekey: Optional[PublicKey]


def deserialise_publish(data: bytes) -> Publishable:
    """
    Deserialise the data to be published.
    """
    identity_key = X25519PublicKey.from_public_bytes(data[:32])
    signed_prekey = X25519PublicKey.from_public_bytes(data[32:64])
    one_time_prekeys = [
        X25519PublicKey.from_public_bytes(data[i : i + 32])
        for i in range(64, len(data), 32)
    ]
    return Publishable(identity_key, signed_prekey, one_time_prekeys)


def serialise_publish(publishable: Publishable) -> bytes:
    """
    Serialise the data to be published.
    """
    serialised = bytearray()
    serialised.extend(publishable.identity_key.public_bytes_raw())
    serialised.extend(publishable.signed_prekey.public_bytes_raw())
    for key in publishable.one_time_prekeys:
        serialised.extend(key)
    return bytes(serialised)


class Server:
    """
    The server handling all connections and messages between clients.
    """

    @dataclass
    class ClientData:
        """
        What the server stores about a single client.
        """

        identity_key: PublicKey
        signed_prekey: PublicKey
        one_time_prekeys: deque[PublicKey]

    # @dataclass
    # class Message:
    #     """
    #     A message from one client to another.
    #     """

    #     sender: PublicKey
    #     receiver: PublicKey
    #     ciphertext: str

    def __init__(self):
        self.clients: Dict[bytes, Server.ClientData] = {}
        # self.message_queue: deque[Server.Message] = deque([])
        self.initial_messages: Dict[bytes, bytes] = {}

    def recv(self, data: bytes) -> None:
        """
        Receive data from a client.
        """
        publishable = self.__deserialise_publish(data)
        logging.debug("Publishable: %s", publishable)
        identity_key = publishable.identity_key
        signed_prekey = publishable.signed_prekey
        one_time_prekeys = publishable.one_time_prekeys
        self.clients[identity_key.public_bytes_raw()] = Server.ClientData(
            identity_key=identity_key,
            signed_prekey=signed_prekey,
            one_time_prekeys=deque(one_time_prekeys),
        )

    def __deserialise_publish(self, data: bytes) -> Publishable:
        """
        Deserialise the data to be published.
        """
        return deserialise_publish(data)

    def get_bundle(self, client: bytes) -> PrekeyBundle:
        """
        Get a prekey bundle for a clinet.
        """
        client_data = self.clients[client]
        # include a one-time prekey if there are any left
        otpk = None
        if len(client_data.one_time_prekeys) != 0:
            otpk = client_data.one_time_prekeys.popleft()
        return PrekeyBundle(
            identity_key=client_data.identity_key,
            signed_prekey=client_data.signed_prekey,
            one_time_prekey=otpk,
        )


class Client:
    """
    The client which can send and receive messages.
    """

    @dataclass
    class Client:
        """
        The client's data.
        """

        name: str
        curve: Curve
        hash: hashes
        info: str
        identity_key: XKeyPair
        ephemeral_key: XKeyPair
        signed_prekey: XKeyPair
        one_time_prekeys: Dict[bytes, XKeyPair]
        shared_secret_key: bytes

    def __init__(
        self,
        name: str,
        curve: Curve = Curve.CURVE25519,
        hash_type: hashes = hashes.SHA256(),
        info: str = "MyProtocol",
        num_one_time_prekeys: int = 10,
    ):
        logging.debug(XKeyPair(curve))
        self.client = Client.Client(
            name=name,
            curve=curve,
            hash=hash_type,
            info=info,
            identity_key=XKeyPair(curve),
            ephemeral_key=None,
            signed_prekey=XKeyPair(curve),
            one_time_prekeys={},
            shared_secret_key=None,
        )
        self.num_one_time_prekeys = num_one_time_prekeys

    def __generate_one_time_prekeys(self, n: int) -> None:
        """
        Generate n one-time prekeys.
        """
        keys = {}
        while n > 0:
            keypair = XKeyPair(self.client.curve)
            keys[keypair.public_key.public_bytes_raw()] = keypair
            n -= 1
        return keys

    def __serialise_publish(
        self,
        identity_key: PublicKey,
        signed_prekey: PublicKey,
        one_time_prekeys: Dict[bytes, PublicKey],
    ) -> bytes:
        # TODO: use the serialise_publish function instead
        """
        Serialise the data to be published.
        """
        return serialise_publish(
            Publishable(identity_key, signed_prekey, one_time_prekeys)
        )

    def publish(self, server: Server) -> None:
        """
        Publishes the client's identity key and prekeys to the server.
        """
        # generate a prekey signature from the given signed prekey
        # message = self.client.identity_key.public_key.public_bytes_raw()
        # self.client.prekey_signature = self.client.identity_key.private_key.sign(
        #     self.client.signed_prekey.public_key.public_bytes_raw()
        # )
        # logging.debug("Prekey signature: %s", self.client.prekey_signature)
        # # verify
        # try:
        #     self.client.signed_prekey.public_key.verify(
        #         self.client.prekey_signature, message
        #     )
        #     logging.debug("Signature verified with message: %s", message)
        #     logging.debug(
        #         "Signature verified with prekey signature: %s",
        #         self.client.prekey_signature,
        #     )
        #     logging.debug(
        #         "Signature verified with signed prekey: %s",
        #         self.client.signed_prekey.public_key.public_bytes_raw(),
        #     )
        # except InvalidSignature:
        #     logging.error("Invalid signature")

        # generate one-time prekeys
        self.client.one_time_prekeys.update(
            self.__generate_one_time_prekeys(self.num_one_time_prekeys)
        )

        # store the client's public keys on the server
        logging.debug(
            "%s %s %s",
            len(self.client.identity_key.public_key.public_bytes_raw()),
            len(self.client.signed_prekey.public_key.public_bytes_raw()),
            len(self.client.one_time_prekeys),
        )
        serialised = self.__serialise_publish(
            self.client.identity_key.public_key,
            self.client.signed_prekey.public_key,
            self.client.one_time_prekeys,
        )
        server.recv(serialised)

    def send_initial_message(self, server: Server, client: bytes) -> None:
        """
        Fetches the prekey bundle from the server and stores the secret key.
        """
        prekey_bundle = server.get_bundle(client)
        logging.debug("Prekey bundle: %s", prekey_bundle)
        spkb = X25519PublicKey.from_public_bytes(
            prekey_bundle.signed_prekey.public_bytes_raw()
        )
        ikb = prekey_bundle.identity_key
        otpkb = prekey_bundle.one_time_prekey

        # verify the prekey signature
        message = prekey_bundle.identity_key.public_bytes_raw()
        logging.debug("Message: %s", message)
        logging.debug(
            "Signed prekey: %s", prekey_bundle.signed_prekey.public_bytes_raw()
        )
        # prekey_bundle.signed_prekey.verify(
        #     prekey_bundle.prekey_signature, message)
        # logging.debug("Signature verified")

        # now you can create the ephemeral key pair
        self.client.ephemeral_key = XKeyPair(self.client.curve)

        # and perform the Diffie-Hellman key exchanges
        dh1 = self.client.identity_key.private_key.exchange(spkb)
        dh2 = self.client.ephemeral_key.private_key.exchange(ikb)
        dh3 = self.client.ephemeral_key.private_key.exchange(spkb)
        logging.debug("DH1: %s", dh1)
        logging.debug("DH2: %s", dh2)
        logging.debug("DH3: %s", dh3)

        sk = bytearray()
        sk.extend(dh1)
        sk.extend(dh2)
        sk.extend(dh3)
        if otpkb is not None:
            dh4 = self.client.ephemeral_key.private_key.exchange(otpkb)
            sk.extend(dh4)
            logging.debug("DH4: %s", dh4)
        hkdf = HKDF(
            algorithm=self.client.hash,
            length=32,
            salt=None,
            info=self.client.info.encode(),
        )
        sk = hkdf.derive(bytes(sk))
        self.client.shared_secret_key = sk
        logging.info("Shared secret key on Alice: %s", sk)

        # create associated data byte sequence
        logging.debug("Creating associated data byte sequence...")
        ad = bytearray()
        ad.extend(self.client.identity_key.public_key.public_bytes_raw())
        ad.extend(ikb.public_bytes_raw())
        ad = bytes(ad)
        logging.debug("Associated data byte sequence: %s", ad)

        message = bytearray()
        ika = self.client.identity_key.public_key.public_bytes_raw()
        eka = self.client.ephemeral_key.public_key.public_bytes_raw()
        message.extend(ika)
        message.extend(eka)
        if otpkb is not None:
            message.extend(otpkb.public_bytes_raw())

        chacha = ChaCha20Poly1305(self.client.shared_secret_key)
        nonce = os.urandom(12)
        data = "Hello Bob!".encode()
        ciphertext = chacha.encrypt(nonce, data, ad)

        message.extend(ciphertext)
        message = bytes(message)
        logging.debug("Sending message: %s", message)
        logging.debug("Message length: %s", len(message))

        # send the message to the server
        server.initial_messages[client] = message

        logging.debug("Deleting ephemeral key...")
        self.client.ephemeral_key = None

    def recv_initial_message(self, server: Server) -> bytes:
        """
        Receive the initial message from the server.
        """
        message = server.initial_messages[
            self.client.identity_key.public_key.public_bytes_raw()
        ]
        logging.debug("Received message: %s", message)

        # get the public keys from the message
        if self.client.curve == Curve.CURVE25519:
            ika = X25519PublicKey.from_public_bytes(message[:32])
            eka = X25519PublicKey.from_public_bytes(message[32:64])
        elif self.client.curve == Curve.CURVE448:
            ika = X448PublicKey.from_public_bytes(message[:32])
            eka = X448PublicKey.from_public_bytes(message[32:64])
        else:
            raise ValueError("Invalid curve")
        if len(message) == 122:
            otpkb = self.client.one_time_prekeys[message[64:96]]
        elif len(message) == 90:
            otpkb = None
        else:
            raise ValueError("Invalid message length")

        # perform the Diffie-Hellman key exchanges
        sk = bytearray()
        if self.client.curve == Curve.CURVE25519:
            spkb = X25519PrivateKey.from_private_bytes(
                self.client.signed_prekey.private_key.private_bytes_raw()
            )
        elif self.client.curve == Curve.CURVE448:
            spkb = X448PrivateKey.from_private_bytes(
                self.client.signed_prekey.private_key.private_bytes_raw()
            )
        else:
            raise ValueError("Invalid curve")
        dh1 = spkb.exchange(ika)
        dh2 = self.client.identity_key.private_key.exchange(eka)
        dh3 = spkb.exchange(eka)
        sk.extend(dh1)
        sk.extend(dh2)
        sk.extend(dh3)
        logging.debug("DH1: %s", dh1)
        logging.debug("DH2: %s", dh2)
        logging.debug("DH3: %s", dh3)
        if otpkb is not None:
            dh4 = otpkb.private_key.exchange(eka)
            sk.extend(dh4)
            logging.debug("DH4: %s", dh4)

        hkdf = HKDF(
            algorithm=self.client.hash,
            length=32,
            salt=None,
            info=self.client.info.encode(),
        )
        sk = hkdf.derive(bytes(sk))
        self.client.shared_secret_key = sk
        logging.info("Shared secret key on Bob:   %s", sk)

        return sk


class X3DH:
    """
    The X3DH protocol.
    """

    def __init__(self, server: Server, a: Client, b: Client):
        self.server: Server = server
        self.alice: Client = a
        self.bob: Client = b

    def run(self):
        """
        Execute the protocol.
        """
        # bob publishes his identity key and prekeys to a server
        self.bob.publish(self.server)

        # alice fetches a "prekey bundle" from the server, and uses it to send
        # an initial message to bob
        ikb = self.bob.client.identity_key.public_key.public_bytes_raw()
        self.alice.send_initial_message(self.server, ikb)

        # bob receives and processes alice's initial message
        sk = self.bob.recv_initial_message(self.server)
        return sk
