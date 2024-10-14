import logging

from enum import Enum, auto
from collections import deque
from typing import Dict, Set, List, Tuple
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import (
    Ed448PrivateKey,
    Ed448PublicKey,
)
from cryptography.exceptions import InvalidSignature


class Curve(Enum):
    """
    Types of curves.
    """

    Curve25519 = auto()
    Curve448 = auto()


class HashType(Enum):
    """
    Types of hashes.
    """

    SHA256 = auto()
    SHA512 = auto()


class XKeyPair:
    """
    Keypair.
    """

    def __init__(self, curve: Curve = Curve.Curve25519):
        self.curve = curve
        if curve == Curve.Curve25519:
            self.private_key = X25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()
        elif curve == Curve.Curve448:
            self.private_key = X448PrivateKey.generate()
            self.public_key = self.private_key.public_key()

    def __str__(self):
        return f"Private key: {self.private_key.private_bytes_raw()[:7]}... || Public key: {self.public_key.public_bytes_raw()[:7]}..."


class EdKeyPair:
    """
    Keypair.
    """

    def __init__(self, curve: Curve = Curve.Curve25519):
        self.curve = curve
        if curve == Curve.Curve25519:
            self.private_key = Ed25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()
        elif curve == Curve.Curve448:
            self.private_key = Ed448PrivateKey.generate()
            self.public_key = self.private_key.public_key()

    def __str__(self):
        return f"Private key: {self.private_key.private_bytes_raw()[:7]}... || Public key: {self.public_key.public_bytes_raw()[:7]}..."


@dataclass
class KeyBase:
    """
    Public key.
    """

    value: str


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

    identity_key: Ed25519PublicKey
    signed_prekey: Ed25519PublicKey
    prekey_signature: bytes


@dataclass
class Publishable(BundleBase):
    """
    Publishable data.
    """

    one_time_prekeys: List[Ed25519PublicKey]

    def __repr__(self) -> str:
        """
        The representation is going to be the first byte of every key in
        publishable.
        """
        representation = bytearray()
        representation.extend(self.identity_key.public_bytes_raw()[0:1])
        representation.extend(self.signed_prekey.public_bytes_raw()[0:1])
        representation.extend(self.prekey_signature[0:1])
        for key in self.one_time_prekeys:
            representation.extend(key.public_bytes_raw()[0:1])
        return str(bytes(representation))


@dataclass
class PrekeyBundle(BundleBase):
    """
    A prekey bundle.
    """

    one_time_prekeys: List[PublicKey]


def deserialise_publish(data: bytes) -> Publishable:
    """
    Deserialise the data to be published.
    """
    identity_key = Ed25519PublicKey.from_public_bytes(data[:32])
    signed_prekey = Ed25519PublicKey.from_public_bytes(data[32:64])
    prekey_signature = data[64:96]
    one_time_prekeys = [
        Ed25519PublicKey.from_public_bytes(data[i : i + 32])
        for i in range(96, len(data), 32)
    ]
    return Publishable(identity_key, signed_prekey, prekey_signature, one_time_prekeys)


def serialise_publish(publishable: Publishable) -> bytes:
    """
    Serialise the data to be published.
    """
    serialised = bytearray()
    serialised.extend(publishable.identity_key.value)
    serialised.extend(publishable.signed_prekey.value)
    serialised.extend(publishable.prekey_signature)
    for key in publishable.one_time_prekeys:
        serialised.extend(key.value)
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
        prekey_signature: bytes
        one_time_prekeys: Set[PublicKey]

    @dataclass
    class Message:
        """
        A message from one client to another.
        """

        sender: PublicKey
        receiver: PublicKey
        ciphertext: str

    def __init__(self):
        self.clients: Dict[bytes, Server.ClientData] = {}
        self.message_queue: Server.Message = deque([])

    def recv(self, data: bytes) -> None:
        """
        Receive data from a client.
        """
        publishable = self.__deserialise_publish(data)
        logging.debug("Publishable: %s", publishable)
        identity_key = publishable.identity_key
        signed_prekey = publishable.signed_prekey
        prekey_signature = publishable.prekey_signature
        one_time_prekeys = publishable.one_time_prekeys
        self.clients[identity_key.public_bytes_raw()] = Server.ClientData(
            identity_key=identity_key,
            signed_prekey=signed_prekey,
            prekey_signature=prekey_signature,
            one_time_prekeys=one_time_prekeys,
        )

    def __deserialise_publish(self, data: bytes) -> Publishable:
        """
        Deserialise the data to be published.
        """
        return deserialise_publish(data)

    def get_bundle(self, client: Client) -> PrekeyBundle:
        """
        Get a prekey bundle for a clinet.
        """
        # TODO: implment this
        self.clients[client.client.identity_key.public_key]
        # return PrekeyBundle(
        #     identity_key=,
        #     signed_prekey=,
        #     prekey_signature=,
        #     one_time_prekeys=,
        # )


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
        hash: HashType
        info: str
        identity_key: XKeyPair
        ephemeral_key: XKeyPair
        signed_prekey: XKeyPair
        prekey_signature: bytes
        one_time_prekeys: List[XKeyPair]
        shared_secret_key: KeyBase

    def __init__(
        self,
        name: str,
        curve: Curve = Curve.Curve25519,
        hash_type: HashType = HashType.SHA256,
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
            signed_prekey=EdKeyPair(curve),
            prekey_signature=None,
            one_time_prekeys=[],
            shared_secret_key=None,
        )
        self.num_one_time_prekeys = num_one_time_prekeys

    def __generate_one_time_prekeys(self, n: int) -> None:
        """
        Generate n one-time prekeys.
        """
        keys = []
        while n > 0:
            keys.append(XKeyPair(self.client.curve))
            n -= 1
        return keys

    def publish(self, server: Server) -> None:
        """
        Publishes the client's identity key and prekeys to the server.
        """
        # generate a prekey signature from the given signed prekey
        message = f"{self.client.identity_key.public_key}".encode()
        self.client.prekey_signature = self.client.signed_prekey.private_key.sign(
            message
        )
        logging.debug("Prekey signature: %s", self.client.prekey_signature)
        # verify
        try:
            self.client.signed_prekey.public_key.verify(
                self.client.prekey_signature, message
            )
        except InvalidSignature:
            logging.error("Invalid signature")

        # generate one-time prekeys
        self.client.one_time_prekeys += self.__generate_one_time_prekeys(
            self.num_one_time_prekeys
        )

        # store the client's public keys on the server
        logging.debug(
            "%s %s %s %s",
            len(self.client.identity_key.public_key.public_bytes_raw()),
            len(self.client.signed_prekey.public_key.public_bytes_raw()),
            len(self.client.prekey_signature),
            len(self.client.one_time_prekeys),
        )
        serialised = self.__serialise_publish(
            self.client.identity_key.public_key,
            self.client.signed_prekey.public_key,
            self.client.prekey_signature,
            self.client.one_time_prekeys,
        )
        server.recv(serialised)

    def __serialise_publish(
        self,
        identity_key: PublicKey,
        signed_prekey: PublicKey,
        prekey_signature: bytes,
        one_time_prekeys: List[PublicKey],
    ) -> bytes:
        """
        Serialise the data to be published.
        """
        serialised = bytearray()
        serialised.extend(identity_key.public_bytes_raw())
        serialised.extend(signed_prekey.public_bytes_raw())
        serialised.extend(prekey_signature)
        for key in one_time_prekeys:
            serialised.extend(key.public_key.public_bytes_raw())
        return bytes(serialised)

    def fetch(self, server: Server, client: Client) -> None:
        """
        Fetches the prekey bundle from the server.
        """
        prekey_bundle = server.get_bundle(client)
        logging.debug("Prekey bundle: %s", prekey_bundle)
        self.client.ephemeral_key = XKeyPair(self.client.curve)


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
        self.alice.fetch(self.server, self.bob)
        self.alice.send(self.server, self.bob)

        # bob receives and processes alice's initial message
        sk = self.bob.recv(self.server)
        return sk
