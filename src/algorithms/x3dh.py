from enum import Enum, auto
from collections import deque
from typing import Dict, Set
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
        return f"Private key: {self.private_key}\nPublic key: {self.public_key}"


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
        return f"Private key: {self.private_key}\nPublic key: {self.public_key}"


@dataclass
class KeyBase:
    """
    Public key.
    """

    value: str


@dataclass
class PublicKey(KeyBase):
    """
    Private key.
    """


@dataclass
class PrivateKey(KeyBase):
    """
    Private key.
    """


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
        prekey_signature: str
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
        self.clients: Dict[PublicKey, Server.ClientData] = {}
        self.message_queue: Server.Message = deque([])


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
        prekey_signature: str
        one_time_prekeys: Set[XKeyPair]
        shared_secret_key: KeyBase

    def __init__(
        self,
        name: str,
        curve: Curve = Curve.Curve25519,
        hash_type: HashType = HashType.SHA256,
        info: str = "MyProtocol",
    ):
        print(XKeyPair(curve))
        self.client = Client.Client(
            name=name,
            curve=curve,
            hash=hash_type,
            info=info,
            identity_key=XKeyPair(curve),
            ephemeral_key=None,
            signed_prekey=EdKeyPair(curve),
            prekey_signature=None,
            one_time_prekeys=set(),
            shared_secret_key=None,
        )

    def encode(self, pk: PublicKey):
        """
        Converts public key to a byte sequence. A single-byte constant is used
        to represent the type of curve, followed by little-endian encoding
        of the u-coordinate.
        """
        return

    def publish(self, server: Server) -> None:
        """
        Publishes the client's identity key and prekeys to the server.
        """
        prekey_signature = self.client.signed_prekey.private_key.sign(
            f"{self.client.identity_key.public_key}".encode()
        )
        print(prekey_signature)
        server.recv(
            self.identity_key,
            self.signed_prekey,
            self.prekey_signature,
            self.one_time_prekeys,
        )


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
