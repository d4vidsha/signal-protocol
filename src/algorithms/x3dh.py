from enum import Enum, auto
from collections import deque
from typing import Dict, Set
from dataclasses import dataclass


class Curve(Enum):
    """
    Types of curves.
    """

    X25519 = auto()
    X448 = auto()


class HashType(Enum):
    """
    Types of hashes.
    """

    SHA256 = auto()
    SHA512 = auto()


class KeyPair:
    """
    Keypair.
    """

    def __init__(self, curve: Curve = Curve.X25519):
        self.public_key: PublicKey
        self.private_key: PrivateKey
        return

    def generate(self):
        return


def decodeLittleEndian(b, bits):
    """ """
    return sum([b[i] << 8 * i for i in range((bits + 7) / 8)])


def decodeUCoordinate(u, bits):
    u_list = [ord(b) for b in u]
    # Ignore any unused bits.
    if bits % 8:
        u_list[-1] &= (1 << (bits % 8)) - 1
    return decodeLittleEndian(u_list, bits)


def encodeUCoordinate(u, bits):
    u = u % p
    return "".join([chr((u >> 8 * i) & 0xFF) for i in range((bits + 7) / 8)])


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
        identity_key: KeyPair
        ephemeral_key: KeyPair
        signed_prekey: KeyPair
        one_time_prekeys: Set[KeyPair]
        shared_secret_key: KeyBase

    def __init__(
        self,
        name: str,
        curve: Curve = Curve.X25519,
        hash_type: HashType = HashType.SHA256,
        info: str = "MyProtocol",
    ):
        self.data = Client.Client(
            name=name,
            curve=curve,
            hash=hash_type,
            info=info,
            identity_key=KeyPair(curve),
            ephemeral_key=KeyPair(curve),
            signed_prekey=KeyPair(curve),
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

    def publish(self, server: Server):
        """
        Publishes the client's identity key and prekeys to the server.
        """

        return


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
