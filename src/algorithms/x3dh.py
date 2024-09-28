from enum import Enum
from collections import deque


class Curve(Enum):
    """
    Types of curves.
    """

    X25519 = 0
    X448 = 1


class HashType(Enum):
    """
    Types of hashes.
    """

    SHA256 = 0
    SHA512 = 1


class KeyPair:
    """
    Keypair.
    """

    def __init__(self):
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


class Client:
    """
    The client which can send and receive messages.
    """

    def __init__(
        self,
        name: str,
        curve: Curve = Curve.X25519,
        hash_type: HashType = HashType.SHA256,
        info: str = "MyProtocol",
    ):
        self.name = name
        self.curve: Curve = curve
        self.hash: HashType = hash_type
        self.info: str = info
        self.ik = KeyPair()
        self.ek = KeyPair()
        self.spk = KeyPair()
        self.opk = KeyPair()
        self.mk = KeyPair()

    def encode(self, pk: PublicKey):
        """
        Converts public key to a byte sequence. A single-byte constant is used
        to represent the type of curve, followed by little-endian encoding
        of the u-coordinate.
        """


class Server:
    """
    The server handling all connections and messages between clients.
    """

    def __init__(self):
        self.message_queue = deque([])


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

        # alice fetches a "prekey bundle" from the server, and uses it to send an
        # initial message to bob
        self.alice.fetch(self.server, self.bob)
        self.alice.send(self.server, self.bob)

        # bob receives and processes alice's initial message
        sk = self.bob.recv(self.server)
        return sk
