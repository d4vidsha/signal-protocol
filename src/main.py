from collections import deque
from algorithms.x3dh import X3DH
from algorithms.doublerachet import DoubleRachet
from enum import Enum


def main():
    """
    Demonstrate X3DH and DoubleRachet algorithms in the context of the
    Signal Protocol.
    """
    server = Server()
    alice = Client("Alice")
    bob = Client("Bob")

    # establish connection between alice and bob (x3dh)

    # send messages between alice and bob (double ratchet)

    return


class Curve(Enum):
    X25519 = 0
    X448 = 1


class KeyPair:
    def __init__(self):
        return


class Client:
    def __init__(
        self, name: str, curve: Curve = Curve.X25519, info: str = "MyProtocol"
    ):
        self.name = name
        self.info: str = info
        self.curve: Curve
        self.ik = KeyPair()
        self.ek = KeyPair()
        self.spk = KeyPair()
        self.opk = KeyPair()
        self.mk = KeyPair()


class Server:
    def __init__(self):
        self.message_queue = deque([])


if __name__ == "__main__":
    main()
