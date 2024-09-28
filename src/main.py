from algorithms.x3dh import X3DH

# from algorithms.doublerachet import DoubleRachet
from algorithms.x3dh import Client, Server


def main():
    """
    Demonstrate X3DH and DoubleRachet algorithms in the context of the
    Signal Protocol.
    """
    server = Server()
    alice = Client("Alice")
    bob = Client("Bob")

    # establish connection between alice and bob (x3dh)
    x3dh = X3DH(server, alice, bob)
    sk = x3dh.run()
    print(sk)

    # send messages between alice and bob (double ratchet)
    # alice.send("Hello world!")

    return


if __name__ == "__main__":
    main()
