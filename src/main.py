from collections import deque
from algorithms.x3dh import X3DH
from algorithms.doublerachet import DoubleRachet

def main():
    """
    Demonstrate X3DH and DoubleRachet algorithms in the context of the
    Signal Protocol.
    """
    server = Server()
    alice = Client('Alice')
    bob = Client('Bob')
    
    # establish connection between alice and bob (x3dh)
    

    # send messages between alice and bob (double ratchet)

    return

class KeyPair():
    def __init__(self):
        return

class Client:
    def __init__(self, name: str):
        self.name = name
        self.ik = KeyPair()
        self.ek = KeyPair()
        self.spk = KeyPair()
        self.opk = KeyPair()

class Server:
    def __init__(self):
        self.message_queue = deque([])


if __name__ == '__main__':
    main()
