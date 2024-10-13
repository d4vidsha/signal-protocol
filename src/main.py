import logging
import sys
import argparse
from algorithms.x3dh import X3DH

# from algorithms.doublerachet import DoubleRachet
from algorithms.x3dh import Client, Server


def main():
    """
    Demonstrate X3DH and DoubleRachet algorithms in the context of the
    Signal Protocol.
    """

    # get all the arguments
    parser = argparse.ArgumentParser(description="Demonstrate Signal Protocol.")
    parser.add_argument(
        "--log",
        type=str,
        choices=["DEBUG", "INFO", "ERROR"],
        default="INFO",
        help="The log level to use.",
    )
    args = parser.parse_args()

    # set up logging
    match args.log:
        case "DEBUG":
            logging_level = logging.DEBUG
            logging_format = "[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"
        case "INFO":
            logging_level = logging.INFO
            logging_format = "[%(asctime)s] %(levelname)s: %(message)s"
        case "ERROR":
            logging_level = logging.ERROR
            logging_format = "[%(asctime)s] %(levelname)s: %(message)s"

    logging.basicConfig(stream=sys.stderr, level=logging_level, format=logging_format)

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
