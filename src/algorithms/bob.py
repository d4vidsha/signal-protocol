import time
import threading

# Shared file for communication
shared_file = "/app/shared.txt"

def send_messages():
    while True:
        message = input("Bob, enter your message: ")
        with open(shared_file, "a") as f:
            f.write(f"Bob: {message}\n")
        print(f"Bob sent: {message}")

def listen_for_messages():
    last_seen = 0
    while True:
        with open(shared_file, "r") as f:
            lines = f.readlines()
            # Print new messages that Bob hasn't seen yet
            for line in lines[last_seen:]:
                if line.startswith("Alice:"):
                    print(f"Bob received: {line.strip()}")
            last_seen = len(lines)
        time.sleep(1)

if __name__ == '__main__':
    threading.Thread(target=send_messages, daemon=True).start()
    listen_for_messages()
