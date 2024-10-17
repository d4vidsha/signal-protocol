import time
import threading

# Shared file for communication
shared_file = "/app/shared.txt"

# Global variables for username and target
username = 'Alice'
target = None
# alice private key

def send_messages():
    global username, target
    print("Welcome to the chat, Alice!")
    target = input("Enter the recipient's username: ")

    while True:
        message = input(f"{username}, enter your message: ")
        with open(shared_file, "a") as f:
            f.write(f"{username} to {target}: {message}\n")
        print(f"{username} sent: {message}")

def listen_for_messages():
    last_seen = 0
    while True:
        with open(shared_file, "r") as f:
            lines = f.readlines()
            # Print new messages that Alice hasn't seen yet
            for line in lines[last_seen:]:
                # Only display messages that are for the current user
                if line.startswith(f"{target}:"):
                    print(f"{username} received: {line.strip()}")
            last_seen = len(lines)
        time.sleep(1)

if __name__ == '__main__':
    threading.Thread(target=send_messages, daemon=True).start()
    listen_for_messages()
