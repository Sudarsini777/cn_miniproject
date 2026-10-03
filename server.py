import socket
import json
import base64
import hashlib
import tkinter as tk
from tkinter import scrolledtext
from datetime import datetime
import threading

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


HOST = "127.0.0.1"
PORT = 5000


def verify_signature(data):
    try:
        message = data["message"]

        # Get original SHA-256 hash sent by client
        received_hash = data["sha256"]

        # Calculate SHA-256 of received message
        calculated_hash = hashlib.sha256(
            message.encode("utf-8")
        ).hexdigest()

        # Reconstruct public key
        public_numbers = rsa.RSAPublicNumbers(
            int(data["public_key"]["e"]),
            int(data["public_key"]["n"])
        )

        public_key = public_numbers.public_key()

        # Decode signature
        signature = base64.b64decode(data["signature"])

        # First check message integrity
        if received_hash != calculated_hash:
            return (
                "INVALID - Message integrity check failed.\n"
                "The message was modified."
            )

        # Verify digital signature
        public_key.verify(
            signature,
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return "VALID - Digital signature verified successfully."

    except InvalidSignature:
        return "INVALID - Digital signature verification failed."

    except Exception as e:
        return f"ERROR - {str(e)}"


def handle_client(conn, address):
    try:
        data = conn.recv(65536)

        if not data:
            return

        packet = json.loads(data.decode("utf-8"))

        message = packet["message"]

        received_hash = packet["sha256"]

        calculated_hash = hashlib.sha256(
            message.encode("utf-8")
        ).hexdigest()

        result = verify_signature(packet)

        log_message(
            f"""
========================================
TIME: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
CLIENT: {address}

RECEIVED MESSAGE:
{message}

RECEIVED SHA-256:
{received_hash}

CALCULATED SHA-256:
{calculated_hash}

VERIFICATION RESULT:
{result}
========================================
"""
        )

        response = {
            "result": result
        }

        conn.sendall(
            json.dumps(response).encode("utf-8")
        )

    except Exception as e:
        log_message(f"Server Error: {e}")

    finally:
        conn.close()


def start_server():
    server_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server_socket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    log_message(
        f"Server started on {HOST}:{PORT}\n"
        "Waiting for client messages..."
    )

    while True:
        conn, address = server_socket.accept()

        thread = threading.Thread(
            target=handle_client,
            args=(conn, address),
            daemon=True
        )

        thread.start()


def log_message(message):
    server_log.insert(tk.END, message + "\n")
    server_log.see(tk.END)


# ---------------- GUI ----------------

root = tk.Tk()
root.title("Digital Signature - Server")
root.geometry("750x600")

title = tk.Label(
    root,
    text="Digital Signature Verification Server",
    font=("Arial", 18, "bold")
)

title.pack(pady=10)

status = tk.Label(
    root,
    text="Server: Starting...",
    font=("Arial", 12)
)

status.pack(pady=5)

server_log = scrolledtext.ScrolledText(
    root,
    width=85,
    height=28,
    font=("Consolas", 10)
)

server_log.pack(
    padx=10,
    pady=10,
    fill=tk.BOTH,
    expand=True
)

threading.Thread(
    target=start_server,
    daemon=True
).start()

status.config(
    text=f"Server running on {HOST}:{PORT}"
)

root.mainloop()