import socket
import json
import base64
import hashlib
import threading
import tkinter as tk
from tkinter import scrolledtext

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


HOST = "127.0.0.1"
PORT = 5000
KEY_FILE = "private_key.pem"

# The FIRST signature becomes the fixed reference
reference_signature = None


# ==========================================
# LOAD PRIVATE KEY
# ==========================================

def load_private_key():

    with open(KEY_FILE, "rb") as file:
        return serialization.load_pem_private_key(
            file.read(),
            password=None
        )


private_key = load_private_key()


# ==========================================
# CREATE SIGNATURE
# ==========================================

def create_signature(message):

    return private_key.sign(
        message.encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256()
    )


# ==========================================
# HANDLE CLIENT
# ==========================================

def handle_client(client_socket, address):

    global reference_signature

    try:

        # Receive data
        data = client_socket.recv(8192)

        if not data:
            return

        request = json.loads(
            data.decode("utf-8")
        )

        message = request["message"]

        # Client's signature
        client_signature = base64.b64decode(
            request["signature"]
        )

        # ==========================================
        # SERVER GENERATES SIGNATURE
        # ==========================================

        server_signature = create_signature(
            message
        )

        # ==========================================
        # HASH CHECK
        # ==========================================

        client_hash = request["sha256"]

        server_hash = hashlib.sha256(
            message.encode("utf-8")
        ).hexdigest()

        hash_same = (
            client_hash == server_hash
        )

        # ==========================================
        # CLIENT SIGNATURE VS SERVER SIGNATURE
        # ==========================================

        client_server_same = (
            client_signature == server_signature
        )

        # ==========================================
        # FIRST SIGNATURE AS REFERENCE
        # ==========================================

        if reference_signature is None:

            reference_signature = server_signature

            first_request = True

            reference_same = True

        else:

            first_request = False

            reference_same = (
                reference_signature ==
                server_signature
            )

        # ==========================================
        # FINAL RESULT
        # ==========================================

        if reference_same:

            final_result = "TRUE"

        else:

            final_result = "FALSE"

        # ==========================================
        # SERVER OUTPUT
        # ==========================================

        server_output.insert(
            tk.END,
            "\n\n"
            "========================================\n"
        )

        server_output.insert(
            tk.END,
            "          NEW CLIENT REQUEST\n"
        )

        server_output.insert(
            tk.END,
            "========================================\n\n"
        )

        server_output.insert(
            tk.END,
            f"CLIENT ADDRESS:\n{address}\n\n"
        )

        server_output.insert(
            tk.END,
            f"MESSAGE:\n{message}\n\n"
        )

        # Client signature
        server_output.insert(
            tk.END,
            "CLIENT SIGNATURE:\n"
        )

        server_output.insert(
            tk.END,
            client_signature.hex()
        )

        server_output.insert(
            tk.END,
            "\n\n"
        )

        # Server signature
        server_output.insert(
            tk.END,
            "SERVER GENERATED SIGNATURE:\n"
        )

        server_output.insert(
            tk.END,
            server_signature.hex()
        )

        server_output.insert(
            tk.END,
            "\n\n"
        )

        # Reference signature
        server_output.insert(
            tk.END,
            "FIXED FIRST SIGNATURE:\n"
        )

        server_output.insert(
            tk.END,
            reference_signature.hex()
        )

        server_output.insert(
            tk.END,
            "\n\n"
        )

        # Hash
        server_output.insert(
            tk.END,
            f"CLIENT HASH:\n{client_hash}\n\n"
        )

        server_output.insert(
            tk.END,
            f"SERVER HASH:\n{server_hash}\n\n"
        )

        server_output.insert(
            tk.END,
            f"HASH SAME: {hash_same}\n\n"
        )

        # Client vs server
        server_output.insert(
            tk.END,
            "CLIENT SIGNATURE == "
            "SERVER SIGNATURE:\n"
        )

        server_output.insert(
            tk.END,
            f"{client_server_same}\n\n"
        )

        # Reference comparison
        if first_request:

            server_output.insert(
                tk.END,
                "FIRST SIGNATURE STORED AS "
                "REFERENCE\n\n"
            )

        else:

            server_output.insert(
                tk.END,
                "CURRENT SIGNATURE == "
                "FIRST SIGNATURE:\n"
            )

            server_output.insert(
                tk.END,
                f"{reference_same}\n\n"
            )

        # ==========================================
        # FINAL RESULT
        # ==========================================

        server_output.insert(
            tk.END,
            "========================================\n"
        )

        if final_result == "TRUE":

            server_output.insert(
                tk.END,
                "TRUE - SIGNATURE MATCHES "
                "REFERENCE\n"
            )

            server_output.insert(
                tk.END,
                "DIGITAL SIGNATURE IS VALID\n"
            )

        else:

            server_output.insert(
                tk.END,
                "FALSE - SIGNATURE DOES NOT "
                "MATCH REFERENCE\n"
            )

            server_output.insert(
                tk.END,
                "DIGITAL SIGNATURE IS INVALID\n"
            )

        server_output.insert(
            tk.END,
            "========================================\n"
        )

        server_output.see(tk.END)

        # ==========================================
        # SEND RESULT TO CLIENT
        # ==========================================

        response = {

            "hash_same":
                hash_same,

            "client_server_same":
                client_server_same,

            "reference_same":
                reference_same,

            "first_request":
                first_request,

            "result":
                final_result
        }

        client_socket.send(
            json.dumps(response).encode("utf-8")
        )

    except Exception as e:

        server_output.insert(
            tk.END,
            f"\nERROR: {str(e)}\n"
        )

        server_output.see(tk.END)

    finally:

        client_socket.close()


# ==========================================
# START SERVER
# ==========================================

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

    server_socket.bind(
        (HOST, PORT)
    )

    server_socket.listen(5)

    server_output.insert(
        tk.END,
        "========================================\n"
    )

    server_output.insert(
        tk.END,
        "       DIGITAL SIGNATURE SERVER\n"
    )

    server_output.insert(
        tk.END,
        "========================================\n\n"
    )

    server_output.insert(
        tk.END,
        f"Server running on {HOST}:{PORT}\n"
    )

    server_output.insert(
        tk.END,
        "Waiting for client...\n\n"
    )

    server_output.see(tk.END)

    while True:

        client_socket, address = (
            server_socket.accept()
        )

        client_thread = threading.Thread(
            target=handle_client,
            args=(client_socket, address),
            daemon=True
        )

        client_thread.start()


# ==========================================
# SERVER GUI
# ==========================================

root = tk.Tk()

root.title(
    "Digital Signature - Server"
)

root.geometry(
    "900x700"
)

root.resizable(False, False)


title = tk.Label(
    root,
    text="DIGITAL SIGNATURE SERVER",
    font=("Arial", 20, "bold")
)

title.pack(pady=15)


server_output = scrolledtext.ScrolledText(
    root,
    width=105,
    height=38,
    font=("Courier New", 10)
)

server_output.pack(
    padx=20,
    pady=10
)


server_thread = threading.Thread(
    target=start_server,
    daemon=True
)

server_thread.start()


root.mainloop()
