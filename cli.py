import socket
import json
import base64
import hashlib
import tkinter as tk
from tkinter import scrolledtext, messagebox

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
# CREATE DIGITAL SIGNATURE
# ==========================================

def create_signature(message):

    return private_key.sign(
        message.encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256()
    )


# ==========================================
# SIGN & SEND
# ==========================================

def sign_and_send():

    global reference_signature

    message = message_box.get(
        "1.0",
        tk.END
    ).strip()

    if not message:

        messagebox.showwarning(
            "Warning",
            "Please enter a message."
        )

        return

    try:

        # ==========================================
        # CREATE CURRENT SIGNATURE
        # ==========================================

        current_signature = create_signature(
            message
        )

        # ==========================================
        # CREATE HASH
        # ==========================================

        message_hash = hashlib.sha256(
            message.encode("utf-8")
        ).hexdigest()

        encoded_signature = base64.b64encode(
            current_signature
        ).decode("utf-8")

        # ==========================================
        # SEND PACKET
        # ==========================================

        packet = {

            "message":
                message,

            "signature":
                encoded_signature,

            "sha256":
                message_hash
        }

        client_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        client_socket.connect(
            (HOST, PORT)
        )

        client_socket.send(
            json.dumps(packet).encode("utf-8")
        )

        response_data = client_socket.recv(
            8192
        )

        response = json.loads(
            response_data.decode("utf-8")
        )

        client_socket.close()

        # ==========================================
        # CLIENT OUTPUT
        # ==========================================

        output_box.delete(
            "1.0",
            tk.END
        )

        output_box.insert(
            tk.END,
            "========================================\n"
        )

        output_box.insert(
            tk.END,
            "       DIGITAL SIGNATURE CLIENT\n"
        )

        output_box.insert(
            tk.END,
            "========================================\n\n"
        )

        output_box.insert(
            tk.END,
            f"MESSAGE:\n{message}\n\n"
        )

        # Current signature
        output_box.insert(
            tk.END,
            "CURRENT SIGNATURE:\n"
        )

        output_box.insert(
            tk.END,
            current_signature.hex()
        )

        output_box.insert(
            tk.END,
            "\n\n"
        )

        # ==========================================
        # FIRST SIGNATURE
        # ==========================================

        if reference_signature is None:

            reference_signature = current_signature

            reference_same = True

            output_box.insert(
                tk.END,
                "FIXED FIRST SIGNATURE:\n"
            )

            output_box.insert(
                tk.END,
                reference_signature.hex()
            )

            output_box.insert(
                tk.END,
                "\n\n"
            )

            output_box.insert(
                tk.END,
                "FIRST SIGNATURE STORED AS "
                "REFERENCE.\n\n"
            )

        else:

            output_box.insert(
                tk.END,
                "FIXED FIRST SIGNATURE:\n"
            )

            output_box.insert(
                tk.END,
                reference_signature.hex()
            )

            output_box.insert(
                tk.END,
                "\n\n"
            )

            reference_same = (
                reference_signature ==
                current_signature
            )

            output_box.insert(
                tk.END,
                "CURRENT == FIRST SIGNATURE:\n"
            )

            output_box.insert(
                tk.END,
                f"{reference_same}\n\n"
            )

        # ==========================================
        # SERVER RESPONSE
        # ==========================================

        output_box.insert(
            tk.END,
            "========== SERVER RESPONSE ==========\n\n"
        )

        output_box.insert(
            tk.END,
            f"HASH SAME: "
            f"{response['hash_same']}\n\n"
        )

        output_box.insert(
            tk.END,
            "CLIENT SIGNATURE == "
            "SERVER SIGNATURE:\n"
        )

        output_box.insert(
            tk.END,
            f"{response['client_server_same']}\n\n"
        )

        output_box.insert(
            tk.END,
            "CURRENT == FIRST SIGNATURE "
            "ON SERVER:\n"
        )

        output_box.insert(
            tk.END,
            f"{response['reference_same']}\n\n"
        )

        # ==========================================
        # FINAL RESULT
        # ==========================================

        final_result = response["result"]

        output_box.insert(
            tk.END,
            "========================================\n"
        )

        if final_result == "TRUE":

            output_box.insert(
                tk.END,
                "TRUE - SIGNATURE MATCHES "
                "REFERENCE\n"
            )

            output_box.insert(
                tk.END,
                "DIGITAL SIGNATURE IS VALID\n"
            )

        else:

            output_box.insert(
                tk.END,
                "FALSE - SIGNATURE DOES NOT "
                "MATCH REFERENCE\n"
            )

            output_box.insert(
                tk.END,
                "DIGITAL SIGNATURE IS INVALID\n"
            )

        output_box.insert(
            tk.END,
            "========================================\n"
        )

    except ConnectionRefusedError:

        messagebox.showerror(
            "Connection Error",
            "Server is not running.\n\n"
            "Please start server.py first."
        )

    except Exception as e:

        messagebox.showerror(
            "Error",
            str(e)
        )


# ==========================================
# CLEAR
# ==========================================

def clear_all():

    message_box.delete(
        "1.0",
        tk.END
    )

    output_box.delete(
        "1.0",
        tk.END
    )


# ==========================================
# CLIENT GUI
# ==========================================

root = tk.Tk()

root.title(
    "Digital Signature - Client"
)

root.geometry(
    "850x700"
)

root.resizable(False, False)


title = tk.Label(
    root,
    text="DIGITAL SIGNATURE CLIENT",
    font=("Arial", 20, "bold")
)

title.pack(pady=15)


message_label = tk.Label(
    root,
    text="Enter Message:",
    font=("Arial", 12, "bold")
)

message_label.pack(
    anchor="w",
    padx=30
)


message_box = scrolledtext.ScrolledText(
    root,
    width=90,
    height=5,
    font=("Arial", 11)
)

message_box.pack(
    padx=30,
    pady=10
)


# ==========================================
# BUTTONS
# ==========================================

button_frame = tk.Frame(root)

button_frame.pack(pady=10)


sign_button = tk.Button(
    button_frame,
    text="SIGN & SEND",
    font=("Arial", 12, "bold"),
    width=18,
    command=sign_and_send
)

sign_button.grid(
    row=0,
    column=0,
    padx=10
)


clear_button = tk.Button(
    button_frame,
    text="CLEAR",
    font=("Arial", 12, "bold"),
    width=18,
    command=clear_all
)

clear_button.grid(
    row=0,
    column=1,
    padx=10
)


# ==========================================
# OUTPUT
# ==========================================

output_label = tk.Label(
    root,
    text="Result:",
    font=("Arial", 12, "bold")
)

output_label.pack(
    anchor="w",
    padx=30
)


output_box = scrolledtext.ScrolledText(
    root,
    width=90,
    height=27,
    font=("Courier New", 10)
)

output_box.pack(
    padx=30,
    pady=10
)


root.mainloop()
