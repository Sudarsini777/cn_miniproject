import socket
import json
import base64
import hashlib
import tkinter as tk
from tkinter import messagebox, scrolledtext

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


HOST = "127.0.0.1"
PORT = 5000


# =========================================================
# GENERATE RSA KEY PAIR
# =========================================================

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

public_numbers = public_key.public_numbers()

n = public_numbers.n
e = public_numbers.e


# Store last signed information
last_message = None
last_signature = None
last_hash = None


# =========================================================
# SIGN MESSAGE
# =========================================================

def sign_message(message):

    signature = private_key.sign(
        message.encode("utf-8"),

        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),

        hashes.SHA256()
    )

    return signature


# =========================================================
# CREATE PACKET
# =========================================================

def create_packet(message, signature, message_hash):

    return {
        "message": message,

        "signature": base64.b64encode(
            signature
        ).decode("utf-8"),

        "public_key": {
            "n": str(n),
            "e": str(e)
        },

        "sha256": message_hash
    }


# =========================================================
# SEND PACKET TO SERVER
# =========================================================

def send_to_server(packet):

    try:

        client_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        client_socket.connect(
            (HOST, PORT)
        )

        data = json.dumps(packet).encode("utf-8")

        client_socket.sendall(data)

        response = client_socket.recv(4096)

        client_socket.close()

        result = json.loads(
            response.decode("utf-8")
        )

        return result["result"]

    except Exception as error:

        return f"ERROR - Could not connect to server.\n{error}"


# =========================================================
# SIGN & SEND
# =========================================================

def sign_and_send():

    global last_message
    global last_signature
    global last_hash

    message = message_entry.get("1.0", tk.END).strip()

    if not message:

        messagebox.showwarning(
            "Warning",
            "Please enter a message."
        )

        return

    # Create signature
    signature = sign_message(message)

    # Calculate SHA-256
    message_hash = hashlib.sha256(
        message.encode("utf-8")
    ).hexdigest()

    # SAVE ORIGINAL SIGNED DATA
    last_message = message
    last_signature = signature
    last_hash = message_hash

    # Create packet
    packet = create_packet(
        message,
        signature,
        message_hash
    )

    # Send
    result = send_to_server(packet)

    result_box.delete(
        "1.0",
        tk.END
    )

    result_box.insert(
        tk.END,
        "NORMAL SIGNATURE TEST\n\n"
    )

    result_box.insert(
        tk.END,
        f"Message:\n{message}\n\n"
    )

    result_box.insert(
        tk.END,
        f"SHA-256:\n{message_hash}\n\n"
    )

    result_box.insert(
        tk.END,
        f"RESULT:\n{result}"
    )


# =========================================================
# TAMPERING TEST
# =========================================================

def tamper_and_send():

    global last_message
    global last_signature
    global last_hash

    # First sign a message
    if last_signature is None:

        messagebox.showwarning(
            "Warning",
            "First click 'Sign & Send' to create a valid signature."
        )

        return

    # ---------------------------------------------
    # IMPORTANT:
    # Change the message AFTER it was signed.
    # DO NOT create a new signature.
    # ---------------------------------------------

    tampered_message = last_message + " [TAMPERED]"

    # IMPORTANT:
    # We keep the ORIGINAL signature.
    original_signature = last_signature

    # IMPORTANT:
    # We also keep the ORIGINAL hash.
    original_hash = last_hash

    # Create packet using:
    #
    # NEW / MODIFIED MESSAGE
    # +
    # OLD SIGNATURE
    # +
    # OLD HASH
    #
    # This should FAIL.

    packet = create_packet(
        tampered_message,
        original_signature,
        original_hash
    )

    result = send_to_server(packet)

    result_box.delete(
        "1.0",
        tk.END
    )

    result_box.insert(
        tk.END,
        "TAMPERING ATTACK TEST\n\n"
    )

    result_box.insert(
        tk.END,
        f"Original Message:\n{last_message}\n\n"
    )

    result_box.insert(
        tk.END,
        f"Modified Message:\n{tampered_message}\n\n"
    )

    result_box.insert(
        tk.END,
        "Original Signature: KEPT\n"
    )

    result_box.insert(
        tk.END,
        "Original SHA-256: KEPT\n\n"
    )

    result_box.insert(
        tk.END,
        f"RESULT:\n{result}"
    )


# =========================================================
# CLEAR
# =========================================================

def clear_all():

    global last_message
    global last_signature
    global last_hash

    last_message = None
    last_signature = None
    last_hash = None

    message_entry.delete(
        "1.0",
        tk.END
    )

    result_box.delete(
        "1.0",
        tk.END
    )


# =========================================================
# GUI
# =========================================================

root = tk.Tk()

root.title(
    "Digital Signature - Client"
)

root.geometry(
    "750x650"
)


title = tk.Label(
    root,
    text="Digital Signature Client",
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
    padx=20
)


message_entry = scrolledtext.ScrolledText(
    root,
    width=80,
    height=6,
    font=("Arial", 11)
)

message_entry.pack(
    padx=20,
    pady=10
)


# =========================================================
# BUTTONS
# =========================================================

button_frame = tk.Frame(root)

button_frame.pack(
    pady=10
)


sign_button = tk.Button(
    button_frame,
    text="Sign & Send",
    command=sign_and_send,
    bg="green",
    fg="white",
    font=("Arial", 12, "bold"),
    width=15
)

sign_button.grid(
    row=0,
    column=0,
    padx=5
)


tamper_button = tk.Button(
    button_frame,
    text="Tamper & Send",
    command=tamper_and_send,
    bg="red",
    fg="white",
    font=("Arial", 12, "bold"),
    width=15
)

tamper_button.grid(
    row=0,
    column=1,
    padx=5
)


clear_button = tk.Button(
    button_frame,
    text="Clear",
    command=clear_all,
    font=("Arial", 12),
    width=15
)

clear_button.grid(
    row=0,
    column=2,
    padx=5
)


# =========================================================
# RESULT
# =========================================================

result_label = tk.Label(
    root,
    text="Verification Result:",
    font=("Arial", 12, "bold")
)

result_label.pack(
    anchor="w",
    padx=20,
    pady=(15, 5)
)


result_box = scrolledtext.ScrolledText(
    root,
    width=80,
    height=18,
    font=("Consolas", 10)
)

result_box.pack(
    padx=20,
    pady=5,
    fill=tk.BOTH,
    expand=True
)


root.mainloop()