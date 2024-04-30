import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import socket
import zipfile
import ntplib
from io import BytesIO
from datetime import datetime
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from os import urandom

class SenderGUI:
    def __init__(self, master):
        self.master = master
        master.title("Secure File Sender")
        master.geometry('400x300')
        master.resizable(False, False)

        frame = ttk.Frame(master)
        frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.filepath = tk.StringVar()
        file_select_button = ttk.Button(frame, text="Select File to Send", command=self.select_file)
        file_select_button.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        ttk.Label(frame, text="Recipient IP:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.ip_entry = ttk.Entry(frame)
        self.ip_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

        ttk.Label(frame, text="Port:").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.port_entry = ttk.Entry(frame)
        self.port_entry.insert(0, '54321')
        self.port_entry.grid(row=2, column=1, padx=10, pady=5, sticky="ew")

        self.private_key_path = tk.StringVar()
        self.public_key_path = tk.StringVar()
        ttk.Button(frame, text="Select Your Private Key", command=self.select_private_key).grid(row=3, column=0, padx=10, pady=10, sticky="ew")
        ttk.Button(frame, text="Select Recipient's Public Key", command=self.select_public_key).grid(row=3, column=1, padx=10, pady=10, sticky="ew")

        send_button = ttk.Button(frame, text="Send File", command=self.send_file)
        send_button.grid(row=4, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        self.progress = ttk.Progressbar(frame, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress.grid(row=5, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.filepath.set(file_path)
            messagebox.showinfo("File Selected", f"Selected: {file_path}")

    def select_private_key(self):
        key_path = filedialog.askopenfilename(title="Select Your Private Key", filetypes=[("PEM files", "*.pem")])
        if key_path:
            self.private_key_path.set(key_path)
            messagebox.showinfo("Key Selected", f"Private Key Selected: {key_path}")

    def select_public_key(self):
        key_path = filedialog.askopenfilename(title="Select Recipient's Public Key", filetypes=[("PEM files", "*.pem")])
        if key_path:
            self.public_key_path.set(key_path)
            messagebox.showinfo("Key Selected", f"Recipient's Public Key Selected: {key_path}")

    def send_file(self):
        if not all([self.filepath.get(), self.private_key_path.get(), self.public_key_path.get()]):
            messagebox.showerror("Error", "Please select all necessary files and keys.")
            return

        try:
            with open(self.private_key_path.get(), "rb") as key_file:
                sender_private_key = load_pem_private_key(key_file.read(), password=None)

            with open(self.public_key_path.get(), "rb") as key_file:
                receiver_public_key = load_pem_public_key(key_file.read())

            zip_content = self.package_and_compress(self.filepath.get(), sender_private_key)
            session_key = urandom(32)
            iv, encrypted_data = self.encrypt_data(zip_content, session_key)
            encrypted_session_key = self.encrypt_key(session_key, receiver_public_key)
            final_package = iv + encrypted_session_key + encrypted_data
            self.send_data_over_socket(final_package, self.ip_entry.get(), int(self.port_entry.get()))
            messagebox.showinfo("Success", "File sent successfully.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def generate_message_digest(self, data):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return digest.finalize()

    def sign_message(self, private_key, message):
        return private_key.sign(
            message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def package_and_compress(self, filename, sender_private_key):
        with open(filename, "rb") as f:
            original_data = f.read()

        signature = self.sign_message(sender_private_key, self.generate_message_digest(original_data))
        ntp_client = ntplib.NTPClient()
        response = ntp_client.request('time.nist.gov')
        ntp_timestamp = response.tx_time
        formatted_timestamp = datetime.fromtimestamp(ntp_timestamp).strftime('%Y-%m-%d %H:%M:%S').encode('utf-8')

        mem_file = BytesIO()
        with zipfile.ZipFile(mem_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.writestr('original_data', original_data)
            zipf.writestr('signature.txt', signature)
            zipf.writestr('timestamp.txt', formatted_timestamp)
        mem_file.seek(0)
        return mem_file.getvalue()

    def encrypt_data(self, data, key):
        iv = urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return iv, encrypted_data

    def encrypt_key(self, key, public_key):
        return public_key.encrypt(
            key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def send_data_over_socket(self, data, host, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((host, port))
            sock.sendall(data)
        self.progress['value'] = 100

def main():
    root = tk.Tk()
    app = SenderGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
