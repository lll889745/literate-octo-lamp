import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import socket
import zipfile
from io import BytesIO
from datetime import datetime
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from os import urandom
from threading import Thread

class ReceiverGUI:
    def __init__(self, master):
        self.master = master
        master.title("Secure File Receiver")
        master.geometry('400x300')
        master.resizable(False, False)

        frame = ttk.Frame(master)
        frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Listening Port:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.port_entry = ttk.Entry(frame)
        self.port_entry.insert(0, '54321')
        self.port_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

        self.public_key_path = tk.StringVar()
        self.private_key_path = tk.StringVar()
        ttk.Button(frame, text="Select Your Private Key", command=self.select_private_key).grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        ttk.Button(frame, text="Select Sender's Public Key", command=self.select_sender_public_key).grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        self.receive_button = ttk.Button(frame, text="Start Receiving", command=self.start_receiving)
        self.receive_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        self.status_label = ttk.Label(frame, text="Status: Ready")
        self.status_label.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

        self.progress = ttk.Progressbar(frame, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress.grid(row=4, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

    def select_private_key(self):
        key_path = filedialog.askopenfilename(title="Select Your Private Key", filetypes=[("PEM files", "*.pem")])
        if key_path:
            self.private_key_path.set(key_path)
            messagebox.showinfo("Key Selected", f"Your Private Key Selected: {key_path}")

    def select_sender_public_key(self):
        key_path = filedialog.askopenfilename(title="Select Sender's Public Key", filetypes=[("PEM files", "*.pem")])
        if key_path:
            self.public_key_path.set(key_path)
            messagebox.showinfo("Key Selected", f"Sender's Public Key Selected: {key_path}")

    def start_receiving(self):
        if not all([self.private_key_path.get(), self.public_key_path.get()]):
            messagebox.showerror("Error", "Please select both private and sender's public keys before receiving.")
            return
        self.receive_button.config(state="disabled")
        self.status_label.config(text="Status: Listening")
        port = int(self.port_entry.get())
        thread = Thread(target=self.listen_for_data, args=(port,))
        thread.start()

    def listen_for_data(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(('', port))
            sock.listen(1)
            self.master.after(50, lambda: self.status_label.config(text="Status: Waiting for connection"))
            conn, addr = sock.accept()
            with conn:
                self.master.after(50, lambda: self.status_label.config(text="Status: Receiving Data"))
                total_data = b''
                while True:
                    data = conn.recv(65536)
                    if not data:
                        break
                    total_data += data
                if total_data:
                    Thread(target=self.process_received_data, args=(total_data,)).start()

    def process_received_data(self, data):
        try:
            self.status_label.config(text="Status: Processing Data")
            iv, encrypted_key, encrypted_data = data[:16], data[16:272], data[272:]
            session_key = self.decrypt_key(encrypted_key, self.private_key_path.get())
            decrypted_data = self.decrypt_data(encrypted_data, session_key, iv)
            original_data, signature, timestamp = self.extract_data(decrypted_data)
            sender_public_key = load_pem_public_key(open(self.public_key_path.get(), "rb").read())
            verification_result = self.verify_signature(original_data, signature, sender_public_key)
            timestamp_valid = self.check_timestamp(timestamp)
            self.save_received_file(original_data)
            messagebox.showinfo("Verification Result", f"Signature Verified: {verification_result}\nTimestamp Valid: {timestamp_valid}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to process received data: {str(e)}")
        finally:
            self.status_label.config(text="Status: Ready")
            self.receive_button.config(state="normal")

    def decrypt_key(self, encrypted_key, private_key_path):
        with open(private_key_path, "rb") as key_file:
            private_key = load_pem_private_key(key_file.read(), password=None)
        return private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt_data(self, encrypted_data, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data) + decryptor.finalize()

    def extract_data(self, decrypted_data):
        with zipfile.ZipFile(BytesIO(decrypted_data), 'r') as zipf:
            original_data = zipf.read('original_data')
            signature = zipf.read('signature.txt')
            timestamp = zipf.read('timestamp.txt')
        return original_data, signature, timestamp

    def verify_signature(self, data, signature, public_key):
        try:
            public_key.verify(
                signature,
                data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Signature verification error: {e}")
            return False

    def check_timestamp(self, timestamp):
        received_time = datetime.strptime(timestamp.decode('utf-8'), '%Y-%m-%d %H:%M:%S')
        current_time = datetime.now()
        return (current_time - received_time).total_seconds() < 300

    def save_received_file(self, data):
        save_path = filedialog.asksaveasfilename(title="Save Received File", filetypes=[("All files", "*.*")])
        if save_path:
            with open(save_path, 'wb') as file:
                file.write(data)
            messagebox.showinfo("File Saved", f"File successfully saved to {save_path}")

def main():
    root = tk.Tk()
    app = ReceiverGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
