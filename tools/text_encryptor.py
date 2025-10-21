TAB_NAME = "Text Encryptor"

import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
import base64
import hashlib
from base_tool import BaseToolFrame

def generate_key(password: str):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        self.add_label("🛡 Text Encryption/Decryption", font=("Segoe UI", 12, "bold"))

        self.add_label("Password:")
        self.password_entry = self.add_entry()
        self.password_entry.config(show="*")

        self.add_label("Text:")
        self.text_entry = self.add_textbox(height=5, width=60)

        self.add_button("Encrypt", self.encrypt_text)
        self.add_button("Decrypt", self.decrypt_text)

        self.result_text = self.add_textbox(height=5, width=60)



    def encrypt_text(self):
        pwd = self.password_entry.get()
        if not pwd:
            messagebox.showerror("Error", "Enter a password.")
            return
        key = generate_key(pwd)
        fernet = Fernet(key)
        enc = fernet.encrypt(self.text_entry.get("1.0", tk.END).strip().encode())
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, enc.decode())

    def decrypt_text(self):
        pwd = self.password_entry.get()
        if not pwd:
            messagebox.showerror("Error", "Enter a password.")
            return
        try:
            key = generate_key(pwd)
            fernet = Fernet(key)
            dec = fernet.decrypt(self.text_entry.get("1.0", tk.END).strip().encode())
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert(tk.END, dec.decode())
        except Exception as e:
            messagebox.showerror("Error", "Invalid password or corrupted text.")