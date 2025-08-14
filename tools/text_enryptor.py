TAB_NAME = "Text Encryptor"

import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
import base64
import hashlib

BG_COLOR = "#1E1E1E"
FG_COLOR = "#FFFFFF"
BTN_COLOR = "#333333"
BTN_HOVER = "#444444"

def generate_key(password: str):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

class ToolFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=BG_COLOR)

        tk.Label(self, text="🛡 Text Encryption/Decryption", font=("Segoe UI", 12, "bold"),
                 bg=BG_COLOR, fg=FG_COLOR).pack(pady=10)

        tk.Label(self, text="Password:", bg=BG_COLOR, fg=FG_COLOR).pack()
        self.password_entry = tk.Entry(self, show="*", bg="#222222", fg=FG_COLOR, insertbackground=FG_COLOR)
        self.password_entry.pack(pady=5)

        tk.Label(self, text="Text:", bg=BG_COLOR, fg=FG_COLOR).pack()
        self.text_entry = tk.Text(self, height=5, width=60, bg="#222222", fg=FG_COLOR, insertbackground=FG_COLOR)
        self.text_entry.pack(pady=5)

        self.make_button(self, "Encrypt", self.encrypt_text).pack(pady=5)
        self.make_button(self, "Decrypt", self.decrypt_text).pack(pady=5)

        self.result_text = tk.Text(self, height=5, width=60, bg="#222222", fg=FG_COLOR, insertbackground=FG_COLOR)
        self.result_text.pack(pady=5)

    def make_button(self, parent, text, cmd):
        btn = tk.Button(parent, text=text, bg=BTN_COLOR, fg=FG_COLOR, relief="flat", command=cmd)
        btn.bind("<Enter>", lambda e: btn.config(bg=BTN_HOVER))
        btn.bind("<Leave>", lambda e: btn.config(bg=BTN_COLOR))
        return btn

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
