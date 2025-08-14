TAB_NAME = "Password Generator"

import tkinter as tk
from tkinter import messagebox
import secrets
import string
from utils import get_save_path

BG_COLOR = "#1E1E1E"
FG_COLOR = "#FFFFFF"
BTN_COLOR = "#333333"
BTN_HOVER = "#444444"

class ToolFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=BG_COLOR)

        tk.Label(self, text="Password Generator", font=("Segoe UI", 12, "bold"),
                 bg=BG_COLOR, fg=FG_COLOR).pack(pady=10)

        row = tk.Frame(self, bg=BG_COLOR); row.pack(pady=4)
        tk.Label(row, text="Length:", bg=BG_COLOR, fg=FG_COLOR).pack(side="left")
        self.len_entry = tk.Entry(row, width=6, bg="#222222", fg=FG_COLOR, insertbackground=FG_COLOR)
        self.len_entry.insert(0, "16")
        self.len_entry.pack(side="left", padx=6)

        self.use_upper = tk.IntVar(value=1)
        self.use_lower = tk.IntVar(value=1)
        self.use_digits = tk.IntVar(value=1)
        self.use_punct = tk.IntVar(value=1)

        opts = tk.Frame(self, bg=BG_COLOR); opts.pack(pady=4)
        tk.Checkbutton(opts, text="Uppercase", variable=self.use_upper, bg=BG_COLOR, fg=FG_COLOR,
                       selectcolor=BG_COLOR, activebackground=BG_COLOR).pack(side="left")
        tk.Checkbutton(opts, text="Lowercase", variable=self.use_lower, bg=BG_COLOR, fg=FG_COLOR,
                       selectcolor=BG_COLOR, activebackground=BG_COLOR).pack(side="left", padx=4)
        tk.Checkbutton(opts, text="Digits", variable=self.use_digits, bg=BG_COLOR, fg=FG_COLOR,
                       selectcolor=BG_COLOR, activebackground=BG_COLOR).pack(side="left", padx=4)
        tk.Checkbutton(opts, text="Symbols", variable=self.use_punct, bg=BG_COLOR, fg=FG_COLOR,
                       selectcolor=BG_COLOR, activebackground=BG_COLOR).pack(side="left", padx=4)

        self.make_button(self, "Generate", self.generate).pack(pady=8)
        self.output = tk.Entry(self, width=60, bg="#222222", fg=FG_COLOR, insertbackground=FG_COLOR)
        self.output.pack(pady=4)

    def make_button(self, parent, text, cmd):
        btn = tk.Button(parent, text=text, bg=BTN_COLOR, fg=FG_COLOR, relief="flat", command=cmd)
        btn.bind("<Enter>", lambda e: btn.config(bg=BTN_HOVER))
        btn.bind("<Leave>", lambda e: btn.config(bg=BTN_COLOR))
        return btn

    def generate(self):
        try:
            length = int(self.len_entry.get())
            if length <= 0:
                raise ValueError
        except Exception:
            messagebox.showerror("Error", "Invalid length.")
            return

        pool = ""
        if self.use_upper.get(): pool += string.ascii_uppercase
        if self.use_lower.get(): pool += string.ascii_lowercase
        if self.use_digits.get(): pool += string.digits
        if self.use_punct.get(): pool += string.punctuation

        if not pool:
            messagebox.showerror("Error", "Select at least one character set.")
            return

        chars = []
        if self.use_upper.get(): chars.append(secrets.choice(string.ascii_uppercase))
        if self.use_lower.get(): chars.append(secrets.choice(string.ascii_lowercase))
        if self.use_digits.get(): chars.append(secrets.choice(string.digits))
        if self.use_punct.get(): chars.append(secrets.choice(string.punctuation))
        while len(chars) < length:
            chars.append(secrets.choice(pool))
        secrets.SystemRandom().shuffle(chars)
        pwd = "".join(chars[:length])

        self.output.delete(0, tk.END)
        self.output.insert(0, pwd)

        path = get_save_path("Password_Generator", "passwords.txt")
        with open(path, "a", encoding="utf-8") as f:
            f.write(pwd + "\n")
        messagebox.showinfo("Saved", f"Password appended to:\n{path}")
