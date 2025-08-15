import random
import string
import tkinter as tk
from tkinter import messagebox
from base_tool import BaseToolFrame
from theme import style_button, style_label, style_entry, style_textbox, BG_COLOR, PANEL_COLOR
import pyperclip  # type: ignore  # For copying to clipboard

TAB_NAME = "Password Generator"

class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        # ===== MAIN PANELS =====
        self.left_panel = tk.Frame(self, bg=PANEL_COLOR, width=300)
        self.left_panel.pack(side="left", fill="y", padx=5, pady=5)

        self.right_panel = tk.Frame(self, bg=BG_COLOR)
        self.right_panel.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        # ===== LEFT: SETTINGS =====
        style_label(tk.Label(self.left_panel, text="🔢 Password Length"))
        self.length_var = tk.IntVar(value=12)
        self.length_slider = tk.Scale(self.left_panel, from_=4, to=64, orient="horizontal",
                                      variable=self.length_var, bg=PANEL_COLOR, fg="white",
                                      troughcolor=BG_COLOR, highlightthickness=0)
        self.length_slider.pack(fill="x", pady=5)

        style_label(tk.Label(self.left_panel, text="⚙️ Options"))
        self.use_upper = tk.BooleanVar(value=True)
        self.use_lower = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)

        for text, var in [
            ("Uppercase (A-Z)", self.use_upper),
            ("Lowercase (a-z)", self.use_lower),
            ("Digits (0-9)", self.use_digits),
            ("Symbols (!@#$)", self.use_symbols)
        ]:
            cb = tk.Checkbutton(self.left_panel, text=text, variable=var,
                                bg=PANEL_COLOR, fg="white", selectcolor=BG_COLOR)
            cb.pack(anchor="w")

        style_label(tk.Label(self.left_panel, text="📦 Batch Size"))
        self.batch_var = tk.IntVar(value=1)
        self.batch_entry = tk.Entry(self.left_panel, textvariable=self.batch_var)
        style_entry(self.batch_entry)
        self.batch_entry.pack(fill="x", pady=5)

        gen_btn = tk.Button(self.left_panel, text="Generate Password(s)", command=self.generate_passwords)
        style_button(gen_btn)
        gen_btn.pack(pady=5)

        # ===== RIGHT: OUTPUT =====
        style_label(tk.Label(self.right_panel, text="📜 Generated Passwords"))
        self.output_text = tk.Text(self.right_panel, height=15)
        style_textbox(self.output_text)
        self.output_text.pack(fill="both", expand=True, pady=5)

        copy_btn = tk.Button(self.right_panel, text="Copy All to Clipboard", command=self.copy_all)
        style_button(copy_btn)
        copy_btn.pack(pady=5)

    def generate_passwords(self):
        length = self.length_var.get()
        batch_size = self.batch_var.get()

        if batch_size < 1 or batch_size > 50:
            messagebox.showerror("Error", "Batch size must be between 1 and 50.")
            return

        chars = ""
        if self.use_upper.get():
            chars += string.ascii_uppercase
        if self.use_lower.get():
            chars += string.ascii_lowercase
        if self.use_digits.get():
            chars += string.digits
        if self.use_symbols.get():
            chars += "!@#$%^&*()-_=+[]{}|;:,.<>?/"

        if not chars:
            messagebox.showerror("Error", "Select at least one character set!")
            return

        self.output_text.delete("1.0", tk.END)
        for _ in range(batch_size):
            password = "".join(random.choice(chars) for _ in range(length))
            self.output_text.insert(tk.END, password + "\n")

    def copy_all(self):
        text = self.output_text.get("1.0", tk.END).strip()
        if not text:
            messagebox.showerror("Error", "No passwords to copy.")
            return
        pyperclip.copy(text)
        messagebox.showinfo("Copied", "All passwords copied to clipboard.")
