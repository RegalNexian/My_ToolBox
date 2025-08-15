# base_tool.py — Sci-Fi styled base for all tools
import tkinter as tk
from theme import BG_COLOR, TEXT_COLOR, style_button

class BaseToolFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=BG_COLOR)

    def add_label(self, text, font=("Consolas", 12, "bold")):
        label = tk.Label(self, text=text, bg=BG_COLOR, fg=TEXT_COLOR, font=font)
        label.pack(pady=5)
        return label

    def add_button(self, text, command):
        btn = tk.Button(self, text=text, command=command)
        style_button(btn)
        btn.pack(pady=5)
        return btn

    def add_entry(self, width=40):
        entry = tk.Entry(self, bg="#111111", fg=TEXT_COLOR, insertbackground=TEXT_COLOR, width=width)
        entry.pack(pady=5)
        return entry

    def add_textbox(self, width=60, height=10):
        text_box = tk.Text(self, bg="#111111", fg=TEXT_COLOR, insertbackground=TEXT_COLOR,
                           width=width, height=height, wrap="word")
        text_box.pack(pady=5)
        return text_box
