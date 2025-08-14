TAB_NAME = "Text Counter"

import tkinter as tk

BG_COLOR = "#1E1E1E"
FG_COLOR = "#FFFFFF"
BTN_COLOR = "#333333"
BTN_HOVER = "#444444"

class ToolFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=BG_COLOR)

        tk.Label(self, text="📝 Text Counter", font=("Segoe UI", 12, "bold"),
                 bg=BG_COLOR, fg=FG_COLOR).pack(pady=10)

        self.text_entry = tk.Text(self, height=10, width=70, bg="#222222", fg=FG_COLOR, insertbackground=FG_COLOR)
        self.text_entry.pack(pady=5)

        self.make_button(self, "Count", self.count_text).pack(pady=5)

        self.result_label = tk.Label(self, text="", bg=BG_COLOR, fg=FG_COLOR, font=("Segoe UI", 11))
        self.result_label.pack(pady=5)

    def make_button(self, parent, text, cmd):
        btn = tk.Button(parent, text=text, bg=BTN_COLOR, fg=FG_COLOR, relief="flat", command=cmd)
        btn.bind("<Enter>", lambda e: btn.config(bg=BTN_HOVER))
        btn.bind("<Leave>", lambda e: btn.config(bg=BTN_COLOR))
        return btn

    def count_text(self):
        text = self.text_entry.get("1.0", tk.END).strip()
        words = len(text.split())
        chars = len(text)
        sentences = text.count(".")
        self.result_label.config(text=f"Words: {words} | Characters: {chars} | Sentences: {sentences}")
