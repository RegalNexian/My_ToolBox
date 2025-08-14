TAB_NAME = "Text Formatter"

import tkinter as tk
from tkinter import messagebox
from reportlab.lib.pagesizes import letter # type: ignore
from reportlab.pdfgen import canvas # type: ignore
from utils import get_save_path

BG_COLOR = "#1E1E1E"
FG_COLOR = "#FFFFFF"
BTN_COLOR = "#333333"
BTN_HOVER = "#444444"

class ToolFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=BG_COLOR)

        tk.Label(self, text="Text Formatter (Plain → PDF / Markdown)", font=("Segoe UI", 12, "bold"),
                 bg=BG_COLOR, fg=FG_COLOR).pack(pady=10)
        self.text = tk.Text(self, width=100, height=24, wrap="word",
                            bg="#222222", fg=FG_COLOR, insertbackground=FG_COLOR)
        self.text.pack(padx=10, pady=8)

        btns = tk.Frame(self, bg=BG_COLOR)
        btns.pack(pady=4)
        self.make_button(btns, "Save as PDF", self.save_pdf).pack(side="left", padx=6)
        self.make_button(btns, "Save as Markdown", self.save_md).pack(side="left", padx=6)

    def make_button(self, parent, text, cmd):
        btn = tk.Button(parent, text=text, bg=BTN_COLOR, fg=FG_COLOR, relief="flat", command=cmd)
        btn.bind("<Enter>", lambda e: btn.config(bg=BTN_HOVER))
        btn.bind("<Leave>", lambda e: btn.config(bg=BTN_COLOR))
        return btn

    def save_pdf(self):
        content = self.text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showerror("Error", "No text entered.")
            return
        path = get_save_path("Text_Formatter", "output.pdf")
        c = canvas.Canvas(path, pagesize=letter)
        t = c.beginText(40, 750)
        for line in content.splitlines():
            t.textLine(line)
        c.drawText(t)
        c.showPage()
        c.save()
        messagebox.showinfo("Saved", f"PDF saved to:\n{path}")

    def save_md(self):
        content = self.text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showerror("Error", "No text entered.")
            return
        path = get_save_path("Text_Formatter", "output.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content + "\n")
        messagebox.showinfo("Saved", f"Markdown saved to:\n{path}")
