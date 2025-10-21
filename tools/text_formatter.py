TAB_NAME = "Text Formatter"

import tkinter as tk
from tkinter import messagebox
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from utils import get_save_path
from base_tool import BaseToolFrame
from theme import style_button

class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        self.add_label("Text Formatter (Plain → PDF / Markdown)", font=("Segoe UI", 12, "bold"))
        self.text = self.add_textbox(width=100, height=24)

        btns = tk.Frame(self, bg=self["bg"])
        btns.pack(pady=4)
        pdf_btn = tk.Button(btns, text="Save as PDF", command=self.save_pdf)
        style_button(pdf_btn)
        pdf_btn.pack(side="left", padx=6)
        md_btn = tk.Button(btns, text="Save as Markdown", command=self.save_md)
        style_button(md_btn)
        md_btn.pack(side="left", padx=6)



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
