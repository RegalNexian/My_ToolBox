from base_tool import BaseToolFrame
from theme import style_button
from datetime import datetime
import qrcode
import pyzbar.pyzbar as pyzbar
import pyperclip
import re
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from utils import get_save_path, ensure_results_subfolder

TAB_NAME = "QR Tools"

class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        # --------- Generator ---------
        self.add_label("QR Code Generator", font=("Orbitron", 16, "bold"))

        self.entry = self.add_entry(50)
        self.add_button("Generate & Save", self.generate_qr)
        self.add_button("Open Output Folder", lambda: ensure_results_subfolder("QR_Code"))

        self.qr_label = tk.Label(self, bg=self["bg"])
        self.qr_label.pack(pady=8)

        # --------- Scanner ---------
        self.add_label("QR Code Scanner", font=("Orbitron", 16, "bold"))
        self.add_button("Select QR Image", self.scan_qr)

        self.result_text = self.add_textbox(80, 4)
        self.add_button("Copy to Clipboard", self.copy_result)

    def generate_qr(self):
        data = self.entry.get().strip()
        if not data:
            messagebox.showerror("Error", "Please enter something!")
            return

        # Add https if looks like a domain
        if re.match(r"^[\w.-]+\.[a-z]{2,}$", data) and not data.startswith(("http://", "https://")):
            data = "https://" + data

        img = qrcode.make(str(data))
        file_name = f"QR_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        img_path = get_save_path("QR_Code", file_name)
        img.save(img_path)

        thumb = img.resize((180, 180))
        img_tk = ImageTk.PhotoImage(thumb)
        self.qr_label.config(image=img_tk)
        self.qr_label.image = img_tk

        messagebox.showinfo("Saved", f"QR saved to:\n{img_path}")

    def scan_qr(self):
        file_path = filedialog.askopenfilename(
            title="Select QR Code Image",
            filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")]
        )
        if not file_path:
            return
        try:
            img = Image.open(file_path)
            decoded = pyzbar.decode(img)
            if not decoded:
                messagebox.showerror("Error", "No QR code found in the image.")
                return
            result = decoded[0].data.decode("utf-8")
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert(tk.END, result)
        except (OSError, ValueError) as e:
            messagebox.showerror("Error", f"Failed to read QR: {e}")

    def copy_result(self):
        txt = self.result_text.get("1.0", tk.END).strip()
        if not txt:
            messagebox.showerror("Error", "No result to copy.")
            return
        pyperclip.copy(txt)
        messagebox.showinfo("Copied", "Result copied to clipboard.")
