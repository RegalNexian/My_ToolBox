TAB_NAME = "QR Tools"
from datetime import datetime
import qrcode
import pyzbar.pyzbar as pyzbar
import pyperclip
import re
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from utils import get_save_path, ensure_results_subfolder

BG_COLOR = "#1E1E1E"
FG_COLOR = "#FFFFFF"
BTN_COLOR = "#333333"
BTN_HOVER = "#444444"

class ToolFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=BG_COLOR)

        # --------- Generator ---------
        gen = tk.LabelFrame(self, text="QR Code Generator", padx=10, pady=10,
                            bg=BG_COLOR, fg=FG_COLOR)
        gen.pack(fill="x", padx=10, pady=8)

        tk.Label(gen, text="Enter text/URL:", bg=BG_COLOR, fg=FG_COLOR).pack(anchor="w")
        self.entry = tk.Entry(gen, width=70, bg="#222222", fg=FG_COLOR, insertbackground=FG_COLOR)
        self.entry.pack(pady=6, fill="x")

        btns = tk.Frame(gen, bg=BG_COLOR)
        btns.pack(fill="x", pady=4)

        self.make_button(btns, "Generate & Save", self.generate_qr).pack(side="left")
        self.make_button(btns, "Open Output Folder", lambda: ensure_results_subfolder("QR_Code")).pack(side="left", padx=8)

        self.qr_label = tk.Label(gen, bg=BG_COLOR)
        self.qr_label.pack(pady=8)

        # --------- Scanner ---------
        scan = tk.LabelFrame(self, text="QR Code Scanner", padx=10, pady=10,
                             bg=BG_COLOR, fg=FG_COLOR)
        scan.pack(fill="x", padx=10, pady=8)

        self.make_button(scan, "Select QR Image", self.scan_qr).pack()
        self.result_text = tk.Text(scan, width=80, height=4, wrap="word",
                                   bg="#222222", fg=FG_COLOR, insertbackground=FG_COLOR)
        self.result_text.pack(pady=8)
        self.make_button(scan, "Copy to Clipboard", self.copy_result).pack()

    def make_button(self, parent, text, cmd):
        btn = tk.Button(parent, text=text, bg=BTN_COLOR, fg=FG_COLOR, relief="flat", command=cmd)
        btn.bind("<Enter>", lambda e: btn.config(bg=BTN_HOVER))
        btn.bind("<Leave>", lambda e: btn.config(bg=BTN_COLOR))
        return btn

    def generate_qr(self):
        data = self.entry.get().strip()
        if not data:
            messagebox.showerror("Error", "Please enter something!")
            return

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
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read QR: {e}")

    def copy_result(self):
        txt = self.result_text.get("1.0", tk.END).strip()
        if not txt:
            messagebox.showerror("Error", "No result to copy.")
            return
        pyperclip.copy(txt)
        messagebox.showinfo("Copied", "Result copied to clipboard.")
