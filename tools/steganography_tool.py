TAB_NAME = "Steganography Tool"

import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
from utils import get_save_path

BG_COLOR = "#1E1E1E"
FG_COLOR = "#FFFFFF"
BTN_COLOR = "#333333"
BTN_HOVER = "#444444"

class ToolFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=BG_COLOR)

        tk.Label(self, text="🖼 Steganography Tool", font=("Segoe UI", 12, "bold"),
                 bg=BG_COLOR, fg=FG_COLOR).pack(pady=10)

        self.make_button(self, "Encode Message into Image", self.encode_ui).pack(pady=5)
        self.make_button(self, "Decode Message from Image", self.decode_ui).pack(pady=5)

    def make_button(self, parent, text, cmd):
        btn = tk.Button(parent, text=text, bg=BTN_COLOR, fg=FG_COLOR, relief="flat", command=cmd)
        btn.bind("<Enter>", lambda e: btn.config(bg=BTN_HOVER))
        btn.bind("<Leave>", lambda e: btn.config(bg=BTN_COLOR))
        return btn

    def encode_ui(self):
        file_path = filedialog.askopenfilename(filetypes=[("PNG Images", "*.png")])
        if not file_path:
            return

        message = tk.simpledialog.askstring("Message", "Enter the message to hide:")
        if not message:
            return

        img = Image.open(file_path).convert("RGB")  # Ensure RGB format
        encoded_img = img.copy()
        pixels = encoded_img.load()

        bin_message = ''.join(format(ord(c), '08b') for c in message) + '1111111111111110'
        data_index = 0

        for y in range(img.height):
            for x in range(img.width):
                if data_index < len(bin_message):
                    r, g, b = pixels[x, y]
                    r = (r & ~1) | int(bin_message[data_index])
                    pixels[x, y] = (r, g, b)
                    data_index += 1
                else:
                    break

        save_path = get_save_path("Steganography_Tool", "encoded.png")
        encoded_img.save(save_path)
        messagebox.showinfo("Success", f"Message encoded and saved to:\n{save_path}")

    def decode_ui(self):
        file_path = filedialog.askopenfilename(filetypes=[("PNG Images", "*.png")])
        if not file_path:
            return

        img = Image.open(file_path).convert("RGB")  # Ensure RGB format
        pixels = img.load()

        bin_data = ""
        for y in range(img.height):
            for x in range(img.width):
                r, g, b = pixels[x, y]
                bin_data += str(r & 1)

        chars = [bin_data[i:i+8] for i in range(0, len(bin_data), 8)]
        decoded_message = ""
        for c in chars:
            if c == '11111110':
                break
            decoded_message += chr(int(c, 2))

        save_path = get_save_path("Steganography_Tool", "decoded_message.txt")
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(decoded_message)

        messagebox.showinfo("Decoded", f"Message extracted:\n{decoded_message}\nSaved to:\n{save_path}")
