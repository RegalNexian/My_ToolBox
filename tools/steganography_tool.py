TAB_NAME = "Steganography Tool"

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image
from utils import get_save_path
from base_tool import BaseToolFrame
from theme import TITLE_FONT

class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        self.add_label("🖼 Steganography Tool", font=TITLE_FONT)

        self.add_button("Encode Message into Image", self.encode_ui)
        self.add_button("Decode Message from Image", self.decode_ui)

    def encode_ui(self):
        file_path = filedialog.askopenfilename(filetypes=[("PNG Images", "*.png")])
        if not file_path:
            return

        message = simpledialog.askstring("Message", "Enter the message to hide:")
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
