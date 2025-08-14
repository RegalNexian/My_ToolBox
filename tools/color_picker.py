TAB_NAME = "Color Picker"

import tkinter as tk
from tkinter.colorchooser import askcolor

BG_COLOR = "#1E1E1E"
FG_COLOR = "#FFFFFF"
BTN_COLOR = "#333333"
BTN_HOVER = "#444444"

class ToolFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=BG_COLOR)

        tk.Label(self, text="🎨 Color Picker", font=("Segoe UI", 12, "bold"),
                 bg=BG_COLOR, fg=FG_COLOR).pack(pady=10)

        self.make_button(self, "Pick a Color", self.pick_color).pack(pady=20)

        self.color_display = tk.Label(self, text="No color selected", bg=BG_COLOR, fg=FG_COLOR, font=("Segoe UI", 11))
        self.color_display.pack(pady=5)

    def make_button(self, parent, text, cmd):
        btn = tk.Button(parent, text=text, bg=BTN_COLOR, fg=FG_COLOR, relief="flat", command=cmd)
        btn.bind("<Enter>", lambda e: btn.config(bg=BTN_HOVER))
        btn.bind("<Leave>", lambda e: btn.config(bg=BTN_COLOR))
        return btn

    def pick_color(self):
        color = askcolor()[1]
        if color:
            self.color_display.config(text=f"Selected: {color}", bg=color, fg="black" if color != "#000000" else "white")
