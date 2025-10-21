TAB_NAME = "Color Picker"

import tkinter as tk
from tkinter.colorchooser import askcolor
from base_tool import BaseToolFrame
from theme import BG_COLOR, TEXT_COLOR, TITLE_FONT, LABEL_FONT

class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        self.add_label("🎨 Color Picker", font=TITLE_FONT)

        self.add_button("Pick a Color", self.pick_color)

        self.color_display = tk.Label(self, text="No color selected", bg=BG_COLOR, fg=TEXT_COLOR, font=LABEL_FONT)
        self.color_display.pack(pady=5)

    def pick_color(self):
        color = askcolor()[1]
        if color:
            self.color_display.config(text=f"Selected: {color}", bg=color, fg="black" if color != "#000000" else "white")
