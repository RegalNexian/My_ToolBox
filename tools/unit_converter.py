TAB_NAME = "Unit Converter"

import tkinter as tk
from tkinter import messagebox

BG_COLOR = "#1E1E1E"
FG_COLOR = "#FFFFFF"
BTN_COLOR = "#333333"
BTN_HOVER = "#444444"

CONVERSIONS = {
    "Length (m→km)": lambda x: x / 1000,
    "Length (km→m)": lambda x: x * 1000,
    "Weight (g→kg)": lambda x: x / 1000,
    "Weight (kg→g)": lambda x: x * 1000,
    "Temperature (°C→°F)": lambda x: (x * 9/5) + 32,
    "Temperature (°F→°C)": lambda x: (x - 32) * 5/9
}

class ToolFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=BG_COLOR)

        tk.Label(self, text="📊 Unit Converter", font=("Segoe UI", 12, "bold"),
                 bg=BG_COLOR, fg=FG_COLOR).pack(pady=10)

        tk.Label(self, text="Enter value:", bg=BG_COLOR, fg=FG_COLOR).pack()
        self.value_entry = tk.Entry(self, bg="#222222", fg=FG_COLOR, insertbackground=FG_COLOR)
        self.value_entry.pack(pady=5)

        tk.Label(self, text="Select conversion:", bg=BG_COLOR, fg=FG_COLOR).pack()
        self.conversion_var = tk.StringVar(value=list(CONVERSIONS.keys())[0])
        tk.OptionMenu(self, self.conversion_var, *CONVERSIONS.keys()).pack(pady=5)

        self.make_button(self, "Convert", self.convert).pack(pady=10)

        self.result_label = tk.Label(self, text="", bg=BG_COLOR, fg=FG_COLOR, font=("Segoe UI", 11))
        self.result_label.pack(pady=5)

    def make_button(self, parent, text, cmd):
        btn = tk.Button(parent, text=text, bg=BTN_COLOR, fg=FG_COLOR, relief="flat", command=cmd)
        btn.bind("<Enter>", lambda e: btn.config(bg=BTN_HOVER))
        btn.bind("<Leave>", lambda e: btn.config(bg=BTN_COLOR))
        return btn

    def convert(self):
        try:
            value = float(self.value_entry.get())
            result = CONVERSIONS[self.conversion_var.get()](value)
            self.result_label.config(text=f"Result: {result}")
        except ValueError:
            messagebox.showerror("Error", "Invalid input value.")
