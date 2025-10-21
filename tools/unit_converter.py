TAB_NAME = "Unit Converter"

import tkinter as tk
from tkinter import messagebox
from base_tool import BaseToolFrame

CONVERSIONS = {
    "Length (m→km)": lambda x: x / 1000,
    "Length (km→m)": lambda x: x * 1000,
    "Weight (g→kg)": lambda x: x / 1000,
    "Weight (kg→g)": lambda x: x * 1000,
    "Temperature (°C→°F)": lambda x: (x * 9/5) + 32,
    "Temperature (°F→°C)": lambda x: (x - 32) * 5/9
}

class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        self.add_label("📊 Unit Converter", font=("Segoe UI", 12, "bold"))

        self.add_label("Enter value:")
        self.value_entry = self.add_entry()

        self.add_label("Select conversion:")
        self.conversion_var = tk.StringVar(value=list(CONVERSIONS.keys())[0])
        option_menu = tk.OptionMenu(self, self.conversion_var, *CONVERSIONS.keys())
        option_menu.pack(pady=5)

        self.add_button("Convert", self.convert)

        self.result_label = self.add_label("", font=("Segoe UI", 11))



    def convert(self):
        try:
            value = float(self.value_entry.get())
            result = CONVERSIONS[self.conversion_var.get()](value)
            self.result_label.config(text=f"Result: {result}")
        except ValueError:
            messagebox.showerror("Error", "Invalid input value.")
