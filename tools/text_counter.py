import tkinter as tk
from tkinter import filedialog, messagebox
from base_tool import BaseToolFrame
from theme import style_button, style_label, style_entry, style_textbox, BG_COLOR, PANEL_COLOR

TAB_NAME = "Text Counter"

class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        # ===== MAIN PANELS =====
        self.left_panel = tk.Frame(self, bg=PANEL_COLOR, width=350)
        self.left_panel.pack(side="left", fill="y", padx=5, pady=5)

        self.right_panel = tk.Frame(self, bg=BG_COLOR)
        self.right_panel.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        # ===== LEFT: INPUT =====
        style_label(tk.Label(self.left_panel, text="📝 Enter or Paste Text"))
        self.text_input = tk.Text(self.left_panel, height=10)
        style_textbox(self.text_input)
        self.text_input.pack(fill="both", expand=True, pady=5)

        load_btn = tk.Button(self.left_panel, text="Load from File", command=self.load_file)
        style_button(load_btn)
        load_btn.pack(pady=5, fill="x")

        count_btn = tk.Button(self.left_panel, text="Count Text Stats", command=self.count_text)
        style_button(count_btn)
        count_btn.pack(pady=5, fill="x")

        # ===== RIGHT: RESULTS =====
        style_label(tk.Label(self.right_panel, text="📊 Text Statistics"))
        self.results_text = tk.Text(self.right_panel, height=15)
        style_textbox(self.results_text)
        self.results_text.pack(fill="both", expand=True, pady=5)

    def load_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Text File",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if not file_path:
            return
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.text_input.delete("1.0", tk.END)
            self.text_input.insert(tk.END, content)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {e}")

    def count_text(self):
        text = self.text_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showerror("Error", "No text entered.")
            return

        word_count = len(text.split())
        char_count = len(text)
        line_count = text.count("\n") + 1

        self.results_text.delete("1.0", tk.END)
        self.results_text.insert(tk.END, f"Words: {word_count}\n")
        self.results_text.insert(tk.END, f"Characters: {char_count}\n")
        self.results_text.insert(tk.END, f"Lines: {line_count}\n")
