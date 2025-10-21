TAB_NAME = "File Renamer"

import tkinter as tk
from tkinter import filedialog, messagebox
import os
from utils import ensure_results_subfolder, get_save_path
from base_tool import BaseToolFrame
from theme import style_button

class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        self.add_label("📂 Batch File Renamer", font=("Segoe UI", 12, "bold"))

        self.folder_path = tk.StringVar()

        # Folder selection
        row1 = tk.Frame(self, bg=self["bg"])
        row1.pack(pady=5)
        folder_entry = tk.Entry(row1, textvariable=self.folder_path, width=60, 
                               bg="#111111", fg="#FFFFFF", insertbackground="#FFFFFF")
        folder_entry.pack(side="left", padx=5)
        browse_btn = tk.Button(row1, text="Browse", command=self.select_folder)
        style_button(browse_btn)
        browse_btn.pack(side="left")

        # Rename options
        row2 = tk.Frame(self, bg=self["bg"])
        row2.pack(pady=5)
        tk.Label(row2, text="Prefix:", bg=self["bg"], fg="#FFFFFF").pack(side="left")
        self.prefix_entry = tk.Entry(row2, width=12, bg="#111111", fg="#FFFFFF", insertbackground="#FFFFFF")
        self.prefix_entry.pack(side="left", padx=5)
        tk.Label(row2, text="Suffix:", bg=self["bg"], fg="#FFFFFF").pack(side="left")
        self.suffix_entry = tk.Entry(row2, width=12, bg="#111111", fg="#FFFFFF", insertbackground="#FFFFFF")
        self.suffix_entry.pack(side="left", padx=5)

        row3 = tk.Frame(self, bg=self["bg"])
        row3.pack(pady=5)
        tk.Label(row3, text="Start Number:", bg=self["bg"], fg="#FFFFFF").pack(side="left")
        self.start_num_entry = tk.Entry(row3, width=8, bg="#111111", fg="#FFFFFF", insertbackground="#FFFFFF")
        self.start_num_entry.insert(0, "1")
        self.start_num_entry.pack(side="left", padx=5)

        # Action buttons
        self.add_button("Rename Files", self.rename_files)

        # Output log
        self.log = self.add_textbox(width=80, height=15)



    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_path.set(folder)

    def rename_files(self):
        folder = self.folder_path.get().strip()
        if not folder or not os.path.isdir(folder):
            messagebox.showerror("Error", "Please select a valid folder.")
            return

        prefix = self.prefix_entry.get().strip()
        suffix = self.suffix_entry.get().strip()
        try:
            start_num = int(self.start_num_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid start number.")
            return

        files = sorted([f for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))])
        if not files:
            messagebox.showerror("Error", "No files found in selected folder.")
            return

        self.log.delete("1.0", tk.END)
        renamed_files = []

        for i, filename in enumerate(files, start=start_num):
            name, ext = os.path.splitext(filename)
            new_name = f"{prefix}{i}{suffix}{ext}"
            old_path = os.path.join(folder, filename)
            new_path = os.path.join(folder, new_name)
            os.rename(old_path, new_path)
            log_line = f"{filename} → {new_name}\n"
            self.log.insert(tk.END, log_line)
            renamed_files.append(log_line.strip())

        # Save log
        log_path = get_save_path("File_Renamer", "rename_log.txt")
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("\n".join(renamed_files))

        messagebox.showinfo("Done", f"Renamed {len(files)} files.\nLog saved to:\n{log_path}")
