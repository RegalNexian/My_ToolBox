TAB_NAME = "File Renamer"

import tkinter as tk
from tkinter import filedialog, messagebox
import os
from utils import ensure_results_subfolder, get_save_path

BG_COLOR = "#1E1E1E"
FG_COLOR = "#FFFFFF"
BTN_COLOR = "#333333"
BTN_HOVER = "#444444"

class ToolFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=BG_COLOR)

        tk.Label(self, text="📂 Batch File Renamer", font=("Segoe UI", 12, "bold"),
                 bg=BG_COLOR, fg=FG_COLOR).pack(pady=10)

        self.folder_path = tk.StringVar()

        # Folder selection
        row1 = tk.Frame(self, bg=BG_COLOR)
        row1.pack(pady=5)
        tk.Entry(row1, textvariable=self.folder_path, width=60,
                 bg="#222222", fg=FG_COLOR, insertbackground=FG_COLOR).pack(side="left", padx=5)
        self.make_button(row1, "Browse", self.select_folder).pack(side="left")

        # Rename options
        row2 = tk.Frame(self, bg=BG_COLOR)
        row2.pack(pady=5)
        tk.Label(row2, text="Prefix:", bg=BG_COLOR, fg=FG_COLOR).pack(side="left")
        self.prefix_entry = tk.Entry(row2, width=12, bg="#222222", fg=FG_COLOR, insertbackground=FG_COLOR)
        self.prefix_entry.pack(side="left", padx=5)
        tk.Label(row2, text="Suffix:", bg=BG_COLOR, fg=FG_COLOR).pack(side="left")
        self.suffix_entry = tk.Entry(row2, width=12, bg="#222222", fg=FG_COLOR, insertbackground=FG_COLOR)
        self.suffix_entry.pack(side="left", padx=5)

        row3 = tk.Frame(self, bg=BG_COLOR)
        row3.pack(pady=5)
        tk.Label(row3, text="Start Number:", bg=BG_COLOR, fg=FG_COLOR).pack(side="left")
        self.start_num_entry = tk.Entry(row3, width=8, bg="#222222", fg=FG_COLOR, insertbackground=FG_COLOR)
        self.start_num_entry.insert(0, "1")
        self.start_num_entry.pack(side="left", padx=5)

        # Action buttons
        self.make_button(self, "Rename Files", self.rename_files).pack(pady=10)

        # Output log
        self.log = tk.Text(self, width=80, height=15, bg="#222222", fg=FG_COLOR, insertbackground=FG_COLOR)
        self.log.pack(pady=5)

    def make_button(self, parent, text, cmd):
        btn = tk.Button(parent, text=text, bg=BTN_COLOR, fg=FG_COLOR, relief="flat", command=cmd)
        btn.bind("<Enter>", lambda e: btn.config(bg=BTN_HOVER))
        btn.bind("<Leave>", lambda e: btn.config(bg=BTN_COLOR))
        return btn

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
