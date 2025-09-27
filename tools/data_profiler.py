TAB_NAME = "Data Profiler"

import json
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

from base_tool import BaseToolFrame
from utils import get_save_path


class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        self.file_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Awaiting dataset…")

        header = tk.Label(self, text="📊 Data Profiler", font=("Segoe UI", 16, "bold"),
                          bg=self["bg"], fg="#E0E0E0")
        header.pack(pady=10)

        path_frame = tk.Frame(self, bg=self["bg"])
        path_frame.pack(pady=5, fill="x")

        tk.Entry(path_frame, textvariable=self.file_var, width=60, bg="#111111", fg="#E0E0E0",
                 insertbackground="#E0E0E0").pack(side="left", padx=5, expand=True, fill="x")
        browse_btn = tk.Button(path_frame, text="Browse", command=self.select_file)
        browse_btn.pack(side="left", padx=5)

        self.style_button(browse_btn)

        profile_btn = tk.Button(self, text="Profile Dataset", command=self.start_profile)
        profile_btn.pack(pady=10)
        self.style_button(profile_btn)

        self.status_label = tk.Label(self, textvariable=self.status_var, bg=self["bg"], fg="#9CDCFE")
        self.status_label.pack(pady=5)

        self.output_box = scrolledtext.ScrolledText(self, width=80, height=20, bg="#111111",
                                                   fg="#E0E0E0", insertbackground="#E0E0E0")
        self.output_box.pack(padx=10, pady=10, fill="both", expand=True)

    def style_button(self, button):
        button.configure(bg="#2D2D2D", fg="#E0E0E0", activebackground="#3C3C3C",
                         activeforeground="#FFFFFF", relief="flat", padx=12, pady=6)

    def select_file(self):
        file_path = filedialog.askopenfilename(
            title="Select dataset",
            filetypes=[
                ("Data files", "*.csv *.parquet *.json"),
                ("CSV", "*.csv"),
                ("Parquet", "*.parquet"),
                ("JSON", "*.json"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            self.file_var.set(file_path)
            self.status_var.set("Ready to profile")

    def start_profile(self):
        path = self.file_var.get().strip()
        if not path:
            messagebox.showerror("Data Profiler", "Please choose a dataset file.")
            return

        self.status_var.set("Profiling in progress…")
        self.output_box.delete("1.0", tk.END)
        thread = threading.Thread(target=self._profile_dataset, args=(path,), daemon=True)
        thread.start()

    def _profile_dataset(self, path):
        try:
            ext = path.lower()
            if ext.endswith('.csv'):
                df = pd.read_csv(path)
            elif ext.endswith('.parquet'):
                df = pd.read_parquet(path)
            elif ext.endswith('.json'):
                df = pd.read_json(path)
            else:
                raise ValueError("Unsupported file type. Use CSV, Parquet, or JSON.")

            overview = {
                "rows": int(df.shape[0]),
                "columns": int(df.shape[1]),
                "column_types": {col: str(dtype) for col, dtype in df.dtypes.items()},
                "missing_counts": df.isna().sum().to_dict(),
            }

            describe_df = df.describe(include='all').transpose()
            describe_path = get_save_path("Data_Profiler", "summary.csv")
            describe_df.to_csv(describe_path)

            overview_path = get_save_path("Data_Profiler", "overview.json")
            with open(overview_path, 'w', encoding='utf-8') as f:
                json.dump(overview, f, indent=2)

            numeric = df.select_dtypes(include=['number'])
            heatmap_path = None
            if not numeric.empty and numeric.shape[1] > 1:
                corr = numeric.corr(numeric_only=True)
                plt.figure(figsize=(8, 6))
                sns.heatmap(corr, annot=True, fmt=".2f", cmap="mako")
                plt.tight_layout()
                heatmap_path = get_save_path("Data_Profiler", "correlation.png")
                plt.savefig(heatmap_path)
                plt.close()

            text_lines = [
                f"Rows: {overview['rows']}",
                f"Columns: {overview['columns']}",
                "",
                "Column Types:",
            ]
            for col, dtype in overview['column_types'].items():
                text_lines.append(f"  • {col}: {dtype}")

            text_lines.append("\nMissing Values:")
            for col, cnt in overview['missing_counts'].items():
                text_lines.append(f"  • {col}: {cnt}")

            text_lines.append(f"\nDetailed stats saved to: {describe_path}")
            if heatmap_path:
                text_lines.append(f"Correlation heatmap saved to: {heatmap_path}")
            text_lines.append(f"Overview saved to: {overview_path}")

            self.after(0, lambda: self._display_success(text_lines))
        except Exception as exc:
            self.after(0, lambda: messagebox.showerror("Data Profiler", str(exc)))
            self.after(0, lambda: self.status_var.set("Profiling failed."))

    def _display_success(self, lines):
        self.status_var.set("Profiling complete ✔")
        self.output_box.insert(tk.END, "\n".join(lines))
        self.output_box.see(tk.END)
