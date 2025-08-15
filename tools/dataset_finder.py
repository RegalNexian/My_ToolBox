TAB_NAME = "Dataset Finder"

import tkinter as tk
from tkinter import messagebox, scrolledtext
from utils import get_save_path
from ddgs import DDGS  # Updated import
import requests
import os
import csv
import json
from io import StringIO
import gzip

BG_COLOR = "#1E1E1E"
FG_COLOR = "#FFFFFF"
BTN_COLOR = "#333333"
BTN_HOVER = "#444444"

DATASET_EXTS = (
    ".csv", ".xlsx", ".json", ".zip", ".tsv", ".gz",
    ".mtx", ".edgelist", ".txt", ".txt.gz", ".edges", ".graphml", ".gml"
)

TEXT_FORMATS = (".csv", ".tsv", ".json", ".txt", ".edgelist", ".mtx", ".edges", ".graphml", ".gml")

class ToolFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=BG_COLOR)

        tk.Label(self, text="🌐 Dataset Finder", font=("Segoe UI", 12, "bold"),
                 bg=BG_COLOR, fg=FG_COLOR).pack(pady=10)

        self.query_entry = tk.Entry(self, width=50, bg="#222222", fg=FG_COLOR, insertbackground=FG_COLOR)
        self.query_entry.pack(pady=5)

        self.make_button(self, "Search Datasets", self.search_datasets).pack(pady=5)

        self.results_list = tk.Listbox(self, width=80, height=15, bg="#222222", fg=FG_COLOR)
        self.results_list.pack(pady=5)

        action_frame = tk.Frame(self, bg=BG_COLOR)
        action_frame.pack(pady=5)
        self.make_button(action_frame, "Preview Selected", self.preview_selected).pack(side="left", padx=5)
        self.make_button(action_frame, "Download Selected", self.download_selected).pack(side="left", padx=5)

    def make_button(self, parent, text, cmd):
        btn = tk.Button(parent, text=text, bg=BTN_COLOR, fg=FG_COLOR, relief="flat", command=cmd)
        btn.bind("<Enter>", lambda e: btn.config(bg=BTN_HOVER))
        btn.bind("<Leave>", lambda e: btn.config(bg=BTN_COLOR))
        return btn

    def search_datasets(self):
        query = self.query_entry.get().strip()
        if not query:
            messagebox.showerror("Error", "Please enter a search query.")
            return

        self.results_list.delete(0, tk.END)
        with DDGS() as ddgs:
            results = ddgs.text(query + " dataset", max_results=50)
            for res in results:
                url = res.get("href", "")
                if url.lower().endswith(DATASET_EXTS) or "dataset" in url.lower():
                    self.results_list.insert(tk.END, url)

        if self.results_list.size() == 0:
            messagebox.showinfo("No Results", "No dataset links found.")

    def preview_selected(self):
        selection = self.results_list.curselection()
        if not selection:
            messagebox.showerror("Error", "Please select a dataset link.")
            return

        url = self.results_list.get(selection[0])
        try:
            response = requests.get(url, timeout=30)
            if response.status_code != 200:
                messagebox.showerror("Error", f"Failed to fetch: HTTP {response.status_code}")
                return

            ext = os.path.splitext(url.lower())[1]
            content = None

            if ext == ".gz" or ext.endswith(".txt.gz"):
                try:
                    content = gzip.decompress(response.content).decode("utf-8", errors="ignore")
                except:
                    content = None

            elif ext in TEXT_FORMATS:
                text_data = response.text
                if ext in (".csv", ".tsv"):
                    delimiter = "," if ext == ".csv" else "\t"
                    csv_data = csv.reader(StringIO(text_data), delimiter=delimiter)
                    rows = []
                    for i, row in enumerate(csv_data):
                        rows.append(", ".join(row))
                        if i >= 20:
                            break
                    content = "\n".join(rows)

                elif ext == ".json":
                    try:
                        data = json.loads(text_data)
                        content = json.dumps(data, indent=2)[:2000]
                    except:
                        content = text_data[:2000]

                else:
                    content = "\n".join(text_data.splitlines()[:20])

            else:
                content = "Preview not available for this file type."

            self.show_preview_window(url, content or "No preview available.")

        except Exception as e:
            messagebox.showerror("Error", f"Preview failed: {e}")

    def show_preview_window(self, title, content):
        preview_win = tk.Toplevel(self)
        preview_win.title(f"Preview - {title}")
        preview_win.configure(bg=BG_COLOR)
        text_area = scrolledtext.ScrolledText(preview_win, wrap="word", width=100, height=30,
                                              bg="#222222", fg=FG_COLOR, insertbackground=FG_COLOR)
        text_area.insert(tk.END, content)
        text_area.config(state="disabled")
        text_area.pack(padx=10, pady=10)

    def download_selected(self):
        selection = self.results_list.curselection()
        if not selection:
            messagebox.showerror("Error", "Please select a dataset link.")
            return

        url = self.results_list.get(selection[0])
        try:
            response = requests.get(url, stream=True, timeout=30)
            if response.status_code == 200:
                filename = os.path.basename(url.split("?")[0])
                save_path = get_save_path("Dataset_Finder", filename)
                with open(save_path, "wb") as f:
                    f.write(response.content)
                messagebox.showinfo("Success", f"Downloaded to:\n{save_path}")
            else:
                messagebox.showerror("Error", f"Failed to download: HTTP {response.status_code}")
        except Exception as e:
            messagebox.showerror("Error", f"Download failed: {e}")
