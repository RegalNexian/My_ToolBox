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
from base_tool import BaseToolFrame
from theme import BG_COLOR, TEXT_COLOR, TITLE_FONT, style_button, style_entry

DATASET_EXTS = (
    ".csv", ".xlsx", ".json", ".zip", ".tsv", ".gz",
    ".mtx", ".edgelist", ".txt", ".txt.gz", ".edges", ".graphml", ".gml"
)

TEXT_FORMATS = (".csv", ".tsv", ".json", ".txt", ".edgelist", ".mtx", ".edges", ".graphml", ".gml")

class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        self.add_label("🌐 Dataset Finder", font=TITLE_FONT)

        self.query_entry = self.add_entry(width=50)

        self.add_button("Search Datasets", self.search_datasets)

        self.results_list = tk.Listbox(self, width=80, height=15, bg="#111111", fg=TEXT_COLOR)
        self.results_list.pack(pady=5)

        action_frame = tk.Frame(self, bg=BG_COLOR)
        action_frame.pack(pady=5)
        
        preview_btn = tk.Button(action_frame, text="Preview Selected", command=self.preview_selected)
        style_button(preview_btn)
        preview_btn.pack(side="left", padx=5)
        
        download_btn = tk.Button(action_frame, text="Download Selected", command=self.download_selected)
        style_button(download_btn)
        download_btn.pack(side="left", padx=5)

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
                                              bg="#111111", fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
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
