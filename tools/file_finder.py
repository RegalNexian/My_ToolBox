import os, sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import tkinter as tk
from tkinter import messagebox
from base_tool import BaseToolFrame
import requests
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from theme import style_button, style_label, style_entry, BG_COLOR, PANEL_COLOR
from utils import get_save_path, ensure_results_subfolder
from ddgs import DDGS  # ✅ DuckDuckGo Search

TAB_NAME = "File Finder"

# File size categories (bytes)
SIZE_CATEGORIES = {
    "All": (0, float("inf")),
    "Small (<1MB)": (0, 1 * 1024 * 1024),
    "Medium (1–100MB)": (1 * 1024 * 1024, 100 * 1024 * 1024),
    "Large (100MB–1GB)": (100 * 1024 * 1024, 1024 * 1024 * 1024),
    "Huge (>1GB)": (1024 * 1024 * 1024, float("inf")),
}

FILE_TYPES = ["pdf", "mp4", "torrent", "txt", "mtx", "edgelist", "docx"]

class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        ensure_results_subfolder("File_Finder")

        # ===== Left Controls =====
        self.left_panel = tk.Frame(self, bg=PANEL_COLOR, width=350)
        self.left_panel.pack(side="left", fill="y", padx=5, pady=5)

        style_label(tk.Label(self.left_panel, text="🔍 Search Query"))
        self.query_entry = tk.Entry(self.left_panel)
        style_entry(self.query_entry)
        self.query_entry.pack(fill="x", pady=5)

        style_label(tk.Label(self.left_panel, text="📂 File Type"))
        self.filetype_var = tk.StringVar(value="pdf")
        self.filetype_menu = tk.OptionMenu(self.left_panel, self.filetype_var, *FILE_TYPES)
        self.filetype_menu.config(bg=PANEL_COLOR, fg="white", relief="flat", highlightthickness=0)
        self.filetype_menu.pack(fill="x", pady=5)

        style_label(tk.Label(self.left_panel, text="📏 File Size Category"))
        self.size_var = tk.StringVar(value="All")
        self.size_menu = tk.OptionMenu(self.left_panel, self.size_var, *SIZE_CATEGORIES.keys())
        self.size_menu.config(bg=PANEL_COLOR, fg="white", relief="flat", highlightthickness=0)
        self.size_menu.pack(fill="x", pady=5)

        self.skip_size_var = tk.BooleanVar(value=False)
        skip_size_check = tk.Checkbutton(
            self.left_panel, text="⚡ Skip Size Check (faster)",
            variable=self.skip_size_var, bg=PANEL_COLOR, fg="white", selectcolor=BG_COLOR
        )
        skip_size_check.pack(pady=5, anchor="w")

        search_btn = tk.Button(self.left_panel, text="Search Files", command=self.search_files)
        style_button(search_btn)
        search_btn.pack(pady=10, fill="x")

        # ===== Right Results Panel =====
        self.right_panel = tk.Frame(self, bg=BG_COLOR)
        self.right_panel.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        style_label(tk.Label(self.right_panel, text="📜 Search Results"))

        self.results_frame = tk.Frame(self.right_panel, bg=BG_COLOR)
        self.results_frame.pack(fill="both", expand=True)

        self.results_canvas = tk.Canvas(self.results_frame, bg=BG_COLOR, highlightthickness=0)
        self.scrollbar = tk.Scrollbar(self.results_frame, orient="vertical", command=self.results_canvas.yview)
        self.scrollable_frame = tk.Frame(self.results_canvas, bg=BG_COLOR)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.results_canvas.configure(scrollregion=self.results_canvas.bbox("all"))
        )
        self.results_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.results_canvas.configure(yscrollcommand=self.scrollbar.set)

        self.results_canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

    def search_files(self):
        query = self.query_entry.get().strip()
        filetype = self.filetype_var.get()
        size_category = self.size_var.get()

        if not query:
            messagebox.showerror("Error", "Please enter a search query.")
            return

        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        min_size, max_size = SIZE_CATEGORIES[size_category]
        results_found = 0

        urls = []
        with DDGS() as ddgs:
            for result in ddgs.text(f"{query} filetype:{filetype}", max_results=100):
                url = result.get("href")
                title = result.get("title", "No Title")

                if not url or not url.lower().endswith(f".{filetype}"):
                    continue
                urls.append((title, url))

        if not urls:
            tk.Label(self.scrollable_frame, text="⚠️ No matching files found.", bg=BG_COLOR, fg="red").pack(pady=10)
            return

        if self.skip_size_var.get():
            # Skip size check: instantly show results
            for title, url in urls:
                self.add_result(title, url, None)
                results_found += 1
        else:
            # Parallel size fetching
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(self.fetch_size, url): (title, url) for title, url in urls}
                for future in as_completed(futures):
                    title, url = futures[future]
                    size_mb = future.result()
                    if size_mb is not None:
                        size_bytes = size_mb * 1024 * 1024
                        if not (min_size <= size_bytes <= max_size):
                            continue
                    self.add_result(title, url, size_mb)
                    results_found += 1

        if results_found == 0:
            tk.Label(self.scrollable_frame, text="⚠️ No files matched your filters.", bg=BG_COLOR, fg="red").pack(pady=10)

    def fetch_size(self, url):
        """Fetch file size using HEAD request (returns MB, or None if unknown)."""
        try:
            head = requests.head(url, allow_redirects=True, timeout=5)
            if "Content-Length" in head.headers:
                size = int(head.headers["Content-Length"])
                if size > 0:
                    return size / (1024 * 1024)
        except Exception:
            try:
                # Fallback: try GET request just for headers
                with requests.get(url, stream=True, timeout=5) as r:
                    if "Content-Length" in r.headers:
                        size = int(r.headers["Content-Length"])
                        if size > 0:
                            return size / (1024 * 1024)
            except Exception:
                return None
        return None

    def add_result(self, title, url, size_mb):
        frame = tk.Frame(self.scrollable_frame, bg=BG_COLOR, pady=5)
        frame.pack(fill="x", anchor="w")

        short_title = (title[:60] + "...") if len(title) > 60 else title
        style_label(tk.Label(frame, text=f"🔹 {short_title}"))

        link = tk.Label(frame, text=f"🌐 {url}", fg="cyan", bg=BG_COLOR, cursor="hand2")
        link.pack(anchor="w")
        link.bind("<Button-1>", lambda e: webbrowser.open(url))

        if size_mb is None:
            size_text = " (Unknown Size)"
        else:
            size_text = f" ({size_mb:.2f} MB)"

        download_btn = tk.Button(frame, text=f"📥 Download{size_text}", command=lambda: self.download_file(url))
        style_button(download_btn)
        download_btn.pack(anchor="e", pady=2)

        tk.Label(frame, text="-" * 60, bg=BG_COLOR, fg="gray").pack(fill="x")

    def download_file(self, url):
        filename = url.split("/")[-1] or "downloaded_file"
        save_path = get_save_path("File_Finder", filename)

        if not messagebox.askyesno("Confirm Download", f"Download this file?\n\n{url}\n\n→ {save_path}"):
            return

        try:
            response = requests.get(url, stream=True, timeout=10)
            with open(save_path, "wb") as f:
                for chunk in response.iter_content(1024):
                    f.write(chunk)
            messagebox.showinfo("Download Complete", f"File saved to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to download file:\n{e}")
