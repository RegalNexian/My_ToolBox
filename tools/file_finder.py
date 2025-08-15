TAB_NAME = "File Finder"

import tkinter as tk
from tkinter import messagebox, scrolledtext
from ddgs import DDGS
import requests
import os
from urllib.parse import urlparse
from utils import get_save_path

BG_COLOR = "#1E1E1E"
FG_COLOR = "#FFFFFF"
BTN_COLOR = "#333333"
BTN_HOVER = "#444444"
ENTRY_BG = "#222222"

# File type groups
GROUPS = {
    "Documents": [".pdf", ".epub", ".docx", ".pptx", ".xlsx"],
    "Audio": [".mp3", ".wav", ".flac", ".m4a"],
    "Video": [".mp4", ".mkv", ".avi", ".mov"],
    "Archives": [".zip", ".rar", ".7z"],
    "Torrents": [".torrent"],
    "Data": [".csv", ".json", ".tsv"]
}

TEXT_PREVIEWABLE = (".txt", ".csv", ".tsv", ".json", ".md")
HEAD_TIMEOUT = 10
GET_TIMEOUT = 30
MAX_RESULTS = 80

def human_size(num):
    try:
        num = float(num)
    except:
        return "Unknown"
    for unit in ["B","KB","MB","GB","TB"]:
        if num < 1024:
            return f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} PB"

class ToolFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=BG_COLOR)

        tk.Label(self, text="🔎 Universal File Hunter", font=("Segoe UI", 12, "bold"),
                 bg=BG_COLOR, fg=FG_COLOR).pack(pady=10)

        # Query row
        qrow = tk.Frame(self, bg=BG_COLOR)
        qrow.pack(pady=5)
        tk.Label(qrow, text="Search:", bg=BG_COLOR, fg=FG_COLOR).pack(side="left", padx=(0,6))
        self.query_entry = tk.Entry(qrow, width=60, bg=ENTRY_BG, fg=FG_COLOR, insertbackground=FG_COLOR)
        self.query_entry.pack(side="left", padx=(0,8))
        self.make_button(qrow, "Search", self.search).pack(side="left")

        # Filters
        filt = tk.LabelFrame(self, text=" File Types ", bg=BG_COLOR, fg=FG_COLOR)
        filt.pack(pady=8)

        self.vars = {}
        grid = tk.Frame(filt, bg=BG_COLOR)
        grid.pack(padx=6, pady=6)
        col = 0
        for group, exts in GROUPS.items():
            v = tk.BooleanVar(value=True if group in ("Documents","Audio","Video","Torrents") else False)
            self.vars[group] = v
            cb = tk.Checkbutton(grid, text=f"{group}", variable=v, bg=BG_COLOR, fg=FG_COLOR,
                                activebackground=BG_COLOR, activeforeground=FG_COLOR,
                                selectcolor=BG_COLOR, highlightthickness=0)
            cb.grid(row=0, column=col, padx=10, pady=2, sticky="w")
            col += 1

        crow = tk.Frame(filt, bg=BG_COLOR)
        crow.pack(pady=4)
        tk.Label(crow, text="Custom extensions (comma-separated, e.g. .txt,.srt):",
                 bg=BG_COLOR, fg=FG_COLOR).pack(side="left", padx=(0,6))
        self.custom_ext = tk.Entry(crow, width=30, bg=ENTRY_BG, fg=FG_COLOR, insertbackground=FG_COLOR)
        self.custom_ext.pack(side="left")

        # Results list
        self.results = []  # list of dicts: {title, href}
        self.listbox = tk.Listbox(self, width=100, height=16, bg=ENTRY_BG, fg=FG_COLOR)
        self.listbox.pack(pady=6)

        # Actions
        arow = tk.Frame(self, bg=BG_COLOR)
        arow.pack(pady=6)
        self.make_button(arow, "Details / Preview", self.details).pack(side="left", padx=5)
        self.make_button(arow, "Download Selected", self.download).pack(side="left", padx=5)

        # Info area
        self.info = scrolledtext.ScrolledText(self, wrap="word", width=100, height=10,
                                              bg=ENTRY_BG, fg=FG_COLOR, insertbackground=FG_COLOR)
        self.info.pack(padx=6, pady=(2,10))
        self.info.insert(tk.END, "Tip: refine with keywords like year, resolution, or author. "
                                 "Double-check legality before downloading.")
        self.info.config(state="disabled")

    def make_button(self, parent, text, cmd):
        btn = tk.Button(parent, text=text, bg=BTN_COLOR, fg=FG_COLOR, relief="flat", command=cmd)
        btn.bind("<Enter>", lambda e: btn.config(bg=BTN_HOVER))
        btn.bind("<Leave>", lambda e: btn.config(bg=BTN_COLOR))
        return btn

    def selected_exts(self):
        exts = []
        for group, v in self.vars.items():
            if v.get():
                exts.extend(GROUPS[group])
        extra = [e.strip() for e in self.custom_ext.get().split(",") if e.strip()]
        for e in extra:
            if not e.startswith("."):
                e = "." + e
            exts.append(e.lower())
        # Deduplicate
        return sorted(set([e.lower() for e in exts]))

    def search(self):
        query = self.query_entry.get().strip()
        if not query:
            messagebox.showerror("Error", "Please enter a search query.")
            return

        exts = self.selected_exts()
        # Build a gentle hint for filetypes; DuckDuckGo understands filetype:pdf
        # but we also filter client-side by extension
        hint = ""
        if exts:
            # keep short to avoid query bloat; include a few common ones
            common = [e.lstrip(".") for e in exts[:6]]
            hint = " " + " OR ".join([f"filetype:{c}" for c in common])

        self.listbox.delete(0, tk.END)
        self.results = []

        try:
            with DDGS() as ddgs:
                for res in ddgs.text(query + hint, max_results=MAX_RESULTS):
                    href = (res.get("href") or "").strip()
                    title = (res.get("title") or href).strip()
                    if not href:
                        continue
                    if self._matches_ext(href, exts):
                        self.results.append({"title": title, "href": href})
                        self.listbox.insert(tk.END, f"{title}  —  {href}")
        except Exception as e:
            messagebox.showerror("Search Error", f"Failed to search: {e}")
            return

        if not self.results:
            messagebox.showinfo("No Results", "No matching files found with the selected types.")

    def _matches_ext(self, url, exts):
        path = urlparse(url).path.lower()
        for e in exts:
            if path.endswith(e.lower()):
                return True
        # also accept obvious direct files even if extension absent
        return any(path.endswith(e) for e in sum(GROUPS.values(), []))

    def _head_info(self, url):
        try:
            r = requests.head(url, allow_redirects=True, timeout=HEAD_TIMEOUT)
            size = r.headers.get("Content-Length")
            ctype = r.headers.get("Content-Type")
            return human_size(size) if size else "Unknown", ctype or "Unknown"
        except Exception:
            return "Unknown", "Unknown"

    def details(self):
        idxs = self.listbox.curselection()
        if not idxs:
            messagebox.showerror("Error", "Select a result first.")
            return
        item = self.results[idxs[0]]
        url = item["href"]

        size, ctype = self._head_info(url)
        preview = self._preview_text_if_possible(url)

        self.info.config(state="normal")
        self.info.delete("1.0", tk.END)
        self.info.insert(tk.END, f"Title: {item['title']}\nURL: {url}\nSize: {size}\nType: {ctype}\n\n")
        if preview:
            self.info.insert(tk.END, "— Preview —\n")
            self.info.insert(tk.END, preview)
        else:
            self.info.insert(tk.END, "No preview available for this file type.")
        self.info.config(state="disabled")

    def _preview_text_if_possible(self, url):
        path = urlparse(url).path.lower()
        if not any(path.endswith(ext) for ext in TEXT_PREVIEWABLE + (".txt",)):
            return None
        try:
            r = requests.get(url, timeout=GET_TIMEOUT)
            if r.status_code != 200:
                return None
            text = r.text
            lines = text.splitlines()[:40]
            snippet = "\n".join(lines)
            return snippet[:4000]
        except Exception:
            return None

    def download(self):
        idxs = self.listbox.curselection()
        if not idxs:
            messagebox.showerror("Error", "Select a result to download.")
            return
        item = self.results[idxs[0]]
        url = item["href"]
        filename = os.path.basename(urlparse(url).path) or "downloaded_file"
        size, ctype = self._head_info(url)

        if not messagebox.askyesno(
            "Confirm Download",
            f"File: {filename}\nSize: {size}\nType: {ctype}\n\nDo you want to download this file?"
        ):
            return

        try:
            resp = requests.get(url, stream=True, timeout=GET_TIMEOUT)
            if resp.status_code != 200:
                messagebox.showerror("Error", f"Failed to download: HTTP {resp.status_code}")
                return
            save_path = get_save_path("File_Finder", filename)
            with open(save_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            messagebox.showinfo("Success", f"Downloaded to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Download failed: {e}")
