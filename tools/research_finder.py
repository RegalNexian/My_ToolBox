import os
import csv
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import requests
import webbrowser
from base_tool import BaseToolFrame
from theme import style_button, style_label, style_entry, style_textbox, BG_COLOR, PANEL_COLOR
from utils import get_save_path, ensure_results_subfolder
from datetime import datetime
import xml.etree.ElementTree as ET

TAB_NAME = "Research Finder"

API_URL = "https://api.semanticscholar.org/graph/v1/paper/search"


class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)
        ensure_results_subfolder("Research_Finder")

        # ===== Left Controls =====
        self.left_panel = tk.Frame(self, bg=PANEL_COLOR, width=350)
        self.left_panel.pack(side="left", fill="y", padx=5, pady=5)

        # Topic
        style_label(tk.Label(self.left_panel, text="🔍 Research Topic"))
        self.query_entry = tk.Entry(self.left_panel)
        style_entry(self.query_entry)
        self.query_entry.insert(0, "Enter research topic (e.g. Graph Neural Networks)")
        self.query_entry.pack(fill="x", pady=5)

        # Max Results
        style_label(tk.Label(self.left_panel, text="📑 Max Results"))
        self.limit_var = tk.StringVar(value="25")
        limit_entry = tk.Entry(self.left_panel, textvariable=self.limit_var)
        style_entry(limit_entry)
        limit_entry.pack(fill="x", pady=5)

        # Filters
        style_label(tk.Label(self.left_panel, text="📅 Year (>=)"))
        self.year_var = tk.StringVar(value="")
        year_entry = tk.Entry(self.left_panel, textvariable=self.year_var)
        style_entry(year_entry)
        year_entry.pack(fill="x", pady=5)

        style_label(tk.Label(self.left_panel, text="👨‍🔬 Author Contains"))
        self.author_var = tk.StringVar(value="")
        author_entry = tk.Entry(self.left_panel, textvariable=self.author_var)
        style_entry(author_entry)
        author_entry.pack(fill="x", pady=5)

        # Sort
        style_label(tk.Label(self.left_panel, text="↕️ Sort By"))
        self.sort_var = tk.StringVar(value="year")
        sort_menu = ttk.Combobox(
            self.left_panel,
            textvariable=self.sort_var,
            values=["year", "citations"],
            state="readonly",
        )
        sort_menu.pack(fill="x", pady=5)

        # API Source
        style_label(tk.Label(self.left_panel, text="🌐 Source"))
        self.api_source = tk.StringVar(value="Semantic Scholar")
        source_menu = ttk.Combobox(
            self.left_panel,
            textvariable=self.api_source,
            values=["Semantic Scholar", "arXiv", "CrossRef", "PubMed"],
            state="readonly",
        )
        source_menu.pack(fill="x", pady=5)

        # Buttons
        search_btn = tk.Button(self.left_panel, text="Search Papers", command=self.search_papers)
        style_button(search_btn)
        search_btn.pack(pady=10, fill="x")

        bulk_btn = tk.Button(self.left_panel, text="📥 Bulk Download", command=self.bulk_download)
        style_button(bulk_btn)
        bulk_btn.pack(pady=2, fill="x")

        csv_btn = tk.Button(self.left_panel, text="📊 Export CSV", command=self.export_csv)
        style_button(csv_btn)
        csv_btn.pack(pady=2, fill="x")

        bookmark_btn = tk.Button(self.left_panel, text="🔖 View Bookmarks", command=self.view_bookmarks)
        style_button(bookmark_btn)
        bookmark_btn.pack(pady=2, fill="x")

        # Progress Bar
        self.progress = ttk.Progressbar(self.left_panel, mode="indeterminate")
        self.progress.pack(fill="x", pady=(2, 10))
        self.progress.pack_forget()

        # ===== Right Results =====
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
            lambda e: self.results_canvas.configure(scrollregion=self.results_canvas.bbox("all")),
        )
        self.results_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.results_canvas.configure(yscrollcommand=self.scrollbar.set)

        self.results_canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # State
        self.current_papers = []
        self.bookmarks = []

    # ------------------ API Fetchers ------------------
    def fetch_semantic_scholar(self, query, limit):
        params = {"query": query, "fields": "title,url,abstract,year,authors,citationCount,openAccessPdf", "limit": limit}
        r = requests.get(API_URL, params=params, timeout=10)
        r.raise_for_status()
        return r.json().get("data", [])

    def fetch_arxiv(self, query, limit):
        url = f"http://export.arxiv.org/api/query?search_query=all:{query}&start=0&max_results={limit}"
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        root = ET.fromstring(r.text)
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        papers = []
        for entry in root.findall("atom:entry", ns):
            papers.append({
                "title": entry.find("atom:title", ns).text,
                "url": entry.find("atom:id", ns).text,
                "abstract": entry.find("atom:summary", ns).text,
                "year": entry.find("atom:published", ns).text[:4],
                "authors": [{"name": a.text} for a in entry.findall("atom:author/atom:name", ns)],
                "citationCount": 0,
                "openAccessPdf": {"url": entry.find("atom:id", ns).text + ".pdf"}
            })
        return papers

    def fetch_crossref(self, query, limit):
        url = f"https://api.crossref.org/works?query={query}&rows={limit}"
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        items = r.json().get("message", {}).get("items", [])
        papers = []
        for it in items:
            papers.append({
                "title": it.get("title", ["Untitled"])[0],
                "url": it.get("URL"),
                "abstract": it.get("abstract", "No abstract"),
                "year": it.get("created", {}).get("date-parts", [[None]])[0][0],
                "authors": [{"name": a.get("given", "") + " " + a.get("family", "")} for a in it.get("author", [])],
                "citationCount": it.get("is-referenced-by-count", 0),
                "openAccessPdf": None
            })
        return papers

    def fetch_pubmed(self, query, limit):
        url = f"https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi"
        params = {"db": "pubmed", "term": query, "retmax": limit, "retmode": "json"}
        r = requests.get(url, params=params, timeout=10)
        r.raise_for_status()
        ids = r.json()["esearchresult"]["idlist"]
        papers = []
        for pmid in ids:
            papers.append({
                "title": f"PubMed Paper {pmid}",
                "url": f"https://pubmed.ncbi.nlm.nih.gov/{pmid}/",
                "abstract": "Abstract not available via free API.",
                "year": None,
                "authors": [],
                "citationCount": 0,
                "openAccessPdf": None
            })
        return papers

    # ------------------ Search ------------------
    def search_papers(self):
        query = self.query_entry.get().strip()
        if not query or query.lower().startswith("enter research"):
            messagebox.showerror("Error", "Please enter a research topic.")
            return

        try:
            limit = int(self.limit_var.get())
        except Exception:
            limit = 25

        for w in self.scrollable_frame.winfo_children():
            w.destroy()
        self.current_papers = []

        # progress bar
        self.progress.pack(fill="x", pady=(2, 10))
        self.progress.start(10)
        self.update_idletasks()

        try:
            src = self.api_source.get()
            if src == "Semantic Scholar":
                papers = self.fetch_semantic_scholar(query, limit)
            elif src == "arXiv":
                papers = self.fetch_arxiv(query, limit)
            elif src == "CrossRef":
                papers = self.fetch_crossref(query, limit)
            elif src == "PubMed":
                papers = self.fetch_pubmed(query, limit)
            else:
                papers = []

            # Filtering
            year_f = self.year_var.get().strip()
            author_f = self.author_var.get().strip().lower()
            filtered = []
            for p in papers:
                y = p.get("year")
                if year_f and y and str(y).isdigit() and int(y) < int(year_f):
                    continue
                if author_f:
                    authors = " ".join(a.get("name", "").lower() for a in p.get("authors", []))
                    if author_f not in authors:
                        continue
                filtered.append(p)

            # Sorting
            if self.sort_var.get() == "year":
                filtered.sort(key=lambda x: x.get("year") or 0, reverse=True)
            elif self.sort_var.get() == "citations":
                filtered.sort(key=lambda x: x.get("citationCount") or 0, reverse=True)

            self.current_papers = filtered
            if not filtered:
                tk.Label(self.scrollable_frame, text="⚠️ No papers found.", bg=BG_COLOR, fg="red").pack(pady=10)
                return

            for i, p in enumerate(filtered):
                self.render_paper(p, i)

        except Exception as e:
            messagebox.showerror("Error", f"Failed: {e}")
        finally:
            self.progress.stop()
            self.progress.pack_forget()

    # ------------------ UI for Paper ------------------
    def render_paper(self, paper, idx):
        frame = tk.Frame(self.scrollable_frame, bg=("#111111" if idx % 2 == 0 else "#1A1A1A"), pady=8, padx=6)
        frame.pack(fill="x", anchor="w", pady=2)

        title = paper.get("title", "Untitled Paper")
        url = paper.get("url", "#")
        abstract = paper.get("abstract", "No abstract.")
        pdf_link = paper.get("openAccessPdf", {}).get("url") if paper.get("openAccessPdf") else None

        # Title
        style_label(tk.Label(frame, text=f"📄 {title}"))

        # Collapsible abstract
        abs_box = tk.Text(frame, height=3, wrap="word")
        style_textbox(abs_box)
        abs_box.insert("1.0", abstract)
        abs_box.config(state="disabled")
        abs_box.pack(fill="x", pady=2)

        # Links
        link = tk.Label(frame, text=f"🌐 {url}", fg="cyan", bg=frame.cget("bg"), cursor="hand2")
        link.pack(anchor="w")
        link.bind("<Button-1>", lambda e: webbrowser.open(url))

        # Buttons
        btns = tk.Frame(frame, bg=frame.cget("bg"))
        btns.pack(fill="x", pady=2)
        if pdf_link:
            d_btn = tk.Button(btns, text="📥 PDF", command=lambda u=pdf_link: self.download_pdf(u))
            style_button(d_btn)
            d_btn.pack(side="left", padx=2)
        b_btn = tk.Button(btns, text="🔖 Bookmark", command=lambda p=paper: self.bookmark(p))
        style_button(b_btn)
        b_btn.pack(side="left", padx=2)

        tk.Label(frame, text="—" * 60, bg=frame.cget("bg"), fg="gray").pack(fill="x")

    # ------------------ Actions ------------------
    def download_pdf(self, pdf_url):
        filename = pdf_url.split("/")[-1] or "paper.pdf"
        save_path = get_save_path("Research_Finder", filename)
        if not messagebox.askyesno("Confirm", f"Download?\n{pdf_url}\n→ {save_path}"):
            return
        try:
            r = requests.get(pdf_url, stream=True, timeout=15)
            with open(save_path, "wb") as f:
                for chunk in r.iter_content(1024):
                    f.write(chunk)
            messagebox.showinfo("Done", f"Saved:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Download failed:\n{e}")

    def bulk_download(self):
        if not self.current_papers:
            messagebox.showerror("Error", "No results.")
            return
        for p in self.current_papers:
            if p.get("openAccessPdf"):
                url = p["openAccessPdf"].get("url")
                if url:
                    self.download_pdf(url)

    def export_csv(self):
        if not self.current_papers:
            messagebox.showerror("Error", "No results to export.")
            return
        file = filedialog.asksaveasfilename(defaultextension=".csv")
        if not file:
            return
        with open(file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Title", "URL", "Abstract", "Year", "Authors", "Citations"])
            for p in self.current_papers:
                writer.writerow([
                    p.get("title", ""),
                    p.get("url", ""),
                    p.get("abstract", ""),
                    p.get("year", ""),
                    "; ".join(a.get("name", "") for a in p.get("authors", [])),
                    p.get("citationCount", 0),
                ])
        messagebox.showinfo("Done", f"Exported to {file}")

    def bookmark(self, paper):
        self.bookmarks.append(paper)
        messagebox.showinfo("Bookmarked", paper.get("title", "Untitled"))

    def view_bookmarks(self):
        top = tk.Toplevel(self)
        top.title("Bookmarks")
        top.geometry("800x600")
        frame = tk.Frame(top, bg=BG_COLOR)
        frame.pack(fill="both", expand=True)
        for p in self.bookmarks:
            tk.Label(frame, text=p.get("title", "Untitled"), bg=BG_COLOR, fg="cyan").pack(anchor="w")


