# tools/disk_visualizer.py
"""
Disk Space Visualizer — a modular tool to analyze and visualize disk usage.

Features:
1) Scans any user-selected folder.
2) Displays an interactive treemap where area is proportional to file/folder size.
3) Click to drill-down into subdirectories.
4) Navigation buttons (Up, Home) to move through the folder hierarchy.
5) Status bar with live feedback on scanning progress.
6) Hover-to-see-details for full path and size information.
7) Background thread for scanning to keep the UI responsive.
"""

from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from dataclasses import dataclass
from functools import lru_cache
from tkinter import filedialog, ttk
from typing import List, Optional

# Optional dependencies (best-effort imports)
try:
    import matplotlib.pyplot as plt
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
except ImportError:
    plt = None # type: ignore
    Figure = None # type: ignore
    FigureCanvasTkAgg = None # type: ignore

try:
    import squarify # type: ignore
except ImportError:
    squarify = None

# Required helper modules from your project
from base_tool import BaseToolFrame
from theme import BG_COLOR, PANEL_COLOR, TEXT_COLOR, style_button, style_label

TAB_NAME = "Disk Space Visualizer"

# ========== Data classes ==========
@dataclass
class PathInfo:
    """A simple data class to hold information about a scanned path."""
    path: str
    size: int
    is_dir: bool


# ========== Utilities ==========
def format_bytes(size: int) -> str:
    """Converts a size in bytes to a human-readable string (KB, MB, GB)."""
    if size < 1024:
        return f"{size} B"
    size_float = float(size)
    for unit in ["", "K", "M", "G", "T", "P"]:
        if size_float < 1024:
            return f"{size_float:.2f} {unit}B"
        size_float /= 1024
    return f"{size_float:.2f} EB" # type: ignore

# Use a cache to speed up repeated size calculations, especially when navigating
@lru_cache(maxsize=1024)
def get_path_size(path: str) -> int:
    """Recursively calculates the size of a directory or file."""
    total_size = 0
    try:
        if os.path.isfile(path):
            return os.path.getsize(path)
        
        with os.scandir(path) as it:
            for entry in it:
                if entry.is_dir(follow_symlinks=False):
                    total_size += get_path_size(entry.path)
                else:
                    total_size += entry.stat(follow_symlinks=False).st_size
    except (PermissionError, FileNotFoundError):
        return 0  # Ignore files/folders we can't access
    return total_size


# ========== Scanner Worker (multi-threaded) ==========
def scan_directory_worker(path: str, out_q: queue.Queue, stop_event: threading.Event):
    """
    Scans the contents of a single directory level, calculates their total sizes,
    and puts the results into a queue. Runs in a separate thread.
    """
    results = []
    try:
        # scandir can be slow on huge directories, so we wrap it
        entries_to_process = list(os.scandir(path))
    except (PermissionError, FileNotFoundError) as e:
        out_q.put(("error", f"Cannot access '{path}': {e}"))
        return

    # Sort entries to process files first, then directories
    entries = sorted(entries_to_process, key=lambda e: e.is_dir())
    for entry in entries:
        if stop_event.is_set():
            out_q.put(("log", "Scan cancelled."))
            return
        
        out_q.put(("log", f"Calculating size of: {entry.name}"))
        size = get_path_size(entry.path)
        if size > 0:  # Only include items with a size
            results.append(PathInfo(path=entry.path, size=size, is_dir=entry.is_dir()))

    # Sort final results by size, descending
    results.sort(key=lambda item: item.size, reverse=True)
    out_q.put(("done", results))


# ========== UI ToolFrame (Tkinter) ==========
class ToolFrame(BaseToolFrame):
    """The main UI frame for the Disk Space Visualizer."""

    def __init__(self, master: tk.Misc):
        super().__init__(master)

        # Check for dependencies
        if any(lib is None for lib in [plt, Figure, FigureCanvasTkAgg, squarify]):
            style_label(tk.Label(self, text="Error: 'matplotlib' and 'squarify' libraries are required.\n"
                                            "Please run: pip install matplotlib squarify",
                                 font=("Segoe UI", 12), fg="red")).pack()
            return

        # Core state
        self.scan_thread: Optional[threading.Thread] = None
        self.out_q: queue.Queue[tuple[str, str | List[PathInfo]]] = queue.Queue() # type: ignore
        self.stop_event = threading.Event()
        self.current_path: Optional[str] = None
        self.path_history: List[str] = []
        self.scan_results: List[PathInfo] = []
        self.rects = None  # To store rectangle objects for interaction

        self._build_ui()
        self.after(100, self._pump_queue)

    def _build_ui(self):
        """Create all the UI widgets for the tool."""
        # --- Control Panel (Top) ---
        top_panel = tk.Frame(self, bg=PANEL_COLOR)
        top_panel.pack(side="top", fill="x", padx=6, pady=6)

        self.select_btn = tk.Button(top_panel, text="📁 Select Folder", command=self._select_folder)
        style_button(self.select_btn)
        self.select_btn.pack(side="left", padx=4, pady=4)
        
        self.home_btn = tk.Button(top_panel, text="🏠 Home", command=self._go_home, state="disabled")
        style_button(self.home_btn)
        self.home_btn.pack(side="left", padx=4, pady=4)

        self.up_btn = tk.Button(top_panel, text="⬆️ Up", command=self._go_up, state="disabled")
        style_button(self.up_btn)
        self.up_btn.pack(side="left", padx=4, pady=4)

        self.path_label = tk.Label(top_panel, text="Select a folder to begin.", bg=PANEL_COLOR, fg=TEXT_COLOR)
        self.path_label.pack(side="left", padx=10)

        # --- Matplotlib Canvas (Center) ---
        self.fig = Figure(figsize=(10, 8), dpi=100, facecolor=BG_COLOR)
        self.ax = self.fig.add_subplot(111, xticks=[], yticks=[])
        self.fig.subplots_adjust(top=1, bottom=0, right=1, left=0, hspace=0, wspace=0)

        self.canvas = FigureCanvasTkAgg(self.fig, self)
        self.canvas.get_tk_widget().pack(side="top", fill="both", expand=True)
        self.canvas.mpl_connect('motion_notify_event', self._on_hover)
        self.canvas.mpl_connect('button_press_event', self._on_click)

        # --- Status Bar (Bottom) ---
        self.status_label = tk.Label(self, text="", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(side="bottom", fill="x")

    def _select_folder(self):
        """Opens a dialog to choose a folder and starts the scan."""
        path = filedialog.askdirectory()
        if path:
            self._start_scan(path)
            self.path_history.clear() # Start fresh history
            self.home_btn.config(state="normal")

    def _start_scan(self, path: str):
        """Initiates a directory scan in a background thread."""
        if self.scan_thread and self.scan_thread.is_alive():
            self.stop_event.set() # Stop previous scan if running
            self.scan_thread.join(timeout=0.5)

        self.current_path = path
        self.path_label.config(text=f"Current: {path}")
        self.select_btn.config(state="disabled")
        self.status_label.config(text=f"Scanning '{os.path.basename(path)}'...")
        self.scan_results.clear()
        
        # Clear previous plot
        self.ax.clear()
        self.ax.set_xticks([])
        self.ax.set_yticks([])
        self.canvas.draw()

        self.stop_event.clear()
        self.scan_thread = threading.Thread(
            target=scan_directory_worker,
            args=(path, self.out_q, self.stop_event),
            daemon=True
        )
        self.scan_thread.start()

    def _pump_queue(self):
        """Processes messages from the scanner thread."""
        try:
            while not self.out_q.empty():
                msg_type, payload = self.out_q.get_nowait()
                if msg_type == "log":
                    self.status_label.config(text=payload)
                elif msg_type == "error":
                    self.status_label.config(text=f"Error: {payload}")
                    self.select_btn.config(state="normal")
                elif msg_type == "done":
                    self.scan_results = payload
                    self._draw_treemap()
                    self.status_label.config(text="Scan complete. Hover for details or click a directory to explore.")
                    self.select_btn.config(state="normal")
        finally:
            self.after(100, self._pump_queue)

    def _draw_treemap(self):
        """Renders the treemap using the scan results."""
        self.ax.clear()
        
        if not self.scan_results:
            self.ax.text(0.5, 0.5, "Empty or inaccessible folder.", 
                         ha='center', va='center', transform=self.ax.transAxes, color=TEXT_COLOR)
            self.canvas.draw()
            return

        sizes = [item.size for item in self.scan_results]
        labels = [f"{os.path.basename(item.path)}\n({format_bytes(item.size)})" for item in self.scan_results]
        
        # --- BUG FIX STARTS HERE ---
        # 1. Handle case where sizes might be empty or max is 0 to avoid ZeroDivisionError.
        max_size = max(sizes) if sizes else 1
        if max_size == 0:
            max_size = 1
        
        # 2. Correctly iterate over the 'sizes' list (which contains integers).
        #    The original code had `item.size` which is wrong. It should be just `s`.
        colors = plt.cm.get_cmap('viridis')([s / max_size for s in sizes])
        # --- BUG FIX ENDS HERE ---

        # squarify.plot returns the rectangle objects
        self.rects = squarify.plot(
            sizes=sizes, label=labels, ax=self.ax, alpha=0.8, color=colors,
            text_kwargs={'color': 'white', 'fontsize': 10}
        )
        self.ax.set_xticks([])
        self.ax.set_yticks([])
        if self.current_path:
             self.fig.suptitle(f"Disk Usage for: {self.current_path}", color=TEXT_COLOR)
        self.canvas.draw()

    def _on_hover(self, event):
        """Updates status bar with details of the item under the cursor."""
        if not self.rects or event.inaxes != self.ax:
            return

        for i, rect in enumerate(self.rects):
            if rect.contains(event)[0]:
                info = self.scan_results[i]
                self.status_label.config(text=f"{info.path} | Size: {format_bytes(info.size)}")
                break

    def _on_click(self, event):
        """Handles clicks on the treemap to drill-down into directories."""
        if not self.rects or event.inaxes != self.ax or self.current_path is None:
            return

        for i, rect in enumerate(self.rects):
            if rect.contains(event)[0]:
                info = self.scan_results[i]
                if info.is_dir:
                    self.path_history.append(self.current_path)
                    self._start_scan(info.path)
                    self.up_btn.config(state="normal")
                else:
                    self.status_label.config(text=f"Selected file: {info.path}")
                break

    def _go_up(self):
        """Navigates to the parent directory."""
        if self.path_history:
            path = self.path_history.pop()
            self._start_scan(path)
            if not self.path_history:
                self.up_btn.config(state="disabled")

    def _go_home(self):
        """Navigates back to the first folder that was scanned."""
        if self.path_history:
            home_path = self.path_history[0]
            self.path_history.clear()
            self._start_scan(home_path)
            self.up_btn.config(state="disabled")

    def stop(self):
        """Cleanly stops the background thread when the app/tab closes."""
        self.stop_event.set()
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=0.5)