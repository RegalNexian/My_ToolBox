TAB_NAME = "Graph Analyzer"

import tkinter as tk
from tkinter import filedialog, messagebox
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
from utils import get_save_path
import os

# Optional SciPy import for .mtx
try:
    from scipy.io import mmread
    import numpy as np
    SCIPY_OK = True
except (ImportError, ModuleNotFoundError):
    SCIPY_OK = False

BG_COLOR = "#1E1E1E"
FG_COLOR = "#FFFFFF"
BTN_COLOR = "#333333"
BTN_HOVER = "#444444"

class ToolFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=BG_COLOR)

        tk.Label(self, text="Graph Analyzer", font=("Segoe UI", 12, "bold"),
                 bg=BG_COLOR, fg=FG_COLOR).pack(pady=10)

        self.make_button(self, "Select Graph File (.edges / .mtx)", self.load_graph).pack(pady=6)

        self.out = tk.Text(self, width=90, height=16,
                           bg="#222222", fg=FG_COLOR, insertbackground=FG_COLOR)
        self.out.pack(padx=10, pady=10)

    def make_button(self, parent, text, cmd):
        btn = tk.Button(parent, text=text, bg=BTN_COLOR, fg=FG_COLOR,
                        relief="flat", command=cmd)
        btn.bind("<Enter>", lambda e: btn.config(bg=BTN_HOVER))
        btn.bind("<Leave>", lambda e: btn.config(bg=BTN_COLOR))
        return btn

    def load_graph(self):
        fp = filedialog.askopenfilename(filetypes=[("Graph files", "*.edges;*.mtx;*.txt")])
        if not fp:
            return
        try:
            G = self._read_graph(fp)
            if G.number_of_nodes() == 0:
                messagebox.showerror("Error", "Empty graph.")
                return

            degs = dict(G.degree())
            avg_deg = sum(degs.values()) / G.number_of_nodes()
            metrics = {
                "Nodes": G.number_of_nodes(),
                "Edges": G.number_of_edges(),
                "Density": nx.density(G),
                "Average Degree": round(avg_deg, 6),
                "Avg. Clustering Coef": round(nx.average_clustering(G), 6),
            }

            df = pd.DataFrame(list(metrics.items()), columns=["Metric", "Value"])
            metrics_path = get_save_path("Graph_Analysis", "metrics.csv")
            df.to_csv(metrics_path, index=False)

            plt.figure(figsize=(6, 6))
            pos = nx.spring_layout(G, seed=42)
            nx.draw(G, pos=pos, node_size=18, with_labels=False)
            plot_path = get_save_path("Graph_Analysis", "graph_plot.png")
            plt.tight_layout()
            plt.savefig(plot_path, dpi=160)
            plt.close()

            self.out.delete("1.0", tk.END)
            self.out.insert(tk.END, df.to_string(index=False))
            messagebox.showinfo("Graph Analyzer", f"Saved:\n{metrics_path}\n{plot_path}")

        except (FileNotFoundError, IOError, ValueError, RuntimeError, nx.NetworkXError) as e:
            messagebox.showerror("Error", str(e))

    def _read_graph(self, path: str):
        ext = os.path.splitext(path)[1].lower()
        if ext in {".edges", ".txt"}:
            return nx.read_edgelist(path)
        if ext == ".mtx":
            if not SCIPY_OK:
                raise RuntimeError("Reading .mtx requires SciPy. Install with: pip install scipy")
            mtx = mmread(path)
            # Only sparse matrices have tocoo()
            if hasattr(mtx, "tocoo"):
                coo = mtx.tocoo()
                rows, cols = coo.row, coo.col
            else:
                # Assume dense ndarray
                rows, cols = np.where(mtx)
            G: nx.Graph = nx.Graph()
            for u, v in zip(rows, cols):
                if u != v:
                    G.add_edge(int(u), int(v))
            return G
        raise ValueError("Unsupported file format.")
