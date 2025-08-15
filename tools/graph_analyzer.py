from base_tool import BaseToolFrame
from theme import style_button, style_label, style_entry, style_textbox, BG_COLOR, PANEL_COLOR
import tkinter as tk
from tkinter import filedialog, messagebox
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import scipy.io
import os

TAB_NAME = "Graph Analyzer"

class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        # ===== MAIN PANELS =====
        self.left_panel = tk.Frame(self, bg=PANEL_COLOR, width=300)
        self.left_panel.pack(side="left", fill="y", padx=5, pady=5)

        self.right_panel = tk.Frame(self, bg=BG_COLOR)
        self.right_panel.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        # ===== LEFT: CONTROLS =====
        style_label(tk.Label(self.left_panel, text="📂 Load Graph File"))
        load_btn = tk.Button(self.left_panel, text="Select File", command=self.load_graph_file)
        style_button(load_btn)
        load_btn.pack(pady=5)

        style_label(tk.Label(self.left_panel, text="📊 Graph Metrics"))
        metrics_btn = tk.Button(self.left_panel, text="Compute Metrics", command=self.compute_metrics)
        style_button(metrics_btn)
        metrics_btn.pack(pady=5)

        style_label(tk.Label(self.left_panel, text="🔍 Clustering"))
        cluster_btn = tk.Button(self.left_panel, text="Run Clustering", command=self.run_clustering)
        style_button(cluster_btn)
        cluster_btn.pack(pady=5)

        style_label(tk.Label(self.left_panel, text="📈 Visualize"))
        vis_btn = tk.Button(self.left_panel, text="Show Graph Plot", command=self.show_graph_plot)
        style_button(vis_btn)
        vis_btn.pack(pady=5)

        # ===== RIGHT: OUTPUT =====
        style_label(tk.Label(self.right_panel, text="📜 Results Log"))
        self.results_text = tk.Text(self.right_panel, height=15)
        style_textbox(self.results_text)
        self.results_text.pack(fill="x", pady=5)

        style_label(tk.Label(self.right_panel, text="📉 Graph Visualization"))
        self.plot_frame = tk.Frame(self.right_panel, bg=BG_COLOR)
        self.plot_frame.pack(fill="both", expand=True)

        self.G = None  # Loaded graph

    def load_graph_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Graph File",
            filetypes=[("Edge List", "*.txt;*.edgelist;*.mtx"), ("All files", "*.*")]
        )
        if not file_path:
            return
        try:
            ext = os.path.splitext(file_path)[1].lower()
            if ext in [".txt", ".edgelist"]:
                self.G = nx.read_edgelist(file_path)
            elif ext == ".mtx":
                sparse_matrix = scipy.io.mmread(file_path)
                self.G = nx.from_scipy_sparse_array(sparse_matrix)
            else:
                messagebox.showerror("Error", "Unsupported file format.")
                return
            self.results_text.insert(tk.END, f"Graph loaded: {file_path}\n")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load graph: {e}")

    def compute_metrics(self):
        if not self.G:
            messagebox.showerror("Error", "Load a graph first.")
            return
        try:
            num_nodes = self.G.number_of_nodes()
            num_edges = self.G.number_of_edges()
            density = nx.density(self.G)

            self.results_text.insert(tk.END, f"Nodes: {num_nodes}\n")
            self.results_text.insert(tk.END, f"Edges: {num_edges}\n")
            self.results_text.insert(tk.END, f"Density: {density:.4f}\n")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to compute metrics: {e}")

    def run_clustering(self):
        if not self.G:
            messagebox.showerror("Error", "Load a graph first.")
            return
        # Placeholder: Replace with actual clustering logic
        self.results_text.insert(tk.END, "Clustering results: [Coming soon]\n")

    def show_graph_plot(self):
        if not self.G:
            messagebox.showerror("Error", "Load a graph first.")
            return

        for widget in self.plot_frame.winfo_children():
            widget.destroy()

        fig, ax = plt.subplots(figsize=(5, 4))
        nx.draw(self.G, with_labels=True, node_color="cyan", edge_color="gray", ax=ax)
        canvas = FigureCanvasTkAgg(fig, master=self.plot_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)
