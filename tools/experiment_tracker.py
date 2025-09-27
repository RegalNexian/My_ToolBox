TAB_NAME = "Experiment Tracker Lite"

import json
import os
import tkinter as tk
from tkinter import messagebox, scrolledtext
from datetime import datetime

import yaml

from base_tool import BaseToolFrame
from utils import ensure_results_subfolder, get_save_path


class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        self.results_dir = ensure_results_subfolder("Experiment_Tracker")

        heading = tk.Label(self, text="🧪 Experiment Tracker", font=("Segoe UI", 16, "bold"),
                           bg=self["bg"], fg="#E6E6E6")
        heading.pack(pady=10)

        form = tk.Frame(self, bg=self["bg"])
        form.pack(fill="x", padx=10)

        tk.Label(form, text="Run Name", bg=self["bg"], fg="#E6E6E6").grid(row=0, column=0, sticky="w")
        self.run_entry = tk.Entry(form, width=40, bg="#111111", fg="#E6E6E6", insertbackground="#E6E6E6")
        self.run_entry.grid(row=0, column=1, sticky="we", pady=4, padx=6)

        tk.Label(form, text="Config (YAML)", bg=self["bg"], fg="#E6E6E6").grid(row=1, column=0, sticky="nw")
        self.config_box = scrolledtext.ScrolledText(form, width=50, height=8, bg="#111111",
                                                    fg="#E6E6E6", insertbackground="#E6E6E6")
        self.config_box.grid(row=1, column=1, sticky="we", pady=4, padx=6)

        tk.Label(form, text="Metrics (JSON)", bg=self["bg"], fg="#E6E6E6").grid(row=2, column=0, sticky="nw")
        self.metrics_box = scrolledtext.ScrolledText(form, width=50, height=6, bg="#111111",
                                                     fg="#E6E6E6", insertbackground="#E6E6E6")
        self.metrics_box.grid(row=2, column=1, sticky="we", pady=4, padx=6)

        btn_frame = tk.Frame(self, bg=self["bg"])
        btn_frame.pack(pady=10)

        save_btn = tk.Button(btn_frame, text="Save Run", command=self.save_run)
        save_btn.grid(row=0, column=0, padx=5)
        self.style_button(save_btn)

        refresh_btn = tk.Button(btn_frame, text="Refresh Runs", command=self.refresh_runs)
        refresh_btn.grid(row=0, column=1, padx=5)
        self.style_button(refresh_btn)

        compare_btn = tk.Button(btn_frame, text="Compare Selected", command=self.compare_runs)
        compare_btn.grid(row=0, column=2, padx=5)
        self.style_button(compare_btn)

        list_frame = tk.Frame(self, bg=self["bg"])
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.run_list = tk.Listbox(list_frame, width=40, height=12, bg="#111111", fg="#E6E6E6")
        self.run_list.pack(side="left", fill="both", expand=False)
        self.run_list.bind('<<ListboxSelect>>', self.load_run_details)

        self.detail_box = scrolledtext.ScrolledText(list_frame, width=60, height=12, bg="#111111",
                                                    fg="#E6E6E6", insertbackground="#E6E6E6")
        self.detail_box.pack(side="left", fill="both", expand=True, padx=(10, 0))

        self.refresh_runs()

    def style_button(self, button):
        button.configure(bg="#2D2D2D", fg="#E6E6E6", activebackground="#3C3C3C",
                         activeforeground="#FFFFFF", relief="flat", padx=12, pady=6)

    def save_run(self):
        name = self.run_entry.get().strip()
        config_text = self.config_box.get('1.0', tk.END).strip()
        metrics_text = self.metrics_box.get('1.0', tk.END).strip()

        if not name:
            messagebox.showerror("Experiment Tracker", "Run name is required.")
            return

        try:
            config_data = yaml.safe_load(config_text) if config_text else {}
            metrics_data = json.loads(metrics_text) if metrics_text else {}
        except Exception as exc:
            messagebox.showerror("Experiment Tracker", f"Failed to parse config/metrics: {exc}")
            return

        payload = {
            "run_name": name,
            "saved_at": datetime.now().isoformat(),
            "config": config_data,
            "metrics": metrics_data
        }

        safe_name = "".join(c for c in name if c.isalnum() or c in ('_', '-')) or "run"
        path = get_save_path("Experiment_Tracker", f"{safe_name}.json")

        with open(path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2)

        messagebox.showinfo("Experiment Tracker", f"Run saved to {path}")
        self.refresh_runs()

    def refresh_runs(self):
        self.run_list.delete(0, tk.END)
        files = sorted(
            (f for f in os.listdir(self.results_dir) if f.endswith('.json')),
            reverse=True
        )
        for filename in files:
            self.run_list.insert(tk.END, filename)
        self.detail_box.delete('1.0', tk.END)

    def load_run_details(self, _event=None):
        selection = self.run_list.curselection()
        if not selection:
            return
        filename = self.run_list.get(selection[0])
        path = os.path.join(self.results_dir, filename)
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            pretty = json.dumps(data, indent=2)
            self.detail_box.delete('1.0', tk.END)
            self.detail_box.insert(tk.END, pretty)
        except Exception as exc:
            messagebox.showerror("Experiment Tracker", f"Failed to read run: {exc}")

    def compare_runs(self):
        selections = self.run_list.curselection()
        if len(selections) < 2:
            messagebox.showinfo("Experiment Tracker", "Select at least two runs to compare.")
            return

        runs = []
        for idx in selections:
            filename = self.run_list.get(idx)
            path = os.path.join(self.results_dir, filename)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    runs.append(json.load(f))
            except Exception as exc:
                messagebox.showerror("Experiment Tracker", f"Failed to load {filename}: {exc}")
                return

        comparison_lines = ["Run Comparison"]
        all_metric_keys = set()
        for run in runs:
            all_metric_keys.update(run.get('metrics', {}).keys())

        for run in runs:
            comparison_lines.append(f"\n▶ {run.get('run_name', 'Unnamed')} ({run.get('saved_at', '-')})")
            for key in sorted(all_metric_keys):
                value = run.get('metrics', {}).get(key, '—')
                comparison_lines.append(f"   - {key}: {value}")

        comparison_text = "\n".join(comparison_lines)
        compare_path = get_save_path("Experiment_Tracker", "comparison.txt")
        with open(compare_path, 'w', encoding='utf-8') as f:
            f.write(comparison_text)

        messagebox.showinfo("Experiment Tracker", f"Comparison saved to {compare_path}")
        self.detail_box.delete('1.0', tk.END)
        self.detail_box.insert(tk.END, comparison_text)
