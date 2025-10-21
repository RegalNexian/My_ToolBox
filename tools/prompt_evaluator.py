TAB_NAME = "Prompt Evaluator"

import csv
import json
import threading
import tkinter as tk
from collections import Counter
from tkinter import filedialog, messagebox, scrolledtext

from utils import get_save_path
from base_tool import BaseToolFrame


def _tokenize(text):
    return [token for token in text.lower().split() if token]


def _overlap_metrics(reference, hypothesis):
    ref_tokens = Counter(_tokenize(reference))
    hyp_tokens = Counter(_tokenize(hypothesis))

    if not hyp_tokens:
        return 0.0, 0.0, 0.0

    intersection = ref_tokens & hyp_tokens
    overlap = sum(intersection.values())
    precision = overlap / max(1, sum(hyp_tokens.values()))
    recall = overlap / max(1, sum(ref_tokens.values()))
    if precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return precision, recall, f1


class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        self.dataset_path = tk.StringVar()
        self.status_var = tk.StringVar(value="Awaiting evaluation dataset…")

        heading = tk.Label(self, text="🧠 Prompt Evaluator", font=("Segoe UI", 16, "bold"),
                           bg="#0F1115", fg="#E6E6E6")
        heading.pack(pady=10)

        file_frame = tk.Frame(self, bg="#0F1115")
        file_frame.pack(fill="x", padx=10)

        tk.Entry(file_frame, textvariable=self.dataset_path, width=60,
                 bg="#111111", fg="#E6E6E6", insertbackground="#E6E6E6").pack(side="left", expand=True, fill="x", padx=5)
        load_btn = tk.Button(file_frame, text="Load CSV", command=self.load_dataset)
        load_btn.pack(side="left", padx=5)
        self._style_button(load_btn)

        self.metrics_text = scrolledtext.ScrolledText(self, width=80, height=18,
                                                      bg="#111111", fg="#E6E6E6", insertbackground="#E6E6E6")
        self.metrics_text.pack(padx=10, pady=10, fill="both", expand=True)

        evaluate_btn = tk.Button(self, text="Run Evaluation", command=self.run_evaluation)
        evaluate_btn.pack(pady=5)
        self._style_button(evaluate_btn)

        status_label = tk.Label(self, textvariable=self.status_var, bg="#0F1115", fg="#9CDCFE")
        status_label.pack(pady=2)

        info = (
            "CSV must include columns: prompt, response, reference. "
            "Optional columns retained in output. Metrics are lexical overlap (precision/recall/F1)."
        )
        tk.Label(self, text=info, wraplength=620, justify="left", bg="#0F1115", fg="#A0AAB4").pack(pady=(0, 10))

        self.dataset_cache = []

    def _style_button(self, button):
        button.configure(bg="#2D2D2D", fg="#E6E6E6", activebackground="#3C3C3C",
                         activeforeground="#FFFFFF", relief="flat", padx=12, pady=6)

    def load_dataset(self):
        path = filedialog.askopenfilename(
            title="Select evaluation CSV",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")]
        )
        if not path:
            return

        try:
            with open(path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                self.dataset_cache = list(reader)
            if not self.dataset_cache:
                raise ValueError("CSV contains no rows.")
            missing_cols = {"prompt", "response", "reference"} - set(self.dataset_cache[0].keys())
            if missing_cols:
                raise ValueError(f"Missing required columns: {', '.join(sorted(missing_cols))}")
        except Exception as exc:
            messagebox.showerror("Prompt Evaluator", f"Failed to load dataset: {exc}")
            self.dataset_cache = []
            return

        self.dataset_path.set(path)
        self.status_var.set(f"Loaded {len(self.dataset_cache)} rows. Ready to evaluate.")
        self.metrics_text.delete('1.0', tk.END)

    def run_evaluation(self):
        if not self.dataset_cache:
            messagebox.showinfo("Prompt Evaluator", "Load a dataset before running evaluation.")
            return

        self.status_var.set("Evaluating…")
        self.metrics_text.delete('1.0', tk.END)
        thread = threading.Thread(target=self._evaluate_rows, daemon=True)
        thread.start()

    def _evaluate_rows(self):
        try:
            results = []
            precision_scores = []
            recall_scores = []
            f1_scores = []

            for row in self.dataset_cache:
                precision, recall, f1 = _overlap_metrics(row.get('reference', ''), row.get('response', ''))
                precision_scores.append(precision)
                recall_scores.append(recall)
                f1_scores.append(f1)

                result_row = dict(row)
                result_row.update({
                    'precision': round(precision, 3),
                    'recall': round(recall, 3),
                    'f1': round(f1, 3),
                    'response_len': len(_tokenize(row.get('response', ''))),
                    'reference_len': len(_tokenize(row.get('reference', '')))
                })
                results.append(result_row)

            avg_precision = sum(precision_scores) / len(precision_scores)
            avg_recall = sum(recall_scores) / len(recall_scores)
            avg_f1 = sum(f1_scores) / len(f1_scores)

            summary = {
                'average_precision': round(avg_precision, 3),
                'average_recall': round(avg_recall, 3),
                'average_f1': round(avg_f1, 3),
                'rows': len(results)
            }

            csv_path = get_save_path("Prompt_Evaluator", "evaluation.csv")
            fieldnames = results[0].keys()
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)

            summary_path = get_save_path("Prompt_Evaluator", "summary.json")
            with open(summary_path, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2)

            text = (
                f"Evaluation complete.\n"
                f"Rows: {summary['rows']}\n"
                f"Average Precision: {summary['average_precision']}\n"
                f"Average Recall: {summary['average_recall']}\n"
                f"Average F1: {summary['average_f1']}\n\n"
                f"Detailed CSV saved to: {csv_path}\n"
                f"Summary JSON saved to: {summary_path}"
            )

            self.after(0, lambda: self._on_success(text))
        except Exception as exc:
            self.after(0, lambda: messagebox.showerror("Prompt Evaluator", str(exc)))
            self.after(0, lambda: self.status_var.set("Evaluation failed."))

    def _on_success(self, message):
        self.status_var.set("Evaluation complete ✔")
        self.metrics_text.insert(tk.END, message)
