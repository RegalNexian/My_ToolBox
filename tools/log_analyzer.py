import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from base_tool import BaseToolFrame
from theme import style_button, style_label, style_entry, style_textbox, BG_COLOR, PANEL_COLOR
import re
from collections import Counter
from datetime import datetime

TAB_NAME = "Log Analyzer"

class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        # ===== MAIN PANELS =====
        self.left_panel = tk.Frame(self, bg=PANEL_COLOR, width=400)
        self.left_panel.pack(side="left", fill="y", padx=5, pady=5)

        self.right_panel = tk.Frame(self, bg=BG_COLOR)
        self.right_panel.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        # ===== LEFT: INPUT & CONTROLS =====
        style_label(tk.Label(self.left_panel, text="📊 Log Analyzer"))
        
        # File selection
        file_frame = tk.Frame(self.left_panel, bg=PANEL_COLOR)
        file_frame.pack(fill="x", pady=5)
        
        load_btn = tk.Button(file_frame, text="Load Log File", command=self.load_log_file)
        style_button(load_btn)
        load_btn.pack(fill="x", pady=2)

        self.file_label = tk.Label(self.left_panel, text="No file loaded", 
                                 bg=PANEL_COLOR, fg="#00ff00", font=("Consolas", 9))
        self.file_label.pack(pady=2)

        # Analysis options
        style_label(tk.Label(self.left_panel, text="Analysis Options:"))
        
        self.analyze_errors = tk.BooleanVar(value=True)
        tk.Checkbutton(self.left_panel, text="Error Analysis", variable=self.analyze_errors,
                      bg=PANEL_COLOR, fg="#00ff00", selectcolor="#111111").pack(anchor="w")
        
        self.analyze_ips = tk.BooleanVar(value=True)
        tk.Checkbutton(self.left_panel, text="IP Address Analysis", variable=self.analyze_ips,
                      bg=PANEL_COLOR, fg="#00ff00", selectcolor="#111111").pack(anchor="w")
        
        self.analyze_timestamps = tk.BooleanVar(value=True)
        tk.Checkbutton(self.left_panel, text="Timestamp Analysis", variable=self.analyze_timestamps,
                      bg=PANEL_COLOR, fg="#00ff00", selectcolor="#111111").pack(anchor="w")
        
        self.analyze_status_codes = tk.BooleanVar(value=True)
        tk.Checkbutton(self.left_panel, text="HTTP Status Codes", variable=self.analyze_status_codes,
                      bg=PANEL_COLOR, fg="#00ff00", selectcolor="#111111").pack(anchor="w")

        # Custom pattern search
        style_label(tk.Label(self.left_panel, text="Custom Pattern (Regex):"))
        self.pattern_entry = tk.Entry(self.left_panel, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.pattern_entry.pack(fill="x", pady=2)
        self.pattern_entry.insert(0, r"ERROR|WARN|CRITICAL")

        # Filter options
        style_label(tk.Label(self.left_panel, text="Filter by Level:"))
        self.level_var = tk.StringVar(value="ALL")
        level_combo = ttk.Combobox(self.left_panel, textvariable=self.level_var,
                                 values=["ALL", "ERROR", "WARN", "INFO", "DEBUG"])
        level_combo.pack(fill="x", pady=2)

        # Analyze button
        analyze_btn = tk.Button(self.left_panel, text="Analyze Logs", command=self.analyze_logs)
        style_button(analyze_btn)
        analyze_btn.pack(pady=10, fill="x")

        # Export button
        export_btn = tk.Button(self.left_panel, text="Export Report", command=self.export_report)
        style_button(export_btn)
        export_btn.pack(pady=2, fill="x")

        # ===== RIGHT: RESULTS =====
        style_label(tk.Label(self.right_panel, text="📈 Analysis Results"))
        
        self.results_text = tk.Text(self.right_panel, height=25, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.results_text.pack(fill="both", expand=True, pady=5)

        self.log_content = ""

    def load_log_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[
                ("Log Files", "*.log"),
                ("Text Files", "*.txt"),
                ("All Files", "*.*")
            ]
        )
        if not file_path:
            return
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                self.log_content = f.read()
            
            filename = file_path.split("/")[-1] if "/" in file_path else file_path.split("\\")[-1]
            self.file_label.config(text=f"Loaded: {filename}")
            
            # Show basic file info
            lines = self.log_content.split('\n')
            self.results_text.delete("1.0", tk.END)
            self.results_text.insert(tk.END, f"File loaded: {filename}\n")
            self.results_text.insert(tk.END, f"Total lines: {len(lines)}\n")
            self.results_text.insert(tk.END, f"File size: {len(self.log_content)} characters\n\n")
            self.results_text.insert(tk.END, "Click 'Analyze Logs' to start analysis...")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {e}")

    def analyze_logs(self):
        if not self.log_content:
            messagebox.showerror("Error", "Please load a log file first")
            return

        self.results_text.delete("1.0", tk.END)
        self.results_text.insert(tk.END, "🔍 LOG ANALYSIS REPORT\n")
        self.results_text.insert(tk.END, "=" * 50 + "\n\n")

        lines = self.log_content.split('\n')
        
        # Filter by log level if specified
        level_filter = self.level_var.get()
        if level_filter != "ALL":
            lines = [line for line in lines if level_filter in line.upper()]

        # Basic statistics
        self.results_text.insert(tk.END, f"📊 BASIC STATISTICS\n")
        self.results_text.insert(tk.END, f"Total lines analyzed: {len(lines)}\n")
        self.results_text.insert(tk.END, f"Non-empty lines: {len([l for l in lines if l.strip()])}\n\n")

        # Error analysis
        if self.analyze_errors.get():
            self.analyze_error_patterns(lines)

        # IP address analysis
        if self.analyze_ips.get():
            self.analyze_ip_addresses(lines)

        # Timestamp analysis
        if self.analyze_timestamps.get():
            self.analyze_timestamps_func(lines)

        # HTTP status codes
        if self.analyze_status_codes.get():
            self.analyze_http_status_codes(lines)

        # Custom pattern search
        pattern = self.pattern_entry.get().strip()
        if pattern:
            self.search_custom_pattern(lines, pattern)

    def analyze_error_patterns(self, lines):
        self.results_text.insert(tk.END, "🚨 ERROR ANALYSIS\n")
        
        error_patterns = {
            'ERROR': r'ERROR|error',
            'WARNING': r'WARN|warning|Warning',
            'CRITICAL': r'CRITICAL|critical|FATAL|fatal',
            'EXCEPTION': r'Exception|exception|Error:|error:'
        }
        
        for pattern_name, pattern in error_patterns.items():
            matches = [line for line in lines if re.search(pattern, line)]
            self.results_text.insert(tk.END, f"{pattern_name}: {len(matches)} occurrences\n")
            
            if matches and len(matches) <= 5:  # Show first few examples
                self.results_text.insert(tk.END, "  Examples:\n")
                for match in matches[:3]:
                    self.results_text.insert(tk.END, f"    {match.strip()[:100]}...\n")
        
        self.results_text.insert(tk.END, "\n")

    def analyze_ip_addresses(self, lines):
        self.results_text.insert(tk.END, "🌐 IP ADDRESS ANALYSIS\n")
        
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        all_ips = []
        
        for line in lines:
            ips = re.findall(ip_pattern, line)
            all_ips.extend(ips)
        
        if all_ips:
            ip_counter = Counter(all_ips)
            self.results_text.insert(tk.END, f"Unique IP addresses: {len(ip_counter)}\n")
            self.results_text.insert(tk.END, f"Total IP occurrences: {len(all_ips)}\n")
            
            self.results_text.insert(tk.END, "Top 10 IP addresses:\n")
            for ip, count in ip_counter.most_common(10):
                self.results_text.insert(tk.END, f"  {ip}: {count} times\n")
        else:
            self.results_text.insert(tk.END, "No IP addresses found\n")
        
        self.results_text.insert(tk.END, "\n")

    def analyze_timestamps_func(self, lines):
        self.results_text.insert(tk.END, "⏰ TIMESTAMP ANALYSIS\n")
        
        # Common timestamp patterns
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',  # 2023-12-01 14:30:45
            r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}',  # 12/01/2023 14:30:45
            r'\w{3} \d{2} \d{2}:\d{2}:\d{2}',        # Dec 01 14:30:45
        ]
        
        timestamps = []
        for line in lines:
            for pattern in timestamp_patterns:
                matches = re.findall(pattern, line)
                timestamps.extend(matches)
        
        if timestamps:
            self.results_text.insert(tk.END, f"Timestamps found: {len(timestamps)}\n")
            self.results_text.insert(tk.END, f"First timestamp: {timestamps[0]}\n")
            self.results_text.insert(tk.END, f"Last timestamp: {timestamps[-1]}\n")
            
            # Analyze time distribution by hour
            hours = []
            for ts in timestamps:
                hour_match = re.search(r'(\d{2}):\d{2}:\d{2}', ts)
                if hour_match:
                    hours.append(int(hour_match.group(1)))
            
            if hours:
                hour_counter = Counter(hours)
                self.results_text.insert(tk.END, "Activity by hour:\n")
                for hour in sorted(hour_counter.keys()):
                    self.results_text.insert(tk.END, f"  {hour:02d}:xx - {hour_counter[hour]} entries\n")
        else:
            self.results_text.insert(tk.END, "No timestamps found\n")
        
        self.results_text.insert(tk.END, "\n")

    def analyze_http_status_codes(self, lines):
        self.results_text.insert(tk.END, "🌍 HTTP STATUS CODE ANALYSIS\n")
        
        status_pattern = r'\b[1-5]\d{2}\b'  # HTTP status codes (100-599)
        status_codes = []
        
        for line in lines:
            codes = re.findall(status_pattern, line)
            status_codes.extend(codes)
        
        if status_codes:
            code_counter = Counter(status_codes)
            self.results_text.insert(tk.END, f"Total HTTP requests: {len(status_codes)}\n")
            
            # Categorize status codes
            success = sum(count for code, count in code_counter.items() if code.startswith('2'))
            client_errors = sum(count for code, count in code_counter.items() if code.startswith('4'))
            server_errors = sum(count for code, count in code_counter.items() if code.startswith('5'))
            
            self.results_text.insert(tk.END, f"Success (2xx): {success}\n")
            self.results_text.insert(tk.END, f"Client errors (4xx): {client_errors}\n")
            self.results_text.insert(tk.END, f"Server errors (5xx): {server_errors}\n")
            
            self.results_text.insert(tk.END, "Status code breakdown:\n")
            for code, count in code_counter.most_common(10):
                self.results_text.insert(tk.END, f"  {code}: {count} times\n")
        else:
            self.results_text.insert(tk.END, "No HTTP status codes found\n")
        
        self.results_text.insert(tk.END, "\n")

    def search_custom_pattern(self, lines, pattern):
        self.results_text.insert(tk.END, f"🔍 CUSTOM PATTERN SEARCH: {pattern}\n")
        
        try:
            matches = []
            for i, line in enumerate(lines):
                if re.search(pattern, line, re.IGNORECASE):
                    matches.append((i + 1, line.strip()))
            
            self.results_text.insert(tk.END, f"Pattern matches: {len(matches)}\n")
            
            if matches:
                self.results_text.insert(tk.END, "Sample matches:\n")
                for line_num, line in matches[:10]:  # Show first 10 matches
                    self.results_text.insert(tk.END, f"  Line {line_num}: {line[:100]}...\n")
            
        except re.error as e:
            self.results_text.insert(tk.END, f"Invalid regex pattern: {e}\n")
        
        self.results_text.insert(tk.END, "\n")

    def export_report(self):
        content = self.results_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showerror("Error", "No analysis results to export")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Export Analysis Report",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Report exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {e}")