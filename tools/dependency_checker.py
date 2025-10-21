import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from base_tool import BaseToolFrame
from theme import style_button, style_label, style_entry, style_textbox, BG_COLOR, PANEL_COLOR
import json
import re
import subprocess
import os

TAB_NAME = "Dependency Checker"

class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        # ===== MAIN PANELS =====
        self.left_panel = tk.Frame(self, bg=PANEL_COLOR, width=400)
        self.left_panel.pack(side="left", fill="y", padx=5, pady=5)

        self.right_panel = tk.Frame(self, bg=BG_COLOR)
        self.right_panel.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        # ===== LEFT: PROJECT SELECTION =====
        style_label(tk.Label(self.left_panel, text="📦 Dependency Checker"))
        
        # Project type selection
        type_frame = tk.Frame(self.left_panel, bg=PANEL_COLOR)
        type_frame.pack(fill="x", pady=5)
        
        style_label(tk.Label(type_frame, text="Project Type:"))
        self.project_type = tk.StringVar(value="python")
        type_combo = ttk.Combobox(type_frame, textvariable=self.project_type,
                                values=["python", "nodejs", "requirements.txt", "package.json"])
        type_combo.pack(fill="x", pady=2)

        # File selection
        file_frame = tk.Frame(self.left_panel, bg=PANEL_COLOR)
        file_frame.pack(fill="x", pady=5)
        
        select_btn = tk.Button(file_frame, text="Select Dependency File", command=self.select_file)
        style_button(select_btn)
        select_btn.pack(fill="x", pady=2)

        self.file_label = tk.Label(self.left_panel, text="No file selected", 
                                 bg=PANEL_COLOR, fg="#00ff00", font=("Consolas", 9))
        self.file_label.pack(pady=2)

        # Directory selection for project scanning
        dir_frame = tk.Frame(self.left_panel, bg=PANEL_COLOR)
        dir_frame.pack(fill="x", pady=5)
        
        scan_btn = tk.Button(dir_frame, text="Scan Project Directory", command=self.scan_directory)
        style_button(scan_btn)
        scan_btn.pack(fill="x", pady=2)

        # Analysis options
        style_label(tk.Label(self.left_panel, text="Analysis Options:"))
        
        self.check_outdated = tk.BooleanVar(value=True)
        tk.Checkbutton(self.left_panel, text="Check for outdated packages", variable=self.check_outdated,
                      bg=PANEL_COLOR, fg="#00ff00", selectcolor="#111111").pack(anchor="w")
        
        self.check_security = tk.BooleanVar(value=True)
        tk.Checkbutton(self.left_panel, text="Security vulnerability check", variable=self.check_security,
                      bg=PANEL_COLOR, fg="#00ff00", selectcolor="#111111").pack(anchor="w")
        
        self.check_licenses = tk.BooleanVar(value=False)
        tk.Checkbutton(self.left_panel, text="License compatibility", variable=self.check_licenses,
                      bg=PANEL_COLOR, fg="#00ff00", selectcolor="#111111").pack(anchor="w")

        # Analyze button
        analyze_btn = tk.Button(self.left_panel, text="Analyze Dependencies", command=self.analyze_dependencies)
        style_button(analyze_btn)
        analyze_btn.pack(pady=10, fill="x")

        # Generate report button
        report_btn = tk.Button(self.left_panel, text="Generate Report", command=self.generate_report)
        style_button(report_btn)
        report_btn.pack(pady=2, fill="x")

        # ===== RIGHT: RESULTS =====
        style_label(tk.Label(self.right_panel, text="📊 Dependency Analysis"))
        
        self.results_text = tk.Text(self.right_panel, height=25, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.results_text.pack(fill="both", expand=True, pady=5)

        self.dependencies = {}
        self.selected_file = None

    def select_file(self):
        project_type = self.project_type.get()
        
        if project_type == "python" or project_type == "requirements.txt":
            filetypes = [("Requirements", "requirements.txt"), ("Text Files", "*.txt"), ("All Files", "*.*")]
        elif project_type == "nodejs" or project_type == "package.json":
            filetypes = [("Package JSON", "package.json"), ("JSON Files", "*.json"), ("All Files", "*.*")]
        else:
            filetypes = [("All Files", "*.*")]
        
        file_path = filedialog.askopenfilename(
            title="Select Dependency File",
            filetypes=filetypes
        )
        
        if file_path:
            self.selected_file = file_path
            filename = os.path.basename(file_path)
            self.file_label.config(text=f"Selected: {filename}")
            self.parse_dependency_file(file_path)

    def scan_directory(self):
        directory = filedialog.askdirectory(title="Select Project Directory")
        if not directory:
            return
        
        # Look for common dependency files
        dependency_files = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file in ["requirements.txt", "package.json", "Pipfile", "poetry.lock", "yarn.lock"]:
                    dependency_files.append(os.path.join(root, file))
        
        if dependency_files:
            self.results_text.delete("1.0", tk.END)
            self.results_text.insert(tk.END, f"🔍 Found dependency files in {directory}:\n\n")
            for file in dependency_files:
                rel_path = os.path.relpath(file, directory)
                self.results_text.insert(tk.END, f"📄 {rel_path}\n")
            
            # Auto-select the first requirements.txt or package.json found
            for file in dependency_files:
                if os.path.basename(file) in ["requirements.txt", "package.json"]:
                    self.selected_file = file
                    self.file_label.config(text=f"Auto-selected: {os.path.basename(file)}")
                    self.parse_dependency_file(file)
                    break
        else:
            messagebox.showinfo("No Dependencies", "No dependency files found in the selected directory")

    def parse_dependency_file(self, file_path):
        try:
            filename = os.path.basename(file_path)
            
            if filename == "requirements.txt" or file_path.endswith(".txt"):
                self.parse_requirements_txt(file_path)
            elif filename == "package.json":
                self.parse_package_json(file_path)
            else:
                messagebox.showerror("Error", "Unsupported file type")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to parse file: {e}")

    def parse_requirements_txt(self, file_path):
        self.dependencies = {}
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Parse package==version or package>=version etc.
                    match = re.match(r'^([a-zA-Z0-9_-]+)([><=!]+)?([\d.]+)?', line)
                    if match:
                        package = match.group(1)
                        operator = match.group(2) or "=="
                        version = match.group(3) or "unknown"
                        self.dependencies[package] = {"version": version, "operator": operator}
        
        self.results_text.delete("1.0", tk.END)
        self.results_text.insert(tk.END, f"📦 Parsed {len(self.dependencies)} Python packages from requirements.txt\n\n")
        for pkg, info in list(self.dependencies.items())[:10]:
            self.results_text.insert(tk.END, f"{pkg} {info['operator']} {info['version']}\n")
        if len(self.dependencies) > 10:
            self.results_text.insert(tk.END, f"... and {len(self.dependencies) - 10} more packages\n")

    def parse_package_json(self, file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        self.dependencies = {}
        
        # Parse dependencies and devDependencies
        for dep_type in ["dependencies", "devDependencies"]:
            if dep_type in data:
                for package, version in data[dep_type].items():
                    self.dependencies[package] = {
                        "version": version.lstrip("^~>=<"),
                        "type": dep_type,
                        "raw_version": version
                    }
        
        self.results_text.delete("1.0", tk.END)
        self.results_text.insert(tk.END, f"📦 Parsed {len(self.dependencies)} Node.js packages from package.json\n\n")
        for pkg, info in list(self.dependencies.items())[:10]:
            self.results_text.insert(tk.END, f"{pkg}: {info['raw_version']} ({info['type']})\n")
        if len(self.dependencies) > 10:
            self.results_text.insert(tk.END, f"... and {len(self.dependencies) - 10} more packages\n")

    def analyze_dependencies(self):
        if not self.dependencies:
            messagebox.showerror("Error", "No dependencies loaded. Please select a file first.")
            return

        self.results_text.delete("1.0", tk.END)
        self.results_text.insert(tk.END, "🔍 DEPENDENCY ANALYSIS REPORT\n")
        self.results_text.insert(tk.END, "=" * 50 + "\n\n")

        # Basic statistics
        self.results_text.insert(tk.END, f"📊 SUMMARY\n")
        self.results_text.insert(tk.END, f"Total dependencies: {len(self.dependencies)}\n")
        
        if any("type" in info for info in self.dependencies.values()):
            # Node.js project
            deps = sum(1 for info in self.dependencies.values() if info.get("type") == "dependencies")
            dev_deps = sum(1 for info in self.dependencies.values() if info.get("type") == "devDependencies")
            self.results_text.insert(tk.END, f"Production dependencies: {deps}\n")
            self.results_text.insert(tk.END, f"Development dependencies: {dev_deps}\n")
        
        self.results_text.insert(tk.END, "\n")

        # Check for common security issues
        if self.check_security.get():
            self.check_security_issues()

        # Check for outdated packages (simulated)
        if self.check_outdated.get():
            self.check_outdated_packages()

        # License analysis (simulated)
        if self.check_licenses.get():
            self.analyze_licenses()

        # Dependency analysis
        self.analyze_dependency_patterns()

    def check_security_issues(self):
        self.results_text.insert(tk.END, "🔒 SECURITY ANALYSIS\n")
        
        # Common vulnerable packages (examples)
        vulnerable_packages = {
            "requests": ["2.19.0", "2.18.0"],
            "django": ["1.11.0", "2.0.0"],
            "flask": ["0.12.0"],
            "lodash": ["4.17.10"],
            "moment": ["2.19.0"]
        }
        
        security_issues = []
        for package, info in self.dependencies.items():
            if package.lower() in vulnerable_packages:
                vulnerable_versions = vulnerable_packages[package.lower()]
                current_version = info["version"]
                if current_version in vulnerable_versions:
                    security_issues.append(f"{package} {current_version} - Known vulnerability")
        
        if security_issues:
            self.results_text.insert(tk.END, f"⚠️  Found {len(security_issues)} potential security issues:\n")
            for issue in security_issues:
                self.results_text.insert(tk.END, f"  • {issue}\n")
        else:
            self.results_text.insert(tk.END, "✅ No known security vulnerabilities found\n")
        
        self.results_text.insert(tk.END, "\n")

    def check_outdated_packages(self):
        self.results_text.insert(tk.END, "📅 OUTDATED PACKAGE ANALYSIS\n")
        
        # Simulate checking for outdated packages
        potentially_outdated = []
        for package, info in self.dependencies.items():
            version = info["version"]
            if version != "unknown":
                try:
                    # Simple heuristic: if version is very low, might be outdated
                    major_version = int(version.split('.')[0])
                    if major_version < 2:
                        potentially_outdated.append(f"{package} {version}")
                except:
                    pass
        
        if potentially_outdated:
            self.results_text.insert(tk.END, f"📦 Potentially outdated packages ({len(potentially_outdated)}):\n")
            for pkg in potentially_outdated[:10]:
                self.results_text.insert(tk.END, f"  • {pkg}\n")
            if len(potentially_outdated) > 10:
                self.results_text.insert(tk.END, f"  ... and {len(potentially_outdated) - 10} more\n")
        else:
            self.results_text.insert(tk.END, "✅ All packages appear to be reasonably current\n")
        
        self.results_text.insert(tk.END, "\n")

    def analyze_licenses(self):
        self.results_text.insert(tk.END, "📜 LICENSE ANALYSIS\n")
        
        # Common license types (simulated)
        common_licenses = {
            "MIT": ["requests", "flask", "click"],
            "Apache-2.0": ["django", "tensorflow"],
            "BSD": ["numpy", "pandas"],
            "GPL": ["mysql-python"]
        }
        
        license_summary = {}
        for package in self.dependencies.keys():
            for license_type, packages in common_licenses.items():
                if package.lower() in [p.lower() for p in packages]:
                    if license_type not in license_summary:
                        license_summary[license_type] = []
                    license_summary[license_type].append(package)
                    break
        
        if license_summary:
            self.results_text.insert(tk.END, "License distribution:\n")
            for license_type, packages in license_summary.items():
                self.results_text.insert(tk.END, f"  {license_type}: {len(packages)} packages\n")
        else:
            self.results_text.insert(tk.END, "License information not available for analysis\n")
        
        self.results_text.insert(tk.END, "\n")

    def analyze_dependency_patterns(self):
        self.results_text.insert(tk.END, "🔍 DEPENDENCY PATTERNS\n")
        
        # Analyze version patterns
        version_patterns = {"exact": 0, "range": 0, "latest": 0}
        
        for package, info in self.dependencies.items():
            if "operator" in info:
                if info["operator"] == "==":
                    version_patterns["exact"] += 1
                else:
                    version_patterns["range"] += 1
            elif "raw_version" in info:
                if info["raw_version"].startswith("^") or info["raw_version"].startswith("~"):
                    version_patterns["range"] += 1
                else:
                    version_patterns["exact"] += 1
        
        self.results_text.insert(tk.END, "Version specification patterns:\n")
        for pattern, count in version_patterns.items():
            percentage = (count / len(self.dependencies)) * 100 if self.dependencies else 0
            self.results_text.insert(tk.END, f"  {pattern.title()}: {count} ({percentage:.1f}%)\n")
        
        self.results_text.insert(tk.END, "\n")

    def generate_report(self):
        content = self.results_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showerror("Error", "No analysis results to export")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Save Dependency Report",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("Markdown Files", "*.md"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Report saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report: {e}")