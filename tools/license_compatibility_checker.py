# license_compatibility_checker.py - Software license identification and compatibility analysis
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import json
import re
import requests
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Set
from pathlib import Path

from base_tool import BaseToolFrame
from utils.security_utils import SecurityToolBase
from utils.database import DatabaseManager

TAB_NAME = "License Compatibility Checker"

class ToolFrame(BaseToolFrame, SecurityToolBase):
    def __init__(self, master):
        BaseToolFrame.__init__(self, master)
        SecurityToolBase.__init__(self, "LicenseCompatibilityChecker")
        
        self.db_manager = DatabaseManager()
        self.project_licenses = []
        self.compatibility_matrix = self.load_compatibility_matrix()
        self.license_patterns = self.load_license_patterns()
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface"""
        # Main container
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = ttk.Label(main_frame, text="License Compatibility Checker", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Configuration frame
        config_frame = ttk.LabelFrame(main_frame, text="Scan Configuration", padding=10)
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Project selection
        project_frame = ttk.Frame(config_frame)
        project_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(project_frame, text="Project Directory:").pack(side=tk.LEFT)
        self.project_var = tk.StringVar()
        self.project_entry = ttk.Entry(project_frame, textvariable=self.project_var, width=50)
        self.project_entry.pack(side=tk.LEFT, padx=(10, 5), fill=tk.X, expand=True)
        
        ttk.Button(project_frame, text="Browse", 
                  command=self.browse_project).pack(side=tk.RIGHT)
        
        # Project license selection
        license_frame = ttk.Frame(config_frame)
        license_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(license_frame, text="Project License:").pack(side=tk.LEFT)
        self.project_license_var = tk.StringVar()
        self.license_combo = ttk.Combobox(license_frame, textvariable=self.project_license_var,
                                         values=self.get_common_licenses(), width=20)
        self.license_combo.pack(side=tk.LEFT, padx=(10, 0))
        
        ttk.Button(license_frame, text="Auto-Detect", 
                  command=self.auto_detect_project_license).pack(side=tk.LEFT, padx=(10, 0))
        
        # Scan options
        options_frame = ttk.Frame(config_frame)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.include_dev_deps_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Include dev dependencies", 
                       variable=self.include_dev_deps_var).pack(side=tk.LEFT)
        
        self.strict_mode_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Strict compatibility mode", 
                       variable=self.strict_mode_var).pack(side=tk.LEFT, padx=(20, 0))
        
        # Control buttons
        button_frame = ttk.Frame(config_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.scan_button = ttk.Button(button_frame, text="Scan Licenses", 
                                     command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT)
        
        ttk.Button(button_frame, text="Check Compatibility", 
                  command=self.check_compatibility).pack(side=tk.LEFT, padx=(10, 0))
        
        ttk.Button(button_frame, text="Export Report", 
                  command=self.export_report).pack(side=tk.RIGHT)
        
        # Progress and status
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, 
                                          maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(10, 0))
        
        self.status_var = tk.StringVar(value="Ready to scan")
        status_label = ttk.Label(main_frame, textvariable=self.status_var)
        status_label.pack(pady=(5, 10))
        
        # Results notebook
        self.results_notebook = ttk.Notebook(main_frame)
        self.results_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Licenses tab
        self.setup_licenses_tab()
        
        # Compatibility tab
        self.setup_compatibility_tab()
        
        # Conflicts tab
        self.setup_conflicts_tab()
        
        # Recommendations tab
        self.setup_recommendations_tab()
        
    def setup_licenses_tab(self):
        """Setup the licenses overview tab"""
        licenses_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(licenses_frame, text="Detected Licenses")
        
        # Licenses treeview
        columns = ("Package", "License", "Confidence", "Source", "Risk Level")
        self.licenses_tree = ttk.Treeview(licenses_frame, columns=columns, show="headings", height=15)
        
        # Configure columns
        column_widths = {"Package": 150, "License": 120, "Confidence": 80, 
                        "Source": 100, "Risk Level": 80}
        
        for col in columns:
            self.licenses_tree.heading(col, text=col)
            self.licenses_tree.column(col, width=column_widths.get(col, 100))
        
        # Scrollbars
        licenses_scrollbar_y = ttk.Scrollbar(licenses_frame, orient=tk.VERTICAL, 
                                           command=self.licenses_tree.yview)
        self.licenses_tree.configure(yscrollcommand=licenses_scrollbar_y.set)
        
        self.licenses_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)
        licenses_scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
        # Bind events
        self.licenses_tree.bind("<Double-1>", self.show_license_details)
        
    def setup_compatibility_tab(self):
        """Setup the compatibility analysis tab"""
        compat_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(compat_frame, text="Compatibility Matrix")
        
        # Compatibility matrix display
        self.compat_text = scrolledtext.ScrolledText(compat_frame, wrap=tk.WORD, 
                                                    font=("Courier", 10))
        self.compat_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
    def setup_conflicts_tab(self):
        """Setup the conflicts tab"""
        conflicts_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(conflicts_frame, text="License Conflicts")
        
        # Conflicts treeview
        columns = ("Package 1", "License 1", "Package 2", "License 2", "Conflict Type", "Severity")
        self.conflicts_tree = ttk.Treeview(conflicts_frame, columns=columns, show="headings", height=15)
        
        # Configure columns
        for col in columns:
            self.conflicts_tree.heading(col, text=col)
            self.conflicts_tree.column(col, width=100)
        
        # Scrollbars
        conflicts_scrollbar_y = ttk.Scrollbar(conflicts_frame, orient=tk.VERTICAL, 
                                            command=self.conflicts_tree.yview)
        self.conflicts_tree.configure(yscrollcommand=conflicts_scrollbar_y.set)
        
        self.conflicts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)
        conflicts_scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
        # Bind events
        self.conflicts_tree.bind("<Double-1>", self.show_conflict_details)
        
    def setup_recommendations_tab(self):
        """Setup the recommendations tab"""
        rec_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(rec_frame, text="Recommendations")
        
        # Recommendations text widget
        self.recommendations_text = scrolledtext.ScrolledText(rec_frame, wrap=tk.WORD)
        self.recommendations_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
    def load_compatibility_matrix(self) -> Dict[str, Dict[str, str]]:
        """Load license compatibility matrix"""
        # Simplified compatibility matrix
        # In a real implementation, this would be more comprehensive
        return {
            "MIT": {
                "MIT": "Compatible",
                "Apache-2.0": "Compatible", 
                "BSD-3-Clause": "Compatible",
                "GPL-2.0": "Compatible",
                "GPL-3.0": "Compatible",
                "LGPL-2.1": "Compatible",
                "LGPL-3.0": "Compatible",
                "MPL-2.0": "Compatible",
                "AGPL-3.0": "Compatible"
            },
            "Apache-2.0": {
                "MIT": "Compatible",
                "Apache-2.0": "Compatible",
                "BSD-3-Clause": "Compatible", 
                "GPL-2.0": "Incompatible",
                "GPL-3.0": "Compatible",
                "LGPL-2.1": "Compatible",
                "LGPL-3.0": "Compatible",
                "MPL-2.0": "Compatible",
                "AGPL-3.0": "Compatible"
            },
            "GPL-2.0": {
                "MIT": "Compatible",
                "Apache-2.0": "Incompatible",
                "BSD-3-Clause": "Compatible",
                "GPL-2.0": "Compatible",
                "GPL-3.0": "Incompatible",
                "LGPL-2.1": "Compatible",
                "LGPL-3.0": "Incompatible",
                "MPL-2.0": "Incompatible",
                "AGPL-3.0": "Incompatible"
            },
            "GPL-3.0": {
                "MIT": "Compatible",
                "Apache-2.0": "Compatible",
                "BSD-3-Clause": "Compatible",
                "GPL-2.0": "Incompatible",
                "GPL-3.0": "Compatible",
                "LGPL-2.1": "Compatible",
                "LGPL-3.0": "Compatible",
                "MPL-2.0": "Compatible",
                "AGPL-3.0": "Compatible"
            },
            "LGPL-2.1": {
                "MIT": "Compatible",
                "Apache-2.0": "Compatible",
                "BSD-3-Clause": "Compatible",
                "GPL-2.0": "Compatible",
                "GPL-3.0": "Compatible",
                "LGPL-2.1": "Compatible",
                "LGPL-3.0": "Compatible",
                "MPL-2.0": "Compatible",
                "AGPL-3.0": "Compatible"
            },
            "LGPL-3.0": {
                "MIT": "Compatible",
                "Apache-2.0": "Compatible",
                "BSD-3-Clause": "Compatible",
                "GPL-2.0": "Incompatible",
                "GPL-3.0": "Compatible",
                "LGPL-2.1": "Compatible",
                "LGPL-3.0": "Compatible",
                "MPL-2.0": "Compatible",
                "AGPL-3.0": "Compatible"
            },
            "MPL-2.0": {
                "MIT": "Compatible",
                "Apache-2.0": "Compatible",
                "BSD-3-Clause": "Compatible",
                "GPL-2.0": "Incompatible",
                "GPL-3.0": "Compatible",
                "LGPL-2.1": "Compatible",
                "LGPL-3.0": "Compatible",
                "MPL-2.0": "Compatible",
                "AGPL-3.0": "Compatible"
            },
            "AGPL-3.0": {
                "MIT": "Compatible",
                "Apache-2.0": "Compatible",
                "BSD-3-Clause": "Compatible",
                "GPL-2.0": "Incompatible",
                "GPL-3.0": "Compatible",
                "LGPL-2.1": "Compatible",
                "LGPL-3.0": "Compatible",
                "MPL-2.0": "Compatible",
                "AGPL-3.0": "Compatible"
            }
        }
    
    def load_license_patterns(self) -> Dict[str, List[str]]:
        """Load license detection patterns"""
        return {
            "MIT": [
                r"MIT License",
                r"Permission is hereby granted, free of charge",
                r"THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY"
            ],
            "Apache-2.0": [
                r"Apache License.*Version 2\.0",
                r"Licensed under the Apache License, Version 2\.0",
                r"http://www\.apache\.org/licenses/LICENSE-2\.0"
            ],
            "GPL-2.0": [
                r"GNU GENERAL PUBLIC LICENSE.*Version 2",
                r"This program is free software.*GNU General Public License",
                r"http://www\.gnu\.org/licenses/gpl-2\.0"
            ],
            "GPL-3.0": [
                r"GNU GENERAL PUBLIC LICENSE.*Version 3",
                r"This program is free software.*GNU General Public License.*version 3",
                r"http://www\.gnu\.org/licenses/gpl-3\.0"
            ],
            "LGPL-2.1": [
                r"GNU LESSER GENERAL PUBLIC LICENSE.*Version 2\.1",
                r"This library is free software.*GNU Lesser General Public License",
                r"http://www\.gnu\.org/licenses/lgpl-2\.1"
            ],
            "LGPL-3.0": [
                r"GNU LESSER GENERAL PUBLIC LICENSE.*Version 3",
                r"This library is free software.*GNU Lesser General Public License.*version 3",
                r"http://www\.gnu\.org/licenses/lgpl-3\.0"
            ],
            "BSD-3-Clause": [
                r"BSD 3-Clause License",
                r"Redistribution and use in source and binary forms.*with or without modification",
                r"Neither the name of.*nor the names of its contributors"
            ],
            "MPL-2.0": [
                r"Mozilla Public License.*Version 2\.0",
                r"This Source Code Form is subject to the terms of the Mozilla Public License",
                r"http://mozilla\.org/MPL/2\.0/"
            ],
            "AGPL-3.0": [
                r"GNU AFFERO GENERAL PUBLIC LICENSE.*Version 3",
                r"This program is free software.*GNU Affero General Public License",
                r"http://www\.gnu\.org/licenses/agpl-3\.0"
            ]
        }
    
    def get_common_licenses(self) -> List[str]:
        """Get list of common licenses"""
        return [
            "MIT", "Apache-2.0", "GPL-2.0", "GPL-3.0", "LGPL-2.1", "LGPL-3.0",
            "BSD-3-Clause", "BSD-2-Clause", "MPL-2.0", "AGPL-3.0", "ISC", "Unlicense"
        ]
    
    def browse_project(self):
        """Browse for project directory"""
        directory = filedialog.askdirectory(title="Select Project Directory")
        if directory:
            self.project_var.set(directory)
    
    def auto_detect_project_license(self):
        """Auto-detect project license"""
        project_path = self.project_var.get().strip()
        if not project_path or not os.path.exists(project_path):
            messagebox.showerror("Error", "Please select a valid project directory")
            return
        
        # Look for license files
        license_files = []
        for root, dirs, files in os.walk(project_path):
            for file in files:
                if file.lower() in ['license', 'license.txt', 'license.md', 'copying', 'copyright']:
                    license_files.append(os.path.join(root, file))
            # Only check root directory for license files
            break
        
        if not license_files:
            messagebox.showinfo("No License Found", "No license file found in project root")
            return
        
        # Analyze first license file found
        detected_license = self.detect_license_from_file(license_files[0])
        if detected_license:
            self.project_license_var.set(detected_license)
            messagebox.showinfo("License Detected", f"Detected license: {detected_license}")
        else:
            messagebox.showwarning("Detection Failed", "Could not automatically detect license")
    
    def detect_license_from_file(self, file_path: str) -> Optional[str]:
        """Detect license from file content"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check against known patterns
            for license_name, patterns in self.license_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return license_name
            
            return None
            
        except Exception as e:
            self.log_security_activity("LICENSE_DETECTION_ERROR", f"Error detecting license: {str(e)}")
            return None
    
    def start_scan(self):
        """Start license scanning"""
        project_path = self.project_var.get().strip()
        if not project_path or not os.path.exists(project_path):
            messagebox.showerror("Error", "Please select a valid project directory")
            return
        
        # Validate target for ethical scanning
        if not self.validate_and_authorize(project_path, "license_scan"):
            messagebox.showerror("Authorization Error", 
                               "Project not authorized for scanning. Check security logs.")
            return
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(target=self.run_license_scan, 
                                           args=(project_path,))
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        # Update UI state
        self.scan_button.config(state=tk.DISABLED)
        self.status_var.set("Scanning licenses...")
        self.progress_var.set(0)
    
    def run_license_scan(self, project_path: str):
        """Run the license scan"""
        try:
            self.log_security_activity("LICENSE_SCAN_STARTED", 
                                     f"License scan started", project_path)
            
            # Clear previous results
            self.project_licenses = []
            
            # Scan different types of files and dependencies
            self.scan_source_files(project_path)
            self.scan_dependency_licenses(project_path)
            self.scan_package_metadata(project_path)
            
            # Update UI
            self.master.after(0, self.update_licenses_ui)
            
            self.log_security_activity("LICENSE_SCAN_COMPLETED", 
                                     f"Found {len(self.project_licenses)} license entries", 
                                     project_path)
            
        except Exception as e:
            self.log_security_activity("LICENSE_SCAN_ERROR", f"Scan error: {str(e)}", project_path)
            self.master.after(0, lambda: messagebox.showerror("Scan Error", str(e)))
        
        finally:
            # Reset UI state
            self.master.after(0, self.reset_scan_ui)
    
    def scan_source_files(self, project_path: str):
        """Scan source files for license headers"""
        self.master.after(0, lambda: self.status_var.set("Scanning source files..."))
        
        source_extensions = ['.py', '.js', '.java', '.cpp', '.c', '.h', '.cs', '.php', '.rb']
        
        for root, dirs, files in os.walk(project_path):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv']]
            
            for file in files:
                if any(file.endswith(ext) for ext in source_extensions):
                    file_path = os.path.join(root, file)
                    self.scan_file_license_header(file_path)
        
        self.master.after(0, lambda: self.progress_var.set(25))
    
    def scan_file_license_header(self, file_path: str):
        """Scan individual file for license header"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Read first 50 lines (typical license header length)
                header_lines = []
                for i, line in enumerate(f):
                    if i >= 50:
                        break
                    header_lines.append(line)
                
                header_content = ''.join(header_lines)
            
            # Check for license patterns in header
            detected_license = None
            confidence = 0
            
            for license_name, patterns in self.license_patterns.items():
                pattern_matches = 0
                for pattern in patterns:
                    if re.search(pattern, header_content, re.IGNORECASE):
                        pattern_matches += 1
                
                if pattern_matches > 0:
                    current_confidence = (pattern_matches / len(patterns)) * 100
                    if current_confidence > confidence:
                        confidence = current_confidence
                        detected_license = license_name
            
            if detected_license and confidence > 30:  # Minimum confidence threshold
                license_entry = {
                    "package": os.path.basename(file_path),
                    "license": detected_license,
                    "confidence": f"{confidence:.1f}%",
                    "source": "File Header",
                    "file_path": file_path,
                    "risk_level": self.assess_license_risk(detected_license)
                }
                self.project_licenses.append(license_entry)
                
        except Exception as e:
            self.log_security_activity("FILE_HEADER_SCAN_ERROR", 
                                     f"Error scanning {file_path}: {str(e)}")
    
    def scan_dependency_licenses(self, project_path: str):
        """Scan dependency files for license information"""
        self.master.after(0, lambda: self.status_var.set("Scanning dependencies..."))
        
        # Scan Python dependencies
        self.scan_python_dependency_licenses(project_path)
        
        # Scan NPM dependencies
        self.scan_npm_dependency_licenses(project_path)
        
        # Scan Maven dependencies
        self.scan_maven_dependency_licenses(project_path)
        
        self.master.after(0, lambda: self.progress_var.set(75))
    
    def scan_python_dependency_licenses(self, project_path: str):
        """Scan Python dependencies for license information"""
        req_files = []
        for root, dirs, files in os.walk(project_path):
            for file in files:
                if file in ['requirements.txt', 'Pipfile', 'pyproject.toml']:
                    req_files.append(os.path.join(root, file))
        
        for req_file in req_files:
            try:
                if req_file.endswith('requirements.txt'):
                    self.parse_requirements_licenses(req_file)
                elif req_file.endswith('Pipfile'):
                    self.parse_pipfile_licenses(req_file)
                elif req_file.endswith('pyproject.toml'):
                    self.parse_pyproject_licenses(req_file)
            except Exception as e:
                self.log_security_activity("PYTHON_DEP_LICENSE_ERROR", 
                                         f"Error parsing {req_file}: {str(e)}")
    
    def parse_requirements_licenses(self, file_path: str):
        """Parse requirements.txt and lookup licenses"""
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Extract package name
            package_name = re.split(r'[>=<!=]', line)[0].strip()
            
            # Mock license lookup (in real implementation, query PyPI API)
            license_info = self.lookup_package_license(package_name, 'python')
            if license_info:
                license_entry = {
                    "package": package_name,
                    "license": license_info["license"],
                    "confidence": license_info["confidence"],
                    "source": "PyPI API",
                    "file_path": file_path,
                    "risk_level": self.assess_license_risk(license_info["license"])
                }
                self.project_licenses.append(license_entry)
    
    def parse_pipfile_licenses(self, file_path: str):
        """Parse Pipfile and lookup licenses"""
        # Simplified Pipfile parsing
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Extract package names (simplified)
            package_pattern = r'([a-zA-Z0-9_-]+)\s*='
            matches = re.findall(package_pattern, content)
            
            for package_name in matches:
                license_info = self.lookup_package_license(package_name, 'python')
                if license_info:
                    license_entry = {
                        "package": package_name,
                        "license": license_info["license"],
                        "confidence": license_info["confidence"],
                        "source": "PyPI API",
                        "file_path": file_path,
                        "risk_level": self.assess_license_risk(license_info["license"])
                    }
                    self.project_licenses.append(license_entry)
                    
        except Exception as e:
            self.log_security_activity("PIPFILE_LICENSE_ERROR", f"Error parsing Pipfile: {str(e)}")
    
    def parse_pyproject_licenses(self, file_path: str):
        """Parse pyproject.toml and lookup licenses"""
        # Simplified pyproject.toml parsing
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Extract dependencies
            dep_pattern = r'([a-zA-Z0-9_-]+)\s*='
            matches = re.findall(dep_pattern, content)
            
            for package_name in matches:
                if package_name != 'python':  # Skip Python version
                    license_info = self.lookup_package_license(package_name, 'python')
                    if license_info:
                        license_entry = {
                            "package": package_name,
                            "license": license_info["license"],
                            "confidence": license_info["confidence"],
                            "source": "PyPI API",
                            "file_path": file_path,
                            "risk_level": self.assess_license_risk(license_info["license"])
                        }
                        self.project_licenses.append(license_entry)
                        
        except Exception as e:
            self.log_security_activity("PYPROJECT_LICENSE_ERROR", f"Error parsing pyproject.toml: {str(e)}")
    
    def scan_npm_dependency_licenses(self, project_path: str):
        """Scan NPM dependencies for license information"""
        package_files = []
        for root, dirs, files in os.walk(project_path):
            if 'package.json' in files:
                package_files.append(os.path.join(root, 'package.json'))
        
        for package_file in package_files:
            try:
                with open(package_file, 'r') as f:
                    package_data = json.load(f)
                
                # Check dependencies
                dependencies = package_data.get('dependencies', {})
                if self.include_dev_deps_var.get():
                    dependencies.update(package_data.get('devDependencies', {}))
                
                for package_name in dependencies.keys():
                    license_info = self.lookup_package_license(package_name, 'npm')
                    if license_info:
                        license_entry = {
                            "package": package_name,
                            "license": license_info["license"],
                            "confidence": license_info["confidence"],
                            "source": "NPM Registry",
                            "file_path": package_file,
                            "risk_level": self.assess_license_risk(license_info["license"])
                        }
                        self.project_licenses.append(license_entry)
                        
            except Exception as e:
                self.log_security_activity("NPM_LICENSE_ERROR", 
                                         f"Error parsing {package_file}: {str(e)}")
    
    def scan_maven_dependency_licenses(self, project_path: str):
        """Scan Maven dependencies for license information"""
        pom_files = []
        for root, dirs, files in os.walk(project_path):
            if 'pom.xml' in files:
                pom_files.append(os.path.join(root, 'pom.xml'))
        
        for pom_file in pom_files:
            try:
                with open(pom_file, 'r') as f:
                    content = f.read()
                
                # Extract dependencies (simplified)
                dep_pattern = r'<groupId>([^<]+)</groupId>.*?<artifactId>([^<]+)</artifactId>'
                matches = re.findall(dep_pattern, content, re.DOTALL)
                
                for group_id, artifact_id in matches:
                    package_name = f"{group_id}:{artifact_id}"
                    license_info = self.lookup_package_license(package_name, 'maven')
                    if license_info:
                        license_entry = {
                            "package": package_name,
                            "license": license_info["license"],
                            "confidence": license_info["confidence"],
                            "source": "Maven Central",
                            "file_path": pom_file,
                            "risk_level": self.assess_license_risk(license_info["license"])
                        }
                        self.project_licenses.append(license_entry)
                        
            except Exception as e:
                self.log_security_activity("MAVEN_LICENSE_ERROR", 
                                         f"Error parsing {pom_file}: {str(e)}")
    
    def scan_package_metadata(self, project_path: str):
        """Scan package metadata files for license information"""
        self.master.after(0, lambda: self.status_var.set("Scanning package metadata..."))
        
        # Look for package.json license field
        package_files = []
        for root, dirs, files in os.walk(project_path):
            if 'package.json' in files:
                package_files.append(os.path.join(root, 'package.json'))
        
        for package_file in package_files:
            try:
                with open(package_file, 'r') as f:
                    package_data = json.load(f)
                
                if 'license' in package_data:
                    license_entry = {
                        "package": package_data.get('name', 'Current Project'),
                        "license": package_data['license'],
                        "confidence": "100%",
                        "source": "package.json",
                        "file_path": package_file,
                        "risk_level": self.assess_license_risk(package_data['license'])
                    }
                    self.project_licenses.append(license_entry)
                    
            except Exception as e:
                self.log_security_activity("PACKAGE_METADATA_ERROR", 
                                         f"Error parsing {package_file}: {str(e)}")
        
        self.master.after(0, lambda: self.progress_var.set(90))
    
    def lookup_package_license(self, package_name: str, ecosystem: str) -> Optional[Dict]:
        """Lookup package license from registry (mock implementation)"""
        # Mock license data for demonstration
        # In real implementation, query actual package registries
        
        mock_licenses = {
            'python': {
                'requests': {'license': 'Apache-2.0', 'confidence': '95%'},
                'django': {'license': 'BSD-3-Clause', 'confidence': '95%'},
                'flask': {'license': 'BSD-3-Clause', 'confidence': '95%'},
                'numpy': {'license': 'BSD-3-Clause', 'confidence': '95%'},
                'pandas': {'license': 'BSD-3-Clause', 'confidence': '95%'},
            },
            'npm': {
                'express': {'license': 'MIT', 'confidence': '95%'},
                'lodash': {'license': 'MIT', 'confidence': '95%'},
                'react': {'license': 'MIT', 'confidence': '95%'},
                'vue': {'license': 'MIT', 'confidence': '95%'},
                'angular': {'license': 'MIT', 'confidence': '95%'},
            },
            'maven': {
                'org.springframework:spring-core': {'license': 'Apache-2.0', 'confidence': '95%'},
                'junit:junit': {'license': 'EPL-1.0', 'confidence': '95%'},
                'org.apache.commons:commons-lang3': {'license': 'Apache-2.0', 'confidence': '95%'},
            }
        }
        
        return mock_licenses.get(ecosystem, {}).get(package_name)
    
    def assess_license_risk(self, license_name: str) -> str:
        """Assess risk level of a license"""
        # Risk assessment based on license restrictions
        high_risk_licenses = ['AGPL-3.0', 'GPL-2.0', 'GPL-3.0']
        medium_risk_licenses = ['LGPL-2.1', 'LGPL-3.0', 'MPL-2.0', 'EPL-1.0']
        low_risk_licenses = ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'BSD-2-Clause', 'ISC']
        
        if license_name in high_risk_licenses:
            return "High"
        elif license_name in medium_risk_licenses:
            return "Medium"
        elif license_name in low_risk_licenses:
            return "Low"
        else:
            return "Unknown"   
 
    def update_licenses_ui(self):
        """Update the licenses UI with scan results"""
        # Clear previous results
        for item in self.licenses_tree.get_children():
            self.licenses_tree.delete(item)
        
        # Update licenses tree
        for license_entry in self.project_licenses:
            self.licenses_tree.insert("", tk.END, values=(
                license_entry["package"],
                license_entry["license"],
                license_entry["confidence"],
                license_entry["source"],
                license_entry["risk_level"]
            ))
        
        # Update status
        self.status_var.set(f"Found {len(self.project_licenses)} license entries")
        self.progress_var.set(100)
    
    def check_compatibility(self):
        """Check license compatibility"""
        project_license = self.project_license_var.get().strip()
        if not project_license:
            messagebox.showerror("Error", "Please specify or detect the project license first")
            return
        
        if not self.project_licenses:
            messagebox.showwarning("No Data", "Please scan for licenses first")
            return
        
        # Run compatibility analysis
        self.analyze_compatibility(project_license)
        
        # Update compatibility display
        self.update_compatibility_display(project_license)
        
        # Find and display conflicts
        conflicts = self.find_license_conflicts(project_license)
        self.update_conflicts_display(conflicts)
        
        # Generate recommendations
        self.generate_compatibility_recommendations(project_license, conflicts)
    
    def analyze_compatibility(self, project_license: str):
        """Analyze license compatibility"""
        self.log_security_activity("COMPATIBILITY_CHECK", 
                                 f"Checking compatibility with {project_license}")
        
        # Check each dependency license against project license
        for license_entry in self.project_licenses:
            dep_license = license_entry["license"]
            compatibility = self.get_license_compatibility(project_license, dep_license)
            license_entry["compatibility"] = compatibility
    
    def get_license_compatibility(self, license1: str, license2: str) -> str:
        """Get compatibility between two licenses"""
        # Check compatibility matrix
        if license1 in self.compatibility_matrix:
            return self.compatibility_matrix[license1].get(license2, "Unknown")
        
        # If not in matrix, assume unknown
        return "Unknown"
    
    def update_compatibility_display(self, project_license: str):
        """Update the compatibility matrix display"""
        self.compat_text.delete(1.0, tk.END)
        
        # Generate compatibility matrix display
        matrix_text = f"LICENSE COMPATIBILITY MATRIX\n"
        matrix_text += f"Project License: {project_license}\n"
        matrix_text += "=" * 60 + "\n\n"
        
        # Group licenses by compatibility
        compatible = []
        incompatible = []
        unknown = []
        
        for license_entry in self.project_licenses:
            dep_license = license_entry["license"]
            compatibility = license_entry.get("compatibility", "Unknown")
            
            if compatibility == "Compatible":
                compatible.append(license_entry)
            elif compatibility == "Incompatible":
                incompatible.append(license_entry)
            else:
                unknown.append(license_entry)
        
        # Display compatible licenses
        if compatible:
            matrix_text += f"COMPATIBLE LICENSES ({len(compatible)}):\n"
            matrix_text += "-" * 30 + "\n"
            for entry in compatible:
                matrix_text += f"✓ {entry['package']}: {entry['license']}\n"
            matrix_text += "\n"
        
        # Display incompatible licenses
        if incompatible:
            matrix_text += f"INCOMPATIBLE LICENSES ({len(incompatible)}):\n"
            matrix_text += "-" * 30 + "\n"
            for entry in incompatible:
                matrix_text += f"✗ {entry['package']}: {entry['license']}\n"
            matrix_text += "\n"
        
        # Display unknown licenses
        if unknown:
            matrix_text += f"UNKNOWN COMPATIBILITY ({len(unknown)}):\n"
            matrix_text += "-" * 30 + "\n"
            for entry in unknown:
                matrix_text += f"? {entry['package']}: {entry['license']}\n"
            matrix_text += "\n"
        
        # Add compatibility summary
        total = len(self.project_licenses)
        compatible_count = len(compatible)
        incompatible_count = len(incompatible)
        
        matrix_text += "COMPATIBILITY SUMMARY:\n"
        matrix_text += "-" * 25 + "\n"
        matrix_text += f"Compatible: {compatible_count}/{total} ({compatible_count/total*100:.1f}%)\n"
        matrix_text += f"Incompatible: {incompatible_count}/{total} ({incompatible_count/total*100:.1f}%)\n"
        matrix_text += f"Unknown: {len(unknown)}/{total} ({len(unknown)/total*100:.1f}%)\n"
        
        self.compat_text.insert(tk.END, matrix_text)
    
    def find_license_conflicts(self, project_license: str) -> List[Dict]:
        """Find license conflicts"""
        conflicts = []
        
        # Find direct incompatibilities with project license
        for license_entry in self.project_licenses:
            compatibility = license_entry.get("compatibility", "Unknown")
            if compatibility == "Incompatible":
                conflict = {
                    "package1": "Project",
                    "license1": project_license,
                    "package2": license_entry["package"],
                    "license2": license_entry["license"],
                    "conflict_type": "Direct Incompatibility",
                    "severity": "High",
                    "description": f"{project_license} is incompatible with {license_entry['license']}"
                }
                conflicts.append(conflict)
        
        # Find conflicts between dependencies (simplified)
        if self.strict_mode_var.get():
            for i, entry1 in enumerate(self.project_licenses):
                for entry2 in self.project_licenses[i+1:]:
                    compatibility = self.get_license_compatibility(entry1["license"], entry2["license"])
                    if compatibility == "Incompatible":
                        conflict = {
                            "package1": entry1["package"],
                            "license1": entry1["license"],
                            "package2": entry2["package"],
                            "license2": entry2["license"],
                            "conflict_type": "Dependency Conflict",
                            "severity": "Medium",
                            "description": f"{entry1['license']} conflicts with {entry2['license']}"
                        }
                        conflicts.append(conflict)
        
        return conflicts
    
    def update_conflicts_display(self, conflicts: List[Dict]):
        """Update the conflicts display"""
        # Clear previous conflicts
        for item in self.conflicts_tree.get_children():
            self.conflicts_tree.delete(item)
        
        # Add conflicts to tree
        for conflict in conflicts:
            self.conflicts_tree.insert("", tk.END, values=(
                conflict["package1"],
                conflict["license1"],
                conflict["package2"],
                conflict["license2"],
                conflict["conflict_type"],
                conflict["severity"]
            ))
    
    def generate_compatibility_recommendations(self, project_license: str, conflicts: List[Dict]):
        """Generate compatibility recommendations"""
        self.recommendations_text.delete(1.0, tk.END)
        
        recommendations = "LICENSE COMPATIBILITY RECOMMENDATIONS\n"
        recommendations += "=" * 50 + "\n\n"
        
        if not conflicts:
            recommendations += "✓ No license conflicts detected!\n\n"
            recommendations += "Your project appears to have good license compatibility.\n"
            recommendations += "Continue monitoring for new dependencies.\n\n"
        else:
            recommendations += f"⚠ {len(conflicts)} license conflicts detected!\n\n"
            
            # High severity conflicts
            high_conflicts = [c for c in conflicts if c["severity"] == "High"]
            if high_conflicts:
                recommendations += "IMMEDIATE ACTION REQUIRED:\n"
                recommendations += "-" * 30 + "\n"
                for conflict in high_conflicts:
                    recommendations += f"• {conflict['package2']} ({conflict['license2']})\n"
                    recommendations += f"  Incompatible with project license {project_license}\n"
                    recommendations += f"  Recommendation: Find alternative package or change project license\n\n"
            
            # Medium severity conflicts
            medium_conflicts = [c for c in conflicts if c["severity"] == "Medium"]
            if medium_conflicts:
                recommendations += "REVIEW RECOMMENDED:\n"
                recommendations += "-" * 20 + "\n"
                for conflict in medium_conflicts:
                    recommendations += f"• {conflict['package1']} vs {conflict['package2']}\n"
                    recommendations += f"  {conflict['license1']} conflicts with {conflict['license2']}\n"
                    recommendations += f"  Consider if both packages are actually used together\n\n"
        
        # General recommendations
        recommendations += "GENERAL RECOMMENDATIONS:\n"
        recommendations += "-" * 25 + "\n"
        recommendations += "• Regularly audit licenses when adding new dependencies\n"
        recommendations += "• Maintain a license policy document for your organization\n"
        recommendations += "• Consider using license scanning in your CI/CD pipeline\n"
        recommendations += "• Keep track of license changes in dependency updates\n"
        recommendations += "• Consult legal counsel for complex license scenarios\n\n"
        
        # Alternative suggestions
        incompatible_licenses = set()
        for conflict in conflicts:
            if conflict["severity"] == "High":
                incompatible_licenses.add(conflict["license2"])
        
        if incompatible_licenses:
            recommendations += "ALTERNATIVE LICENSE SUGGESTIONS:\n"
            recommendations += "-" * 35 + "\n"
            for license_name in incompatible_licenses:
                alternatives = self.suggest_license_alternatives(license_name, project_license)
                if alternatives:
                    recommendations += f"Instead of {license_name}, consider:\n"
                    for alt in alternatives:
                        recommendations += f"  • {alt}\n"
                    recommendations += "\n"
        
        self.recommendations_text.insert(tk.END, recommendations)
    
    def suggest_license_alternatives(self, incompatible_license: str, project_license: str) -> List[str]:
        """Suggest alternative licenses that are compatible"""
        alternatives = []
        
        # Find licenses compatible with project license
        if project_license in self.compatibility_matrix:
            compatible_licenses = [
                license_name for license_name, compatibility 
                in self.compatibility_matrix[project_license].items()
                if compatibility == "Compatible"
            ]
            
            # Filter out the incompatible license and suggest similar ones
            license_families = {
                "GPL-2.0": ["LGPL-2.1", "MIT", "Apache-2.0"],
                "GPL-3.0": ["LGPL-3.0", "MIT", "Apache-2.0"],
                "AGPL-3.0": ["GPL-3.0", "LGPL-3.0"],
            }
            
            if incompatible_license in license_families:
                for alt in license_families[incompatible_license]:
                    if alt in compatible_licenses:
                        alternatives.append(alt)
        
        return alternatives[:3]  # Return top 3 alternatives
    
    def show_license_details(self, event):
        """Show detailed license information"""
        selection = self.licenses_tree.selection()
        if not selection:
            return
        
        item = self.licenses_tree.item(selection[0])
        values = item['values']
        package_name = values[0]
        
        # Find the license entry
        license_entry = None
        for entry in self.project_licenses:
            if entry["package"] == package_name:
                license_entry = entry
                break
        
        if license_entry:
            self.show_license_popup(license_entry)
    
    def show_license_popup(self, license_entry: Dict):
        """Show detailed license information in popup"""
        popup = tk.Toplevel(self.master)
        popup.title(f"License Details - {license_entry['package']}")
        popup.geometry("600x500")
        
        text_widget = scrolledtext.ScrolledText(popup, wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        details = f"License Information\n"
        details += "=" * 50 + "\n\n"
        details += f"Package: {license_entry['package']}\n"
        details += f"License: {license_entry['license']}\n"
        details += f"Confidence: {license_entry['confidence']}\n"
        details += f"Source: {license_entry['source']}\n"
        details += f"Risk Level: {license_entry['risk_level']}\n"
        details += f"File: {license_entry.get('file_path', 'N/A')}\n\n"
        
        if 'compatibility' in license_entry:
            details += f"Compatibility with Project: {license_entry['compatibility']}\n\n"
        
        # Add license description
        license_descriptions = {
            "MIT": "A permissive license that allows commercial use, modification, distribution, and private use.",
            "Apache-2.0": "A permissive license with patent protection and trademark restrictions.",
            "GPL-2.0": "A copyleft license requiring derivative works to be open source under the same license.",
            "GPL-3.0": "An updated copyleft license with additional patent and DRM protections.",
            "LGPL-2.1": "A weaker copyleft license allowing linking with proprietary software.",
            "LGPL-3.0": "An updated weaker copyleft license with patent protections.",
            "BSD-3-Clause": "A permissive license with attribution requirements and endorsement restrictions.",
            "MPL-2.0": "A weak copyleft license requiring source disclosure for modified files only.",
            "AGPL-3.0": "A strong copyleft license extending GPL to network use."
        }
        
        description = license_descriptions.get(license_entry['license'], "No description available.")
        details += f"License Description:\n{description}\n\n"
        
        # Add compatibility information
        project_license = self.project_license_var.get()
        if project_license and project_license in self.compatibility_matrix:
            compatibility = self.compatibility_matrix[project_license].get(license_entry['license'], "Unknown")
            details += f"Compatibility with {project_license}: {compatibility}\n"
            
            if compatibility == "Incompatible":
                details += "⚠ This license may create legal conflicts with your project license.\n"
            elif compatibility == "Compatible":
                details += "✓ This license is compatible with your project license.\n"
        
        text_widget.insert(tk.END, details)
        text_widget.config(state=tk.DISABLED)
    
    def show_conflict_details(self, event):
        """Show detailed conflict information"""
        selection = self.conflicts_tree.selection()
        if not selection:
            return
        
        item = self.conflicts_tree.item(selection[0])
        values = item['values']
        
        # Create conflict details popup
        popup = tk.Toplevel(self.master)
        popup.title("License Conflict Details")
        popup.geometry("600x400")
        
        text_widget = scrolledtext.ScrolledText(popup, wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        details = f"License Conflict Details\n"
        details += "=" * 50 + "\n\n"
        details += f"Package 1: {values[0]}\n"
        details += f"License 1: {values[1]}\n"
        details += f"Package 2: {values[2]}\n"
        details += f"License 2: {values[3]}\n"
        details += f"Conflict Type: {values[4]}\n"
        details += f"Severity: {values[5]}\n\n"
        
        details += "Conflict Explanation:\n"
        details += f"The licenses {values[1]} and {values[3]} have incompatible terms.\n\n"
        
        details += "Recommended Actions:\n"
        details += "• Review if both packages are actually needed\n"
        details += "• Look for alternative packages with compatible licenses\n"
        details += "• Consider changing your project license if appropriate\n"
        details += "• Consult legal counsel for complex scenarios\n"
        
        text_widget.insert(tk.END, details)
        text_widget.config(state=tk.DISABLED)
    
    def export_report(self):
        """Export license compatibility report"""
        if not self.project_licenses:
            messagebox.showwarning("No Data", "No license data to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Export License Report",
            defaultextension=".json",
            filetypes=[
                ("JSON files", "*.json"),
                ("CSV files", "*.csv"),
                ("Text files", "*.txt")
            ]
        )
        
        if not file_path:
            return
        
        try:
            if file_path.endswith('.json'):
                self.export_json_report(file_path)
            elif file_path.endswith('.csv'):
                self.export_csv_report(file_path)
            else:
                self.export_text_report(file_path)
            
            messagebox.showinfo("Export Complete", f"Report exported to {file_path}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report: {str(e)}")
    
    def export_json_report(self, file_path: str):
        """Export report as JSON"""
        report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "project_path": self.project_var.get(),
                "project_license": self.project_license_var.get(),
                "total_licenses": len(self.project_licenses)
            },
            "licenses": self.project_licenses,
            "compatibility_matrix": self.compatibility_matrix
        }
        
        with open(file_path, 'w') as f:
            json.dump(report_data, f, indent=2)
    
    def export_csv_report(self, file_path: str):
        """Export report as CSV"""
        import csv
        
        with open(file_path, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                "Package", "License", "Confidence", "Source", "Risk Level", 
                "Compatibility", "File Path"
            ])
            
            # Write data
            for entry in self.project_licenses:
                writer.writerow([
                    entry["package"],
                    entry["license"],
                    entry["confidence"],
                    entry["source"],
                    entry["risk_level"],
                    entry.get("compatibility", "Unknown"),
                    entry.get("file_path", "")
                ])
    
    def export_text_report(self, file_path: str):
        """Export report as text"""
        with open(file_path, 'w') as f:
            f.write("LICENSE COMPATIBILITY REPORT\n")
            f.write("=" * 40 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Project: {self.project_var.get()}\n")
            f.write(f"Project License: {self.project_license_var.get()}\n")
            f.write(f"Total Licenses Found: {len(self.project_licenses)}\n\n")
            
            f.write("DETECTED LICENSES:\n")
            f.write("-" * 20 + "\n")
            for entry in self.project_licenses:
                f.write(f"Package: {entry['package']}\n")
                f.write(f"License: {entry['license']}\n")
                f.write(f"Confidence: {entry['confidence']}\n")
                f.write(f"Risk Level: {entry['risk_level']}\n")
                if 'compatibility' in entry:
                    f.write(f"Compatibility: {entry['compatibility']}\n")
                f.write("\n")
    
    def reset_scan_ui(self):
        """Reset UI state after scan completion"""
        self.scan_button.config(state=tk.NORMAL)
        self.is_authorized = False  # Reset authorization


# Tool registration
def create_tool(master):
    return LicenseCompatibilityChecker(master)

if __name__ == "__main__":
    # Test the tool
    root = tk.Tk()
    tool = LicenseCompatibilityChecker(root)
    root.mainloop()