# configuration_drift_detector.py - Monitor configuration changes across environments
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import json
import yaml
import configparser
import hashlib
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from pathlib import Path
import difflib

from base_tool import BaseToolFrame
from utils.security_utils import SecurityToolBase
from utils.database import DatabaseManager

TAB_NAME = "Configuration Drift Detector"

class ToolFrame(BaseToolFrame, SecurityToolBase):
    def __init__(self, master):
        BaseToolFrame.__init__(self, master)
        SecurityToolBase.__init__(self, "ConfigurationDriftDetector")
        
        self.db_manager = DatabaseManager()
        self.environments = {}
        self.baselines = {}
        self.drift_results = []
        self.monitoring_active = False
        self.setup_ui()
        self.load_saved_environments()
        
    def setup_ui(self):
        """Setup the user interface"""
        # Main container
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = ttk.Label(main_frame, text="Configuration Drift Detector", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Environment management frame
        env_frame = ttk.LabelFrame(main_frame, text="Environment Management", padding=10)
        env_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Environment selection
        env_select_frame = ttk.Frame(env_frame)
        env_select_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(env_select_frame, text="Environment:").pack(side=tk.LEFT)
        self.env_var = tk.StringVar()
        self.env_combo = ttk.Combobox(env_select_frame, textvariable=self.env_var,
                                     values=list(self.environments.keys()), width=20)
        self.env_combo.pack(side=tk.LEFT, padx=(10, 5))
        
        ttk.Button(env_select_frame, text="Add Environment", 
                  command=self.add_environment).pack(side=tk.LEFT, padx=(10, 0))
        
        ttk.Button(env_select_frame, text="Remove Environment", 
                  command=self.remove_environment).pack(side=tk.LEFT, padx=(5, 0))
        
        # Configuration path
        path_frame = ttk.Frame(env_frame)
        path_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(path_frame, text="Config Path:").pack(side=tk.LEFT)
        self.config_path_var = tk.StringVar()
        self.config_path_entry = ttk.Entry(path_frame, textvariable=self.config_path_var, width=50)
        self.config_path_entry.pack(side=tk.LEFT, padx=(10, 5), fill=tk.X, expand=True)
        
        ttk.Button(path_frame, text="Browse", 
                  command=self.browse_config_path).pack(side=tk.RIGHT)
        
        # Scan options
        options_frame = ttk.Frame(env_frame)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.recursive_scan_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Recursive scan", 
                       variable=self.recursive_scan_var).pack(side=tk.LEFT)
        
        self.include_hidden_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Include hidden files", 
                       variable=self.include_hidden_var).pack(side=tk.LEFT, padx=(20, 0))
        
        # Control buttons
        button_frame = ttk.Frame(env_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.scan_button = ttk.Button(button_frame, text="Scan Configuration", 
                                     command=self.scan_configuration)
        self.scan_button.pack(side=tk.LEFT)
        
        self.baseline_button = ttk.Button(button_frame, text="Set as Baseline", 
                                         command=self.set_baseline)
        self.baseline_button.pack(side=tk.LEFT, padx=(10, 0))
        
        self.compare_button = ttk.Button(button_frame, text="Compare Environments", 
                                        command=self.compare_environments)
        self.compare_button.pack(side=tk.LEFT, padx=(10, 0))
        
        self.monitor_button = ttk.Button(button_frame, text="Start Monitoring", 
                                        command=self.toggle_monitoring)
        self.monitor_button.pack(side=tk.LEFT, padx=(10, 0))
        
        ttk.Button(button_frame, text="Export Report", 
                  command=self.export_report).pack(side=tk.RIGHT)
        
        # Progress and status
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, 
                                          maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(10, 0))
        
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(main_frame, textvariable=self.status_var)
        status_label.pack(pady=(5, 10))
        
        # Results notebook
        self.results_notebook = ttk.Notebook(main_frame)
        self.results_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Environments tab
        self.setup_environments_tab()
        
        # Drift Analysis tab
        self.setup_drift_tab()
        
        # Configuration Details tab
        self.setup_details_tab()
        
        # Monitoring tab
        self.setup_monitoring_tab()
        
    def setup_environments_tab(self):
        """Setup the environments overview tab"""
        env_tab_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(env_tab_frame, text="Environments")
        
        # Environments treeview
        columns = ("Environment", "Config Files", "Last Scanned", "Baseline", "Status")
        self.env_tree = ttk.Treeview(env_tab_frame, columns=columns, show="headings", height=15)
        
        # Configure columns
        column_widths = {"Environment": 120, "Config Files": 100, "Last Scanned": 120, 
                        "Baseline": 80, "Status": 100}
        
        for col in columns:
            self.env_tree.heading(col, text=col)
            self.env_tree.column(col, width=column_widths.get(col, 100))
        
        # Scrollbars
        env_scrollbar_y = ttk.Scrollbar(env_tab_frame, orient=tk.VERTICAL, 
                                       command=self.env_tree.yview)
        self.env_tree.configure(yscrollcommand=env_scrollbar_y.set)
        
        self.env_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)
        env_scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
        # Bind events
        self.env_tree.bind("<Double-1>", self.show_environment_details)
        
    def setup_drift_tab(self):
        """Setup the drift analysis tab"""
        drift_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(drift_frame, text="Drift Analysis")
        
        # Filter frame
        filter_frame = ttk.Frame(drift_frame)
        filter_frame.pack(fill=tk.X, padx=10, pady=(10, 0))
        
        ttk.Label(filter_frame, text="Filter by severity:").pack(side=tk.LEFT)
        self.severity_filter_var = tk.StringVar(value="All")
        severity_combo = ttk.Combobox(filter_frame, textvariable=self.severity_filter_var,
                                     values=["All", "Critical", "High", "Medium", "Low"],
                                     state="readonly", width=10)
        severity_combo.pack(side=tk.LEFT, padx=(5, 0))
        severity_combo.bind("<<ComboboxSelected>>", self.filter_drift_results)
        
        # Drift results treeview
        columns = ("File", "Environment", "Change Type", "Severity", "Description", "Timestamp")
        self.drift_tree = ttk.Treeview(drift_frame, columns=columns, show="headings", height=12)
        
        # Configure columns
        column_widths = {"File": 150, "Environment": 100, "Change Type": 100, 
                        "Severity": 80, "Description": 200, "Timestamp": 120}
        
        for col in columns:
            self.drift_tree.heading(col, text=col)
            self.drift_tree.column(col, width=column_widths.get(col, 100))
        
        # Scrollbars
        drift_scrollbar_y = ttk.Scrollbar(drift_frame, orient=tk.VERTICAL, 
                                         command=self.drift_tree.yview)
        self.drift_tree.configure(yscrollcommand=drift_scrollbar_y.set)
        
        self.drift_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)
        drift_scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
        # Bind events
        self.drift_tree.bind("<Double-1>", self.show_drift_details)
        
    def setup_details_tab(self):
        """Setup the configuration details tab"""
        details_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(details_frame, text="Configuration Details")
        
        # Configuration viewer
        self.config_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, 
                                                    font=("Courier", 10))
        self.config_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
    def setup_monitoring_tab(self):
        """Setup the monitoring tab"""
        monitor_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(monitor_frame, text="Monitoring")
        
        # Monitoring configuration
        config_frame = ttk.LabelFrame(monitor_frame, text="Monitoring Configuration", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Check interval
        interval_frame = ttk.Frame(config_frame)
        interval_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(interval_frame, text="Check interval:").pack(side=tk.LEFT)
        self.check_interval_var = tk.StringVar(value="60")
        interval_spin = ttk.Spinbox(interval_frame, from_=5, to=1440, 
                                   textvariable=self.check_interval_var, width=10)
        interval_spin.pack(side=tk.LEFT, padx=(10, 5))
        ttk.Label(interval_frame, text="minutes").pack(side=tk.LEFT)
        
        # Alert settings
        self.alert_critical_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(config_frame, text="Alert on critical changes", 
                       variable=self.alert_critical_var).pack(anchor=tk.W)
        
        self.alert_high_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(config_frame, text="Alert on high severity changes", 
                       variable=self.alert_high_var).pack(anchor=tk.W)
        
        # Monitoring log
        log_frame = ttk.LabelFrame(monitor_frame, text="Monitoring Log", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.monitor_log = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=10)
        self.monitor_log.pack(fill=tk.BOTH, expand=True)
        
    def add_environment(self):
        """Add a new environment"""
        dialog = tk.Toplevel(self.master)
        dialog.title("Add Environment")
        dialog.geometry("400x200")
        dialog.transient(self.master)
        dialog.grab_set()
        
        # Environment name
        ttk.Label(dialog, text="Environment Name:").pack(pady=10)
        name_var = tk.StringVar()
        name_entry = ttk.Entry(dialog, textvariable=name_var, width=30)
        name_entry.pack(pady=5)
        
        # Environment description
        ttk.Label(dialog, text="Description:").pack(pady=(10, 0))
        desc_var = tk.StringVar()
        desc_entry = ttk.Entry(dialog, textvariable=desc_var, width=30)
        desc_entry.pack(pady=5)
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=20)
        
        def save_environment():
            name = name_var.get().strip()
            if not name:
                messagebox.showerror("Error", "Environment name is required")
                return
            
            if name in self.environments:
                messagebox.showerror("Error", "Environment already exists")
                return
            
            self.environments[name] = {
                "name": name,
                "description": desc_var.get().strip(),
                "config_files": {},
                "last_scanned": None,
                "is_baseline": False
            }
            
            # Update combo box
            self.env_combo['values'] = list(self.environments.keys())
            self.env_var.set(name)
            
            # Update environments display
            self.update_environments_display()
            
            # Save to file
            self.save_environments()
            
            dialog.destroy()
        
        ttk.Button(button_frame, text="Save", command=save_environment).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        
        name_entry.focus()
    
    def remove_environment(self):
        """Remove selected environment"""
        env_name = self.env_var.get()
        if not env_name:
            messagebox.showerror("Error", "Please select an environment to remove")
            return
        
        if messagebox.askyesno("Confirm", f"Remove environment '{env_name}'?"):
            del self.environments[env_name]
            
            # Remove from baselines if it was a baseline
            if env_name in self.baselines:
                del self.baselines[env_name]
            
            # Update combo box
            self.env_combo['values'] = list(self.environments.keys())
            self.env_var.set("")
            
            # Update display
            self.update_environments_display()
            
            # Save changes
            self.save_environments()
    
    def browse_config_path(self):
        """Browse for configuration path"""
        path_type = messagebox.askyesno("Path Type", 
                                       "Select 'Yes' for directory, 'No' for file")
        
        if path_type:
            path = filedialog.askdirectory(title="Select Configuration Directory")
        else:
            path = filedialog.askopenfilename(
                title="Select Configuration File",
                filetypes=[
                    ("Config files", "*.json;*.yaml;*.yml;*.ini;*.conf;*.cfg"),
                    ("All files", "*.*")
                ]
            )
        
        if path:
            self.config_path_var.set(path)
    
    def scan_configuration(self):
        """Scan configuration for selected environment"""
        env_name = self.env_var.get()
        config_path = self.config_path_var.get().strip()
        
        if not env_name:
            messagebox.showerror("Error", "Please select an environment")
            return
        
        if not config_path or not os.path.exists(config_path):
            messagebox.showerror("Error", "Please specify a valid configuration path")
            return
        
        # Validate target for ethical scanning
        if not self.validate_and_authorize(config_path, "config_scan"):
            messagebox.showerror("Authorization Error", 
                               "Path not authorized for scanning. Check security logs.")
            return
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(target=self.run_config_scan, 
                                           args=(env_name, config_path))
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        # Update UI state
        self.scan_button.config(state=tk.DISABLED)
        self.status_var.set("Scanning configuration...")
        self.progress_var.set(0)
    
    def run_config_scan(self, env_name: str, config_path: str):
        """Run configuration scan"""
        try:
            self.log_security_activity("CONFIG_SCAN_STARTED", 
                                     f"Configuration scan started for {env_name}", config_path)
            
            # Scan configuration files
            config_files = self.discover_config_files(config_path)
            
            # Parse and store configuration data
            parsed_configs = {}
            total_files = len(config_files)
            
            for i, file_path in enumerate(config_files):
                # Update progress
                progress = (i / total_files) * 100
                self.master.after(0, lambda p=progress: self.progress_var.set(p))
                
                try:
                    config_data = self.parse_config_file(file_path)
                    if config_data:
                        relative_path = os.path.relpath(file_path, config_path)
                        parsed_configs[relative_path] = {
                            "content": config_data,
                            "hash": self.calculate_file_hash(file_path),
                            "size": os.path.getsize(file_path),
                            "modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat(),
                            "full_path": file_path
                        }
                except Exception as e:
                    self.log_security_activity("CONFIG_PARSE_ERROR", 
                                             f"Error parsing {file_path}: {str(e)}")
            
            # Update environment data
            self.environments[env_name]["config_files"] = parsed_configs
            self.environments[env_name]["last_scanned"] = datetime.now().isoformat()
            self.environments[env_name]["config_path"] = config_path
            
            # Update UI
            self.master.after(0, self.update_environments_display)
            
            # Save environments
            self.save_environments()
            
            self.log_security_activity("CONFIG_SCAN_COMPLETED", 
                                     f"Scanned {len(parsed_configs)} config files for {env_name}", 
                                     config_path)
            
        except Exception as e:
            self.log_security_activity("CONFIG_SCAN_ERROR", f"Scan error: {str(e)}", config_path)
            self.master.after(0, lambda: messagebox.showerror("Scan Error", str(e)))
        
        finally:
            # Reset UI state
            self.master.after(0, self.reset_scan_ui)
    
    def discover_config_files(self, config_path: str) -> List[str]:
        """Discover configuration files in the given path"""
        config_files = []
        
        # Common configuration file extensions and names
        config_extensions = ['.json', '.yaml', '.yml', '.ini', '.conf', '.cfg', '.properties', '.toml']
        config_names = ['config', 'configuration', 'settings', 'app', 'application']
        
        if os.path.isfile(config_path):
            config_files.append(config_path)
        else:
            if self.recursive_scan_var.get():
                for root, dirs, files in os.walk(config_path):
                    # Skip hidden directories unless specified
                    if not self.include_hidden_var.get():
                        dirs[:] = [d for d in dirs if not d.startswith('.')]
                    
                    for file in files:
                        # Skip hidden files unless specified
                        if not self.include_hidden_var.get() and file.startswith('.'):
                            continue
                        
                        file_path = os.path.join(root, file)
                        
                        # Check if it's a configuration file
                        if (any(file.endswith(ext) for ext in config_extensions) or
                            any(name in file.lower() for name in config_names)):
                            config_files.append(file_path)
            else:
                # Only scan the specified directory
                if os.path.isdir(config_path):
                    for file in os.listdir(config_path):
                        if not self.include_hidden_var.get() and file.startswith('.'):
                            continue
                        
                        file_path = os.path.join(config_path, file)
                        if os.path.isfile(file_path):
                            if (any(file.endswith(ext) for ext in config_extensions) or
                                any(name in file.lower() for name in config_names)):
                                config_files.append(file_path)
        
        return config_files
    
    def parse_config_file(self, file_path: str) -> Optional[Dict]:
        """Parse configuration file based on its format"""
        try:
            file_ext = os.path.splitext(file_path)[1].lower()
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if file_ext in ['.json']:
                return json.loads(content)
            elif file_ext in ['.yaml', '.yml']:
                try:
                    import yaml
                    return yaml.safe_load(content)
                except ImportError:
                    # Fallback to simple parsing if yaml not available
                    return {"raw_content": content}
            elif file_ext in ['.ini', '.conf', '.cfg']:
                config = configparser.ConfigParser()
                config.read_string(content)
                return {section: dict(config[section]) for section in config.sections()}
            elif file_ext in ['.properties']:
                # Simple properties file parsing
                properties = {}
                for line in content.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        properties[key.strip()] = value.strip()
                return properties
            else:
                # For unknown formats, store raw content
                return {"raw_content": content}
                
        except Exception as e:
            self.log_security_activity("CONFIG_PARSE_ERROR", 
                                     f"Error parsing {file_path}: {str(e)}")
            return None
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception:
            return ""
    
    def set_baseline(self):
        """Set current environment as baseline"""
        env_name = self.env_var.get()
        if not env_name:
            messagebox.showerror("Error", "Please select an environment")
            return
        
        if env_name not in self.environments:
            messagebox.showerror("Error", "Environment not found")
            return
        
        if not self.environments[env_name]["config_files"]:
            messagebox.showerror("Error", "Please scan the environment first")
            return
        
        # Set as baseline
        self.baselines[env_name] = {
            "timestamp": datetime.now().isoformat(),
            "config_files": self.environments[env_name]["config_files"].copy()
        }
        
        self.environments[env_name]["is_baseline"] = True
        
        # Update display
        self.update_environments_display()
        
        # Save changes
        self.save_environments()
        
        messagebox.showinfo("Baseline Set", f"Environment '{env_name}' set as baseline")
    
    def compare_environments(self):
        """Compare environments and detect drift"""
        if len(self.environments) < 2:
            messagebox.showerror("Error", "Need at least 2 environments to compare")
            return
        
        # Create comparison dialog
        self.show_comparison_dialog()
    
    def show_comparison_dialog(self):
        """Show environment comparison dialog"""
        dialog = tk.Toplevel(self.master)
        dialog.title("Compare Environments")
        dialog.geometry("400x300")
        dialog.transient(self.master)
        dialog.grab_set()
        
        # Source environment
        ttk.Label(dialog, text="Source Environment (Baseline):").pack(pady=10)
        source_var = tk.StringVar()
        source_combo = ttk.Combobox(dialog, textvariable=source_var,
                                   values=list(self.environments.keys()), width=30)
        source_combo.pack(pady=5)
        
        # Target environment
        ttk.Label(dialog, text="Target Environment:").pack(pady=(10, 0))
        target_var = tk.StringVar()
        target_combo = ttk.Combobox(dialog, textvariable=target_var,
                                   values=list(self.environments.keys()), width=30)
        target_combo.pack(pady=5)
        
        # Comparison options
        options_frame = ttk.LabelFrame(dialog, text="Comparison Options", padding=10)
        options_frame.pack(fill=tk.X, padx=20, pady=20)
        
        compare_content_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Compare content", 
                       variable=compare_content_var).pack(anchor=tk.W)
        
        compare_structure_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Compare structure", 
                       variable=compare_structure_var).pack(anchor=tk.W)
        
        compare_metadata_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Compare metadata", 
                       variable=compare_metadata_var).pack(anchor=tk.W)
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=20)
        
        def run_comparison():
            source_env = source_var.get()
            target_env = target_var.get()
            
            if not source_env or not target_env:
                messagebox.showerror("Error", "Please select both environments")
                return
            
            if source_env == target_env:
                messagebox.showerror("Error", "Please select different environments")
                return
            
            # Run comparison
            self.run_environment_comparison(
                source_env, target_env,
                compare_content_var.get(),
                compare_structure_var.get(),
                compare_metadata_var.get()
            )
            
            dialog.destroy()
        
        ttk.Button(button_frame, text="Compare", command=run_comparison).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def run_environment_comparison(self, source_env: str, target_env: str,
                                 compare_content: bool, compare_structure: bool,
                                 compare_metadata: bool):
        """Run environment comparison and detect drift"""
        try:
            self.drift_results = []
            
            source_configs = self.environments[source_env]["config_files"]
            target_configs = self.environments[target_env]["config_files"]
            
            # Find missing files
            source_files = set(source_configs.keys())
            target_files = set(target_configs.keys())
            
            missing_in_target = source_files - target_files
            missing_in_source = target_files - source_files
            common_files = source_files & target_files
            
            # Report missing files
            for file_path in missing_in_target:
                drift = {
                    "file": file_path,
                    "environment": target_env,
                    "change_type": "Missing File",
                    "severity": "High",
                    "description": f"File exists in {source_env} but missing in {target_env}",
                    "timestamp": datetime.now().isoformat(),
                    "details": {"source_env": source_env, "target_env": target_env}
                }
                self.drift_results.append(drift)
            
            for file_path in missing_in_source:
                drift = {
                    "file": file_path,
                    "environment": target_env,
                    "change_type": "Extra File",
                    "severity": "Medium",
                    "description": f"File exists in {target_env} but not in {source_env}",
                    "timestamp": datetime.now().isoformat(),
                    "details": {"source_env": source_env, "target_env": target_env}
                }
                self.drift_results.append(drift)
            
            # Compare common files
            for file_path in common_files:
                source_file = source_configs[file_path]
                target_file = target_configs[file_path]
                
                # Compare content
                if compare_content:
                    if source_file["hash"] != target_file["hash"]:
                        severity = self.assess_change_severity(source_file["content"], 
                                                             target_file["content"])
                        drift = {
                            "file": file_path,
                            "environment": target_env,
                            "change_type": "Content Change",
                            "severity": severity,
                            "description": f"Configuration content differs between environments",
                            "timestamp": datetime.now().isoformat(),
                            "details": {
                                "source_env": source_env,
                                "target_env": target_env,
                                "source_hash": source_file["hash"],
                                "target_hash": target_file["hash"]
                            }
                        }
                        self.drift_results.append(drift)
                
                # Compare metadata
                if compare_metadata:
                    if source_file["size"] != target_file["size"]:
                        drift = {
                            "file": file_path,
                            "environment": target_env,
                            "change_type": "Size Change",
                            "severity": "Low",
                            "description": f"File size differs: {source_file['size']} vs {target_file['size']} bytes",
                            "timestamp": datetime.now().isoformat(),
                            "details": {"source_env": source_env, "target_env": target_env}
                        }
                        self.drift_results.append(drift)
            
            # Update drift display
            self.update_drift_display()
            
            # Switch to drift analysis tab
            self.results_notebook.select(1)
            
            self.status_var.set(f"Comparison complete - Found {len(self.drift_results)} differences")
            
        except Exception as e:
            messagebox.showerror("Comparison Error", f"Error comparing environments: {str(e)}")
    
    def assess_change_severity(self, source_content: Dict, target_content: Dict) -> str:
        """Assess the severity of configuration changes"""
        # This is a simplified assessment
        # In a real implementation, you would have more sophisticated rules
        
        # Critical configuration keys that should trigger high severity
        critical_keys = [
            'password', 'secret', 'key', 'token', 'database', 'db',
            'host', 'port', 'url', 'endpoint', 'security', 'auth'
        ]
        
        def find_critical_changes(obj1, obj2, path=""):
            critical_changes = []
            
            if isinstance(obj1, dict) and isinstance(obj2, dict):
                for key in set(obj1.keys()) | set(obj2.keys()):
                    current_path = f"{path}.{key}" if path else key
                    
                    if key not in obj1:
                        if any(crit in key.lower() for crit in critical_keys):
                            critical_changes.append(f"Added critical key: {current_path}")
                    elif key not in obj2:
                        if any(crit in key.lower() for crit in critical_keys):
                            critical_changes.append(f"Removed critical key: {current_path}")
                    elif obj1[key] != obj2[key]:
                        if any(crit in key.lower() for crit in critical_keys):
                            critical_changes.append(f"Changed critical key: {current_path}")
                        else:
                            critical_changes.extend(find_critical_changes(obj1[key], obj2[key], current_path))
            
            return critical_changes
        
        critical_changes = find_critical_changes(source_content, target_content)
        
        if critical_changes:
            return "Critical"
        
        # Count total changes
        source_str = json.dumps(source_content, sort_keys=True)
        target_str = json.dumps(target_content, sort_keys=True)
        
        diff_ratio = difflib.SequenceMatcher(None, source_str, target_str).ratio()
        
        if diff_ratio < 0.7:  # More than 30% different
            return "High"
        elif diff_ratio < 0.9:  # More than 10% different
            return "Medium"
        else:
            return "Low"    

    def update_environments_display(self):
        """Update the environments display"""
        # Clear previous entries
        for item in self.env_tree.get_children():
            self.env_tree.delete(item)
        
        # Add environments to tree
        for env_name, env_data in self.environments.items():
            config_count = len(env_data.get("config_files", {}))
            last_scanned = env_data.get("last_scanned", "Never")
            if last_scanned != "Never":
                last_scanned = last_scanned[:19]  # Show date and time only
            
            is_baseline = "Yes" if env_data.get("is_baseline", False) else "No"
            status = "Scanned" if config_count > 0 else "Not Scanned"
            
            self.env_tree.insert("", tk.END, values=(
                env_name,
                config_count,
                last_scanned,
                is_baseline,
                status
            ))
    
    def update_drift_display(self):
        """Update the drift analysis display"""
        # Clear previous results
        for item in self.drift_tree.get_children():
            self.drift_tree.delete(item)
        
        # Apply severity filter
        severity_filter = self.severity_filter_var.get()
        
        # Add drift results to tree
        for drift in self.drift_results:
            if (severity_filter == "All" or 
                drift.get("severity") == severity_filter):
                
                self.drift_tree.insert("", tk.END, values=(
                    drift["file"],
                    drift["environment"],
                    drift["change_type"],
                    drift["severity"],
                    drift["description"][:50] + "...",
                    drift["timestamp"][:19]  # Date and time only
                ))
    
    def filter_drift_results(self, event=None):
        """Filter drift results by severity"""
        self.update_drift_display()
    
    def show_environment_details(self, event):
        """Show detailed environment information"""
        selection = self.env_tree.selection()
        if not selection:
            return
        
        item = self.env_tree.item(selection[0])
        values = item['values']
        env_name = values[0]
        
        if env_name in self.environments:
            self.show_environment_popup(env_name)
    
    def show_environment_popup(self, env_name: str):
        """Show detailed environment information in popup"""
        env_data = self.environments[env_name]
        
        popup = tk.Toplevel(self.master)
        popup.title(f"Environment Details - {env_name}")
        popup.geometry("700x600")
        
        # Create notebook for different tabs
        notebook = ttk.Notebook(popup)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # General info tab
        info_frame = ttk.Frame(notebook)
        notebook.add(info_frame, text="General Info")
        
        info_text = scrolledtext.ScrolledText(info_frame, wrap=tk.WORD)
        info_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        info_content = f"Environment Information\n"
        info_content += "=" * 50 + "\n\n"
        info_content += f"Name: {env_name}\n"
        info_content += f"Description: {env_data.get('description', 'N/A')}\n"
        info_content += f"Configuration Files: {len(env_data.get('config_files', {}))}\n"
        info_content += f"Last Scanned: {env_data.get('last_scanned', 'Never')}\n"
        info_content += f"Is Baseline: {'Yes' if env_data.get('is_baseline', False) else 'No'}\n"
        info_content += f"Config Path: {env_data.get('config_path', 'N/A')}\n\n"
        
        config_files = env_data.get("config_files", {})
        if config_files:
            info_content += "Configuration Files:\n"
            info_content += "-" * 25 + "\n"
            for file_path, file_data in config_files.items():
                info_content += f"• {file_path}\n"
                info_content += f"  Size: {file_data.get('size', 0)} bytes\n"
                info_content += f"  Modified: {file_data.get('modified', 'Unknown')}\n"
                info_content += f"  Hash: {file_data.get('hash', 'Unknown')[:16]}...\n\n"
        
        info_text.insert(tk.END, info_content)
        info_text.config(state=tk.DISABLED)
        
        # Configuration files tab
        if config_files:
            files_frame = ttk.Frame(notebook)
            notebook.add(files_frame, text="Configuration Files")
            
            # File list
            file_list_frame = ttk.Frame(files_frame)
            file_list_frame.pack(fill=tk.X, padx=10, pady=10)
            
            ttk.Label(file_list_frame, text="Select file to view:").pack(anchor=tk.W)
            
            file_var = tk.StringVar()
            file_combo = ttk.Combobox(file_list_frame, textvariable=file_var,
                                     values=list(config_files.keys()), width=50)
            file_combo.pack(fill=tk.X, pady=5)
            
            # File content display
            file_text = scrolledtext.ScrolledText(files_frame, wrap=tk.WORD, 
                                                 font=("Courier", 10))
            file_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            def show_file_content(event=None):
                selected_file = file_var.get()
                if selected_file and selected_file in config_files:
                    file_data = config_files[selected_file]
                    content = json.dumps(file_data["content"], indent=2)
                    
                    file_text.delete(1.0, tk.END)
                    file_text.insert(tk.END, content)
            
            file_combo.bind("<<ComboboxSelected>>", show_file_content)
    
    def show_drift_details(self, event):
        """Show detailed drift information"""
        selection = self.drift_tree.selection()
        if not selection:
            return
        
        item = self.drift_tree.item(selection[0])
        values = item['values']
        
        # Find the corresponding drift result
        for drift in self.drift_results:
            if (drift["file"] == values[0] and 
                drift["environment"] == values[1] and
                drift["change_type"] == values[2]):
                
                self.show_drift_popup(drift)
                break
    
    def show_drift_popup(self, drift: Dict):
        """Show detailed drift information in popup"""
        popup = tk.Toplevel(self.master)
        popup.title("Configuration Drift Details")
        popup.geometry("700x600")
        
        text_widget = scrolledtext.ScrolledText(popup, wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        details = f"Configuration Drift Details\n"
        details += "=" * 50 + "\n\n"
        details += f"File: {drift['file']}\n"
        details += f"Environment: {drift['environment']}\n"
        details += f"Change Type: {drift['change_type']}\n"
        details += f"Severity: {drift['severity']}\n"
        details += f"Timestamp: {drift['timestamp']}\n\n"
        details += f"Description:\n{drift['description']}\n\n"
        
        # Show additional details if available
        if 'details' in drift:
            drift_details = drift['details']
            details += "Additional Details:\n"
            details += "-" * 20 + "\n"
            for key, value in drift_details.items():
                details += f"{key}: {value}\n"
            details += "\n"
        
        # If it's a content change, show diff
        if drift['change_type'] == 'Content Change' and 'details' in drift:
            details += "Recommended Actions:\n"
            details += "-" * 20 + "\n"
            if drift['severity'] == 'Critical':
                details += "• IMMEDIATE ACTION REQUIRED\n"
                details += "• Review security implications\n"
                details += "• Verify authorized changes\n"
            elif drift['severity'] == 'High':
                details += "• Review changes promptly\n"
                details += "• Update documentation\n"
            else:
                details += "• Review during next maintenance window\n"
            
            details += "• Consider updating baseline if changes are intentional\n"
        
        text_widget.insert(tk.END, details)
        text_widget.config(state=tk.DISABLED)
    
    def toggle_monitoring(self):
        """Toggle configuration monitoring"""
        if not self.monitoring_active:
            self.start_monitoring()
        else:
            self.stop_monitoring()
    
    def start_monitoring(self):
        """Start continuous monitoring"""
        if not self.environments:
            messagebox.showerror("Error", "No environments configured for monitoring")
            return
        
        self.monitoring_active = True
        self.monitor_button.config(text="Stop Monitoring")
        
        # Log monitoring start
        self.log_monitoring("Configuration monitoring started")
        
        # Schedule first check
        self.schedule_next_check()
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.monitoring_active = False
        self.monitor_button.config(text="Start Monitoring")
        
        # Log monitoring stop
        self.log_monitoring("Configuration monitoring stopped")
    
    def schedule_next_check(self):
        """Schedule the next configuration check"""
        if not self.monitoring_active:
            return
        
        # Get check interval in milliseconds
        interval_minutes = int(self.check_interval_var.get())
        interval_ms = interval_minutes * 60 * 1000
        
        # Schedule next check
        self.master.after(interval_ms, self.perform_scheduled_check)
    
    def perform_scheduled_check(self):
        """Perform scheduled configuration check"""
        if not self.monitoring_active:
            return
        
        self.log_monitoring("Performing scheduled configuration check")
        
        # Check each environment for changes
        changes_detected = False
        
        for env_name, env_data in self.environments.items():
            if env_data.get("config_path") and os.path.exists(env_data["config_path"]):
                try:
                    # Re-scan configuration
                    old_configs = env_data.get("config_files", {})
                    
                    # Discover and parse current config files
                    config_files = self.discover_config_files(env_data["config_path"])
                    new_configs = {}
                    
                    for file_path in config_files:
                        try:
                            config_data = self.parse_config_file(file_path)
                            if config_data:
                                relative_path = os.path.relpath(file_path, env_data["config_path"])
                                new_configs[relative_path] = {
                                    "content": config_data,
                                    "hash": self.calculate_file_hash(file_path),
                                    "size": os.path.getsize(file_path),
                                    "modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat(),
                                    "full_path": file_path
                                }
                        except Exception as e:
                            self.log_monitoring(f"Error parsing {file_path}: {str(e)}")
                    
                    # Compare with previous scan
                    drift_detected = self.detect_configuration_drift(env_name, old_configs, new_configs)
                    
                    if drift_detected:
                        changes_detected = True
                        self.log_monitoring(f"Configuration drift detected in {env_name}")
                        
                        # Send alerts if configured
                        self.send_drift_alerts(env_name, drift_detected)
                    
                    # Update environment data
                    env_data["config_files"] = new_configs
                    env_data["last_scanned"] = datetime.now().isoformat()
                    
                except Exception as e:
                    self.log_monitoring(f"Error checking {env_name}: {str(e)}")
        
        if changes_detected:
            # Update UI
            self.master.after(0, self.update_environments_display)
            self.master.after(0, self.update_drift_display)
        
        # Schedule next check
        self.schedule_next_check()
    
    def detect_configuration_drift(self, env_name: str, old_configs: Dict, 
                                 new_configs: Dict) -> List[Dict]:
        """Detect configuration drift between old and new configs"""
        drift_detected = []
        
        old_files = set(old_configs.keys())
        new_files = set(new_configs.keys())
        
        # Check for new files
        for file_path in new_files - old_files:
            drift = {
                "file": file_path,
                "environment": env_name,
                "change_type": "New File",
                "severity": "Medium",
                "description": f"New configuration file detected: {file_path}",
                "timestamp": datetime.now().isoformat()
            }
            drift_detected.append(drift)
            self.drift_results.append(drift)
        
        # Check for deleted files
        for file_path in old_files - new_files:
            drift = {
                "file": file_path,
                "environment": env_name,
                "change_type": "Deleted File",
                "severity": "High",
                "description": f"Configuration file deleted: {file_path}",
                "timestamp": datetime.now().isoformat()
            }
            drift_detected.append(drift)
            self.drift_results.append(drift)
        
        # Check for modified files
        for file_path in old_files & new_files:
            old_file = old_configs[file_path]
            new_file = new_configs[file_path]
            
            if old_file["hash"] != new_file["hash"]:
                severity = self.assess_change_severity(old_file["content"], new_file["content"])
                drift = {
                    "file": file_path,
                    "environment": env_name,
                    "change_type": "Modified File",
                    "severity": severity,
                    "description": f"Configuration file modified: {file_path}",
                    "timestamp": datetime.now().isoformat(),
                    "details": {
                        "old_hash": old_file["hash"],
                        "new_hash": new_file["hash"],
                        "old_size": old_file["size"],
                        "new_size": new_file["size"]
                    }
                }
                drift_detected.append(drift)
                self.drift_results.append(drift)
        
        return drift_detected
    
    def send_drift_alerts(self, env_name: str, drift_list: List[Dict]):
        """Send alerts for detected configuration drift"""
        critical_drifts = [d for d in drift_list if d["severity"] == "Critical"]
        high_drifts = [d for d in drift_list if d["severity"] == "High"]
        
        if critical_drifts and self.alert_critical_var.get():
            self.log_monitoring(f"CRITICAL ALERT: {len(critical_drifts)} critical changes in {env_name}")
        
        if high_drifts and self.alert_high_var.get():
            self.log_monitoring(f"HIGH ALERT: {len(high_drifts)} high severity changes in {env_name}")
    
    def log_monitoring(self, message: str):
        """Log monitoring activity"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.monitor_log.insert(tk.END, log_entry)
        self.monitor_log.see(tk.END)
        
        # Also log to security audit
        self.log_security_activity("CONFIG_MONITORING", message)
    
    def export_report(self):
        """Export configuration drift report"""
        if not self.environments and not self.drift_results:
            messagebox.showwarning("No Data", "No configuration data to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Export Configuration Report",
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
                "total_environments": len(self.environments),
                "total_drift_results": len(self.drift_results)
            },
            "environments": self.environments,
            "baselines": self.baselines,
            "drift_results": self.drift_results
        }
        
        with open(file_path, 'w') as f:
            json.dump(report_data, f, indent=2)
    
    def export_csv_report(self, file_path: str):
        """Export drift results as CSV"""
        import csv
        
        with open(file_path, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                "File", "Environment", "Change Type", "Severity", 
                "Description", "Timestamp"
            ])
            
            # Write drift data
            for drift in self.drift_results:
                writer.writerow([
                    drift["file"],
                    drift["environment"],
                    drift["change_type"],
                    drift["severity"],
                    drift["description"],
                    drift["timestamp"]
                ])
    
    def export_text_report(self, file_path: str):
        """Export report as text"""
        with open(file_path, 'w') as f:
            f.write("CONFIGURATION DRIFT REPORT\n")
            f.write("=" * 40 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Environments: {len(self.environments)}\n")
            f.write(f"Total Drift Results: {len(self.drift_results)}\n\n")
            
            # Environment summary
            f.write("ENVIRONMENTS:\n")
            f.write("-" * 15 + "\n")
            for env_name, env_data in self.environments.items():
                f.write(f"• {env_name}\n")
                f.write(f"  Config Files: {len(env_data.get('config_files', {}))}\n")
                f.write(f"  Last Scanned: {env_data.get('last_scanned', 'Never')}\n")
                f.write(f"  Is Baseline: {'Yes' if env_data.get('is_baseline', False) else 'No'}\n\n")
            
            # Drift results
            if self.drift_results:
                f.write("DRIFT RESULTS:\n")
                f.write("-" * 15 + "\n")
                for i, drift in enumerate(self.drift_results, 1):
                    f.write(f"{i}. {drift['file']} ({drift['environment']})\n")
                    f.write(f"   Type: {drift['change_type']}\n")
                    f.write(f"   Severity: {drift['severity']}\n")
                    f.write(f"   Description: {drift['description']}\n")
                    f.write(f"   Timestamp: {drift['timestamp']}\n\n")
    
    def save_environments(self):
        """Save environments to file"""
        try:
            save_data = {
                "environments": self.environments,
                "baselines": self.baselines
            }
            
            # Create .kiro directory if it doesn't exist
            os.makedirs(".kiro", exist_ok=True)
            
            with open(".kiro/config_environments.json", 'w') as f:
                json.dump(save_data, f, indent=2)
                
        except Exception as e:
            self.log_security_activity("SAVE_ERROR", f"Error saving environments: {str(e)}")
    
    def load_saved_environments(self):
        """Load saved environments from file"""
        try:
            if os.path.exists(".kiro/config_environments.json"):
                with open(".kiro/config_environments.json", 'r') as f:
                    save_data = json.load(f)
                
                self.environments = save_data.get("environments", {})
                self.baselines = save_data.get("baselines", {})
                
                # Update UI
                if self.environments:
                    self.env_combo['values'] = list(self.environments.keys())
                    self.update_environments_display()
                    
        except Exception as e:
            self.log_security_activity("LOAD_ERROR", f"Error loading environments: {str(e)}")
            # Initialize empty if load fails
            self.environments = {}
            self.baselines = {}
    
    def reset_scan_ui(self):
        """Reset UI state after scan completion"""
        self.scan_button.config(state=tk.NORMAL)
        self.is_authorized = False  # Reset authorization


# Tool registration
def create_tool(master):
    return ConfigurationDriftDetector(master)

if __name__ == "__main__":
    # Test the tool
    root = tk.Tk()
    tool = ConfigurationDriftDetector(root)
    root.mainloop()