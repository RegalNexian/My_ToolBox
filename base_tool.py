# base_tool.py — Sci-Fi styled base for all tools
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
import csv
import os
from theme import BG_COLOR, TEXT_COLOR, style_button
from utils.database import db_manager
from utils.security_utils import security_utils

class BaseToolFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=BG_COLOR)
        self.results_data = {}
        self.progress_var = None
        self.progress_bar = None

    def add_label(self, text, font=("Consolas", 12, "bold")):
        label = tk.Label(self, text=text, bg=BG_COLOR, fg=TEXT_COLOR, font=font)
        label.pack(pady=5)
        return label

    def add_button(self, text, command):
        btn = tk.Button(self, text=text, command=command)
        style_button(btn)
        btn.pack(pady=5)
        return btn

    def add_entry(self, width=40):
        entry = tk.Entry(self, bg="#111111", fg=TEXT_COLOR, insertbackground=TEXT_COLOR, width=width)
        entry.pack(pady=5)
        return entry

    def add_textbox(self, width=60, height=10):
        text_box = tk.Text(self, bg="#111111", fg=TEXT_COLOR, insertbackground=TEXT_COLOR,
                           width=width, height=height, wrap="word")
        text_box.pack(pady=5)
        return text_box

    def add_progress_bar(self, label_text="Progress"):
        """Add progress bar components for long-running operations"""
        progress_frame = tk.Frame(self, bg=BG_COLOR)
        progress_frame.pack(pady=5, fill="x", padx=10)
        
        # Progress label
        progress_label = tk.Label(progress_frame, text=label_text, 
                                bg=BG_COLOR, fg=TEXT_COLOR, font=("Consolas", 10))
        progress_label.pack(anchor="w")
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, 
                                          maximum=100, length=300)
        self.progress_bar.pack(fill="x", pady=2)
        
        # Progress percentage label
        self.progress_percent_label = tk.Label(progress_frame, text="0%", 
                                             bg=BG_COLOR, fg=TEXT_COLOR, font=("Consolas", 9))
        self.progress_percent_label.pack(anchor="e")
        
        return self.progress_bar

    def update_progress(self, value, status_text=""):
        """Update progress bar value and status"""
        if self.progress_var:
            self.progress_var.set(value)
            self.progress_percent_label.config(text=f"{value:.1f}%")
            if status_text:
                self.progress_percent_label.config(text=f"{value:.1f}% - {status_text}")
            self.update_idletasks()

    def add_results_viewer(self, tabs_config=None):
        """Implement tabbed results viewer for complex outputs"""
        if tabs_config is None:
            tabs_config = ["Summary", "Details", "Raw Data"]
        
        # Create notebook for tabs
        self.results_notebook = ttk.Notebook(self)
        self.results_notebook.pack(fill="both", expand=True, pady=10, padx=10)
        
        # Store tab frames for later access
        self.tab_frames = {}
        
        for tab_name in tabs_config:
            # Create frame for each tab
            tab_frame = tk.Frame(self.results_notebook, bg=BG_COLOR)
            self.results_notebook.add(tab_frame, text=tab_name)
            
            # Add scrollable text widget to each tab
            text_widget = tk.Text(tab_frame, bg="#111111", fg=TEXT_COLOR, 
                                insertbackground=TEXT_COLOR, wrap="word")
            scrollbar = tk.Scrollbar(tab_frame, orient="vertical", command=text_widget.yview)
            text_widget.configure(yscrollcommand=scrollbar.set)
            
            text_widget.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            self.tab_frames[tab_name] = text_widget
        
        return self.results_notebook

    def update_results_tab(self, tab_name, content):
        """Update content in a specific results tab"""
        if tab_name in self.tab_frames:
            text_widget = self.tab_frames[tab_name]
            text_widget.delete(1.0, tk.END)
            text_widget.insert(1.0, content)

    def add_export_options(self):
        """Create export functionality for multiple file formats"""
        export_frame = tk.Frame(self, bg=BG_COLOR)
        export_frame.pack(pady=10, fill="x", padx=10)
        
        export_label = tk.Label(export_frame, text="Export Results:", 
                              bg=BG_COLOR, fg=TEXT_COLOR, font=("Consolas", 10, "bold"))
        export_label.pack(anchor="w")
        
        button_frame = tk.Frame(export_frame, bg=BG_COLOR)
        button_frame.pack(fill="x", pady=5)
        
        # Export buttons
        json_btn = tk.Button(button_frame, text="Export JSON", 
                           command=lambda: self.export_results("json"))
        style_button(json_btn)
        json_btn.pack(side="left", padx=5)
        
        csv_btn = tk.Button(button_frame, text="Export CSV", 
                          command=lambda: self.export_results("csv"))
        style_button(csv_btn)
        csv_btn.pack(side="left", padx=5)
        
        txt_btn = tk.Button(button_frame, text="Export TXT", 
                          command=lambda: self.export_results("txt"))
        style_button(txt_btn)
        txt_btn.pack(side="left", padx=5)
        
        return export_frame

    def set_results_data(self, data):
        """Set the results data for export"""
        self.results_data = data

    def export_results(self, format_type):
        """Export results in specified format"""
        if not self.results_data:
            messagebox.showwarning("No Data", "No results data available for export.")
            return
        
        # File dialog for save location
        file_extensions = {
            "json": [("JSON files", "*.json")],
            "csv": [("CSV files", "*.csv")],
            "txt": [("Text files", "*.txt")]
        }
        
        filename = filedialog.asksaveasfilename(
            defaultextension=f".{format_type}",
            filetypes=file_extensions.get(format_type, [("All files", "*.*")])
        )
        
        if not filename:
            return
        
        try:
            if format_type == "json":
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.results_data, f, indent=2, ensure_ascii=False)
            
            elif format_type == "csv":
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    if isinstance(self.results_data, dict):
                        # Convert dict to CSV format
                        writer = csv.writer(f)
                        writer.writerow(["Key", "Value"])
                        for key, value in self.results_data.items():
                            writer.writerow([key, str(value)])
                    elif isinstance(self.results_data, list):
                        # Handle list of dictionaries
                        if self.results_data and isinstance(self.results_data[0], dict):
                            writer = csv.DictWriter(f, fieldnames=self.results_data[0].keys())
                            writer.writeheader()
                            writer.writerows(self.results_data)
                        else:
                            writer = csv.writer(f)
                            for item in self.results_data:
                                writer.writerow([str(item)])
            
            elif format_type == "txt":
                with open(filename, 'w', encoding='utf-8') as f:
                    if isinstance(self.results_data, (dict, list)):
                        f.write(json.dumps(self.results_data, indent=2, ensure_ascii=False))
                    else:
                        f.write(str(self.results_data))
            
            messagebox.showinfo("Export Successful", f"Results exported to {filename}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export results: {str(e)}")


class AdvancedToolFrame(BaseToolFrame):
    """Enhanced BaseToolFrame with advanced capabilities for complex tools"""
    
    def __init__(self, master, tool_config=None):
        super().__init__(master)
        self.config = tool_config or {}
        self.tool_name = self.config.get('name', 'Advanced Tool')
        self.tool_id = self.config.get('tool_id', self.tool_name.lower().replace(' ', '_'))
        
        # Load tool configuration from database
        self.load_tool_config()
        
    def load_tool_config(self):
        """Load tool configuration from database"""
        try:
            saved_config = db_manager.get_tool_config(self.tool_id)
            if saved_config:
                self.config.update(saved_config)
        except Exception as e:
            print(f"Error loading tool config: {e}")
    
    def save_tool_config(self):
        """Save current tool configuration to database"""
        try:
            db_manager.save_tool_config(
                tool_id=self.tool_id,
                name=self.tool_name,
                category=self.config.get('category', 'General'),
                config_data=self.config.get('config_data', {}),
                user_preferences=self.config.get('user_preferences', {})
            )
        except Exception as e:
            print(f"Error saving tool config: {e}")
        
    def setup_advanced_ui(self):
        """Setup advanced UI components including progress bar, results viewer, and export options"""
        # Add progress bar
        self.add_progress_bar(f"{self.tool_name} Progress")
        
        # Add results viewer with default tabs
        self.add_results_viewer(["Summary", "Details", "Analysis", "Raw Data"])
        
        # Add export options
        self.add_export_options()
        
    def run_with_progress(self, operation_func, *args, **kwargs):
        """Run an operation with progress tracking"""
        try:
            self.update_progress(0, "Starting...")
            result = operation_func(*args, **kwargs)
            self.update_progress(100, "Complete")
            return result
        except Exception as e:
            self.update_progress(0, f"Error: {str(e)}")
            raise
    
    def save_analysis_result(self, analysis_id, input_data, results_summary, 
                           detailed_findings=None, recommendations=None, metrics=None):
        """Save analysis results to database"""
        try:
            db_manager.save_analysis_result(
                analysis_id=analysis_id,
                tool_id=self.tool_id,
                input_data=input_data,
                results_summary=results_summary,
                detailed_findings=detailed_findings,
                recommendations=recommendations,
                metrics=metrics,
                export_formats=["json", "csv", "txt"]
            )
        except Exception as e:
            print(f"Error saving analysis result: {e}")
    
    def load_analysis_history(self, limit=10):
        """Load recent analysis results from database"""
        try:
            return db_manager.get_analysis_results(tool_id=self.tool_id, limit=limit)
        except Exception as e:
            print(f"Error loading analysis history: {e}")
            return []
    
    def save_tool_state(self, state_name, state_data):
        """Save current tool state"""
        try:
            db_manager.save_tool_state(self.tool_id, state_name, state_data)
        except Exception as e:
            print(f"Error saving tool state: {e}")


class SecurityToolFrame(AdvancedToolFrame):
    """Enhanced tool frame for security tools with ethical validation"""
    
    def __init__(self, master, tool_config=None):
        super().__init__(master, tool_config)
        self.security_base = None
        
    def setup_security_framework(self):
        """Setup security framework with ethical validation"""
        from utils.security_utils import SecurityToolBase
        self.security_base = SecurityToolBase(self.tool_name)
        
        # Add security validation UI
        self.add_security_validation_ui()
    
    def add_security_validation_ui(self):
        """Add UI components for security validation"""
        security_frame = tk.Frame(self, bg=BG_COLOR)
        security_frame.pack(fill="x", padx=10, pady=5)
        
        # Security notice
        notice_label = tk.Label(security_frame, 
                              text="⚠️ Security Tool - Ethical Use Required", 
                              bg=BG_COLOR, fg="#FF6B6B", 
                              font=("Consolas", 10, "bold"))
        notice_label.pack(anchor="w")
        
        # Target validation
        target_frame = tk.Frame(security_frame, bg=BG_COLOR)
        target_frame.pack(fill="x", pady=2)
        
        tk.Label(target_frame, text="Target:", bg=BG_COLOR, fg=TEXT_COLOR).pack(side="left")
        self.target_entry = tk.Entry(target_frame, bg="#111111", fg=TEXT_COLOR, 
                                   insertbackground=TEXT_COLOR, width=30)
        self.target_entry.pack(side="left", padx=5)
        
        validate_btn = tk.Button(target_frame, text="Validate Target", 
                               command=self.validate_target)
        style_button(validate_btn)
        validate_btn.pack(side="left", padx=5)
        
        # Authorization status
        self.auth_status_label = tk.Label(security_frame, text="Status: Not Authorized", 
                                        bg=BG_COLOR, fg="#FF6B6B", font=("Consolas", 9))
        self.auth_status_label.pack(anchor="w")
    
    def validate_target(self):
        """Validate target for security operations"""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("Invalid Target", "Please enter a target.")
            return
        
        operation = f"{self.tool_name}_scan"
        
        if self.security_base.validate_and_authorize(target, operation):
            self.auth_status_label.config(text="Status: Authorized ✓", fg="#4ECDC4")
            messagebox.showinfo("Authorization", "Target validated and authorized for security operations.")
        else:
            self.auth_status_label.config(text="Status: Not Authorized ✗", fg="#FF6B6B")
            messagebox.showwarning("Authorization Failed", 
                                 "Target validation failed. Check logs for details.")
    
    def require_authorization(self, func):
        """Decorator to require authorization before security operations"""
        def wrapper(*args, **kwargs):
            if not self.security_base or not self.security_base.is_authorized:
                messagebox.showerror("Authorization Required", 
                                   "Please validate target before running security operations.")
                return None
            return func(*args, **kwargs)
        return wrapper
    
    def log_security_activity(self, action, details, target=""):
        """Log security activity"""
        if self.security_base:
            self.security_base.log_security_activity(action, details, target)
