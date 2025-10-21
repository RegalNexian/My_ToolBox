# test_coverage_gap_analyzer.py - Test coverage gap analysis and improvement suggestions tool
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import ast
import subprocess
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Any, Optional, Tuple, Set
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
from base_tool import AdvancedToolFrame
from utils.database import db_manager

TAB_NAME = "Test Coverage Gap Analyzer"

class ToolFrame(AdvancedToolFrame):
    """Test coverage gap analysis and improvement suggestions tool"""
    
    def __init__(self, master):
        tool_config = {
            'name': 'Test Coverage Gap Analyzer',
            'tool_id': 'test_coverage_gap_analyzer',
            'category': 'Project Management'
        }
        super().__init__(master, tool_config)
        
        self.project_path = ""
        self.coverage_data = {}
        self.source_files = []
        self.test_files = []
        self.coverage_gaps = []
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface"""
        self.add_label("🎯 Test Coverage Gap Analyzer", ("Consolas", 16, "bold"))
        self.add_label("Identify uncovered code paths and generate targeted test suggestions")
        
        # Setup advanced UI components
        self.setup_advanced_ui()
        
        # Project selection
        project_frame = tk.Frame(self, bg=self.master.cget('bg'))
        project_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(project_frame, text="Project Directory:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.project_path_var = tk.StringVar()
        project_entry = tk.Entry(project_frame, textvariable=self.project_path_var, width=50)
        project_entry.pack(side="left", padx=5, fill="x", expand=True)
        
        browse_btn = tk.Button(project_frame, text="Browse", command=self.browse_project)
        browse_btn.pack(side="right", padx=5)
        
        # Analysis options
        options_frame = tk.LabelFrame(self, text="Analysis Options", 
                                     bg=self.master.cget('bg'), fg="white")
        options_frame.pack(fill="x", padx=10, pady=5)
        
        # Coverage tool selection
        tool_frame = tk.Frame(options_frame, bg=self.master.cget('bg'))
        tool_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(tool_frame, text="Coverage Tool:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.coverage_tool = tk.StringVar(value="coverage.py")
        tool_combo = ttk.Combobox(tool_frame, textvariable=self.coverage_tool,
                                 values=["coverage.py", "pytest-cov", "existing_report"],
                                 state="readonly", width=20)
        tool_combo.pack(side="left", padx=5)
        
        # Test command
        cmd_frame = tk.Frame(options_frame, bg=self.master.cget('bg'))
        cmd_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(cmd_frame, text="Test Command:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.test_command_var = tk.StringVar(value="python -m pytest")
        cmd_entry = tk.Entry(cmd_frame, textvariable=self.test_command_var, width=40)
        cmd_entry.pack(side="left", padx=5, fill="x", expand=True)
        
        # Coverage thresholds
        threshold_frame = tk.Frame(options_frame, bg=self.master.cget('bg'))
        threshold_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(threshold_frame, text="Min Coverage %:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.min_coverage_var = tk.StringVar(value="80")
        tk.Entry(threshold_frame, textvariable=self.min_coverage_var, width=10).pack(side="left", padx=5)
        
        tk.Label(threshold_frame, text="Critical Coverage %:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left", padx=(20, 0))
        
        self.critical_coverage_var = tk.StringVar(value="60")
        tk.Entry(threshold_frame, textvariable=self.critical_coverage_var, width=10).pack(side="left", padx=5)
        
        # Analysis types
        analysis_frame = tk.Frame(options_frame, bg=self.master.cget('bg'))
        analysis_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(analysis_frame, text="Include:", bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.analyze_lines = tk.BooleanVar(value=True)
        self.analyze_branches = tk.BooleanVar(value=True)
        self.analyze_functions = tk.BooleanVar(value=True)
        self.analyze_complexity = tk.BooleanVar(value=True)
        
        tk.Checkbutton(analysis_frame, text="Line Coverage", variable=self.analyze_lines,
                      bg=self.master.cget('bg'), fg="white", selectcolor="#333333").pack(side="left", padx=5)
        tk.Checkbutton(analysis_frame, text="Branch Coverage", variable=self.analyze_branches,
                      bg=self.master.cget('bg'), fg="white", selectcolor="#333333").pack(side="left", padx=5)
        tk.Checkbutton(analysis_frame, text="Function Coverage", variable=self.analyze_functions,
                      bg=self.master.cget('bg'), fg="white", selectcolor="#333333").pack(side="left", padx=5)
        tk.Checkbutton(analysis_frame, text="Complexity Analysis", variable=self.analyze_complexity,
                      bg=self.master.cget('bg'), fg="white", selectcolor="#333333").pack(side="left", padx=5)
        
        # Existing coverage report
        report_frame = tk.Frame(options_frame, bg=self.master.cget('bg'))
        report_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(report_frame, text="Coverage Report File:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.coverage_report_var = tk.StringVar()
        report_entry = tk.Entry(report_frame, textvariable=self.coverage_report_var, width=40)
        report_entry.pack(side="left", padx=5, fill="x", expand=True)
        
        tk.Button(report_frame, text="Browse", command=self.browse_coverage_report).pack(side="right", padx=5)
        
        # Action buttons
        button_frame = tk.Frame(self, bg=self.master.cget('bg'))
        button_frame.pack(fill="x", padx=10, pady=10)
        
        self.scan_btn = self.add_button("Scan Project", self.scan_project)
        self.run_coverage_btn = self.add_button("Run Coverage Analysis", self.run_coverage_analysis)
        self.analyze_gaps_btn = self.add_button("Analyze Coverage Gaps", self.analyze_coverage_gaps)
        self.generate_tests_btn = self.add_button("Generate Test Suggestions", self.generate_test_suggestions)
        
        self.run_coverage_btn.config(state="disabled")
        self.analyze_gaps_btn.config(state="disabled")
        self.generate_tests_btn.config(state="disabled")
        
        # Status label
        self.status_label = tk.Label(self, text="Status: Ready", 
                                   bg=self.master.cget('bg'), fg="white")
        self.status_label.pack(pady=5)
    
    def browse_project(self):
        """Browse for project directory"""
        directory = filedialog.askdirectory(title="Select Project Directory")
        if directory:
            self.project_path_var.set(directory)
            self.project_path = directory
    
    def browse_coverage_report(self):
        """Browse for existing coverage report"""
        filename = filedialog.askopenfilename(
            title="Select Coverage Report",
            filetypes=[("XML files", "*.xml"), ("JSON files", "*.json"), 
                      ("Coverage files", "*.coverage"), ("All files", "*.*")]
        )
        if filename:
            self.coverage_report_var.set(filename)
    
    def scan_project(self):
        """Scan project for source and test files"""
        if not self.project_path:
            messagebox.showwarning("Warning", "Please select a project directory first")
            return
        
        try:
            self.update_progress(10, "Scanning project structure")
            self.status_label.config(text="Status: Scanning project...")
            
            self.source_files = []
            self.test_files = []
            
            # Walk through project directory
            for root, dirs, files in os.walk(self.project_path):
                # Skip common non-source directories
                dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', '.pytest_cache', 
                                                       'node_modules', '.venv', 'venv']]
                
                for file in files:
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, self.project_path)
                    
                    if file.endswith('.py'):
                        if 'test' in file.lower() or 'test' in root.lower():
                            self.test_files.append(relative_path)
                        else:
                            self.source_files.append(relative_path)
            
            self.update_progress(50, "Analyzing project structure")
            
            # Display scan results
            scan_results = f"""Project Scan Results
{'='*40}

Project Path: {self.project_path}
Source Files: {len(self.source_files)}
Test Files: {len(self.test_files)}

Source Files Found:
"""
            
            for source_file in self.source_files[:20]:  # Show first 20
                scan_results += f"• {source_file}\n"
            
            if len(self.source_files) > 20:
                scan_results += f"... and {len(self.source_files) - 20} more files\n"
            
            scan_results += f"\nTest Files Found:\n"
            for test_file in self.test_files[:10]:  # Show first 10
                scan_results += f"• {test_file}\n"
            
            if len(self.test_files) > 10:
                scan_results += f"... and {len(self.test_files) - 10} more files\n"
            
            self.update_results_tab("Summary", scan_results)
            
            # Enable next step
            self.run_coverage_btn.config(state="normal")
            
            self.update_progress(100, "Project scan complete")
            self.status_label.config(text="Status: Project scanned successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Project scan failed: {str(e)}")
            self.update_progress(0, f"Error: {str(e)}")
    
    def run_coverage_analysis(self):
        """Run coverage analysis using selected tool"""
        if not self.source_files:
            messagebox.showwarning("Warning", "Please scan project first")
            return
        
        try:
            self.update_progress(10, "Starting coverage analysis")
            self.status_label.config(text="Status: Running coverage analysis...")
            
            coverage_tool = self.coverage_tool.get()
            
            if coverage_tool == "existing_report":
                self.load_existing_coverage_report()
            else:
                self.run_coverage_tool()
            
            if self.coverage_data:
                self.analyze_gaps_btn.config(state="normal")
                self.update_progress(100, "Coverage analysis complete")
                self.status_label.config(text="Status: Coverage analysis complete")
            else:
                self.update_progress(0, "No coverage data found")
                
        except Exception as e:
            messagebox.showerror("Error", f"Coverage analysis failed: {str(e)}")
            self.update_progress(0, f"Error: {str(e)}")
    
    def load_existing_coverage_report(self):
        """Load existing coverage report"""
        report_file = self.coverage_report_var.get()
        if not report_file or not os.path.exists(report_file):
            raise ValueError("Please select a valid coverage report file")
        
        self.update_progress(30, "Loading coverage report")
        
        if report_file.endswith('.xml'):
            self.coverage_data = self.parse_xml_coverage_report(report_file)
        elif report_file.endswith('.json'):
            self.coverage_data = self.parse_json_coverage_report(report_file)
        else:
            raise ValueError("Unsupported coverage report format")
    
    def parse_xml_coverage_report(self, xml_file: str) -> Dict:
        """Parse XML coverage report (Cobertura format)"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            coverage_data = {
                'files': {},
                'overall_coverage': 0.0,
                'line_coverage': 0.0,
                'branch_coverage': 0.0
            }
            
            # Parse coverage data
            for package in root.findall('.//package'):
                for class_elem in package.findall('classes/class'):
                    filename = class_elem.get('filename', '')
                    
                    # Get line coverage
                    lines = class_elem.findall('lines/line')
                    covered_lines = []
                    missed_lines = []
                    
                    for line in lines:
                        line_num = int(line.get('number', 0))
                        hits = int(line.get('hits', 0))
                        
                        if hits > 0:
                            covered_lines.append(line_num)
                        else:
                            missed_lines.append(line_num)
                    
                    total_lines = len(covered_lines) + len(missed_lines)
                    line_coverage = len(covered_lines) / total_lines * 100 if total_lines > 0 else 0
                    
                    coverage_data['files'][filename] = {
                        'line_coverage': line_coverage,
                        'covered_lines': covered_lines,
                        'missed_lines': missed_lines,
                        'total_lines': total_lines
                    }
            
            return coverage_data
            
        except Exception as e:
            raise ValueError(f"Failed to parse XML coverage report: {str(e)}")
    
    def parse_json_coverage_report(self, json_file: str) -> Dict:
        """Parse JSON coverage report"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            coverage_data = {
                'files': {},
                'overall_coverage': 0.0,
                'line_coverage': 0.0,
                'branch_coverage': 0.0
            }
            
            # Parse coverage.py JSON format
            if 'files' in data:
                for filename, file_data in data['files'].items():
                    executed_lines = file_data.get('executed_lines', [])
                    missing_lines = file_data.get('missing_lines', [])
                    
                    total_lines = len(executed_lines) + len(missing_lines)
                    line_coverage = len(executed_lines) / total_lines * 100 if total_lines > 0 else 0
                    
                    coverage_data['files'][filename] = {
                        'line_coverage': line_coverage,
                        'covered_lines': executed_lines,
                        'missed_lines': missing_lines,
                        'total_lines': total_lines
                    }
            
            # Calculate overall coverage
            if coverage_data['files']:
                total_covered = sum(len(f['covered_lines']) for f in coverage_data['files'].values())
                total_lines = sum(f['total_lines'] for f in coverage_data['files'].values())
                coverage_data['overall_coverage'] = total_covered / total_lines * 100 if total_lines > 0 else 0
            
            return coverage_data
            
        except Exception as e:
            raise ValueError(f"Failed to parse JSON coverage report: {str(e)}")
    
    def run_coverage_tool(self):
        """Run coverage analysis tool"""
        self.update_progress(30, "Running coverage tool")
        
        # Change to project directory
        original_dir = os.getcwd()
        os.chdir(self.project_path)
        
        try:
            coverage_tool = self.coverage_tool.get()
            test_command = self.test_command_var.get()
            
            if coverage_tool == "coverage.py":
                # Run coverage.py
                cmd = f"coverage run -m pytest && coverage json"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    # Load generated coverage.json
                    json_file = os.path.join(self.project_path, 'coverage.json')
                    if os.path.exists(json_file):
                        self.coverage_data = self.parse_json_coverage_report(json_file)
                    else:
                        raise ValueError("Coverage report not generated")
                else:
                    raise ValueError(f"Coverage command failed: {result.stderr}")
                    
            elif coverage_tool == "pytest-cov":
                # Run pytest with coverage
                cmd = f"{test_command} --cov=. --cov-report=json"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    json_file = os.path.join(self.project_path, 'coverage.json')
                    if os.path.exists(json_file):
                        self.coverage_data = self.parse_json_coverage_report(json_file)
                    else:
                        raise ValueError("Coverage report not generated")
                else:
                    raise ValueError(f"Test command failed: {result.stderr}")
            
        finally:
            os.chdir(original_dir)
    
    def analyze_coverage_gaps(self):
        """Analyze coverage gaps and identify priorities"""
        if not self.coverage_data:
            messagebox.showwarning("Warning", "Please run coverage analysis first")
            return
        
        try:
            self.update_progress(10, "Analyzing coverage gaps")
            self.status_label.config(text="Status: Analyzing coverage gaps...")
            
            min_coverage = float(self.min_coverage_var.get())
            critical_coverage = float(self.critical_coverage_var.get())
            
            self.coverage_gaps = []
            
            # Analyze each file
            for filename, file_data in self.coverage_data['files'].items():
                if filename in self.source_files:
                    gap_analysis = self.analyze_file_coverage_gaps(filename, file_data, 
                                                                 min_coverage, critical_coverage)
                    if gap_analysis:
                        self.coverage_gaps.append(gap_analysis)
            
            # Sort gaps by priority
            self.coverage_gaps.sort(key=lambda x: x['priority_score'], reverse=True)
            
            # Display gap analysis results
            self.display_gap_analysis_results()
            
            # Enable test generation
            self.generate_tests_btn.config(state="normal")
            
            self.update_progress(100, "Gap analysis complete")
            self.status_label.config(text="Status: Gap analysis complete")
            
        except Exception as e:
            messagebox.showerror("Error", f"Gap analysis failed: {str(e)}")
            self.update_progress(0, f"Error: {str(e)}")
    
    def analyze_file_coverage_gaps(self, filename: str, file_data: Dict, 
                                  min_coverage: float, critical_coverage: float) -> Optional[Dict]:
        """Analyze coverage gaps for a specific file"""
        try:
            line_coverage = file_data.get('line_coverage', 0)
            missed_lines = file_data.get('missed_lines', [])
            
            # Skip files with good coverage
            if line_coverage >= min_coverage:
                return None
            
            # Calculate priority score
            priority_score = 0
            
            # Coverage deficit
            coverage_deficit = min_coverage - line_coverage
            priority_score += coverage_deficit
            
            # Critical threshold
            if line_coverage < critical_coverage:
                priority_score += 50
            
            # File complexity analysis
            complexity_score = 0
            if self.analyze_complexity.get():
                complexity_score = self.calculate_file_complexity(filename)
                priority_score += complexity_score * 0.1
            
            # Function analysis
            uncovered_functions = []
            if self.analyze_functions.get():
                uncovered_functions = self.identify_uncovered_functions(filename, missed_lines)
                priority_score += len(uncovered_functions) * 5
            
            gap_analysis = {
                'filename': filename,
                'line_coverage': line_coverage,
                'coverage_deficit': coverage_deficit,
                'missed_lines': missed_lines,
                'missed_lines_count': len(missed_lines),
                'priority_score': priority_score,
                'complexity_score': complexity_score,
                'uncovered_functions': uncovered_functions,
                'severity': self.determine_gap_severity(line_coverage, critical_coverage, min_coverage)
            }
            
            return gap_analysis
            
        except Exception as e:
            print(f"Error analyzing file {filename}: {e}")
            return None
    
    def calculate_file_complexity(self, filename: str) -> float:
        """Calculate complexity score for a file"""
        try:
            file_path = os.path.join(self.project_path, filename)
            if not os.path.exists(file_path) or not filename.endswith('.py'):
                return 0
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            complexity_score = 0
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    complexity_score += 2
                elif isinstance(node, ast.ClassDef):
                    complexity_score += 3
                elif isinstance(node, (ast.If, ast.While, ast.For)):
                    complexity_score += 1
                elif isinstance(node, ast.Try):
                    complexity_score += 2
            
            return complexity_score
            
        except Exception:
            return 0
    
    def identify_uncovered_functions(self, filename: str, missed_lines: List[int]) -> List[Dict]:
        """Identify functions that are not covered by tests"""
        try:
            file_path = os.path.join(self.project_path, filename)
            if not os.path.exists(file_path) or not filename.endswith('.py'):
                return []
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            uncovered_functions = []
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    func_start = node.lineno
                    func_end = getattr(node, 'end_lineno', func_start + 10)
                    
                    # Check if function has any missed lines
                    func_missed_lines = [line for line in missed_lines 
                                       if func_start <= line <= func_end]
                    
                    if func_missed_lines:
                        uncovered_functions.append({
                            'name': node.name,
                            'start_line': func_start,
                            'end_line': func_end,
                            'missed_lines': func_missed_lines,
                            'coverage_ratio': 1 - len(func_missed_lines) / max(1, func_end - func_start + 1)
                        })
            
            return uncovered_functions
            
        except Exception:
            return []
    
    def determine_gap_severity(self, coverage: float, critical_threshold: float, 
                              min_threshold: float) -> str:
        """Determine severity of coverage gap"""
        if coverage < critical_threshold:
            return "CRITICAL"
        elif coverage < min_threshold * 0.8:
            return "HIGH"
        elif coverage < min_threshold * 0.9:
            return "MEDIUM"
        else:
            return "LOW"
    
    def display_gap_analysis_results(self):
        """Display coverage gap analysis results"""
        # Summary tab
        summary_text = f"""Coverage Gap Analysis Results
{'='*50}

Overall Coverage: {self.coverage_data.get('overall_coverage', 0):.1f}%
Files Analyzed: {len(self.coverage_data.get('files', {}))}
Coverage Gaps Found: {len(self.coverage_gaps)}

Gap Severity Distribution:
"""
        
        severity_counts = Counter(gap['severity'] for gap in self.coverage_gaps)
        for severity, count in severity_counts.items():
            summary_text += f"• {severity}: {count} files\n"
        
        summary_text += f"\nTop Priority Files:\n"
        for i, gap in enumerate(self.coverage_gaps[:10], 1):
            summary_text += f"{i}. {gap['filename']} - {gap['line_coverage']:.1f}% ({gap['severity']})\n"
        
        self.update_results_tab("Summary", summary_text)
        
        # Details tab
        details_text = "Detailed Gap Analysis:\n\n"
        
        for gap in self.coverage_gaps[:20]:  # Show top 20
            details_text += f"File: {gap['filename']}\n"
            details_text += f"Coverage: {gap['line_coverage']:.1f}%\n"
            details_text += f"Severity: {gap['severity']}\n"
            details_text += f"Missed Lines: {gap['missed_lines_count']}\n"
            details_text += f"Priority Score: {gap['priority_score']:.1f}\n"
            
            if gap['uncovered_functions']:
                details_text += f"Uncovered Functions:\n"
                for func in gap['uncovered_functions'][:5]:
                    details_text += f"  • {func['name']} (lines {func['start_line']}-{func['end_line']})\n"
            
            details_text += "\n" + "-" * 50 + "\n\n"
        
        self.update_results_tab("Details", details_text)
        
        # Create visualizations
        self.create_coverage_visualizations()
        
        # Save analysis results
        self.save_gap_analysis()
    
    def create_coverage_visualizations(self):
        """Create coverage analysis visualizations"""
        try:
            fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(12, 10))
            
            # Overall coverage pie chart
            overall_coverage = self.coverage_data.get('overall_coverage', 0)
            ax1.pie([overall_coverage, 100 - overall_coverage], 
                   labels=['Covered', 'Uncovered'], 
                   colors=['green', 'red'], 
                   autopct='%1.1f%%')
            ax1.set_title(f'Overall Coverage: {overall_coverage:.1f}%')
            
            # Severity distribution
            if self.coverage_gaps:
                severity_counts = Counter(gap['severity'] for gap in self.coverage_gaps)
                severities = list(severity_counts.keys())
                counts = list(severity_counts.values())
                
                colors = {'CRITICAL': 'red', 'HIGH': 'orange', 'MEDIUM': 'yellow', 'LOW': 'lightblue'}
                bar_colors = [colors.get(s, 'gray') for s in severities]
                
                ax2.bar(severities, counts, color=bar_colors, alpha=0.7)
                ax2.set_title('Gap Severity Distribution')
                ax2.set_ylabel('Number of Files')
            
            # Coverage distribution histogram
            if self.coverage_data.get('files'):
                coverages = [f.get('line_coverage', 0) for f in self.coverage_data['files'].values()]
                ax3.hist(coverages, bins=20, alpha=0.7, color='blue')
                ax3.set_xlabel('Coverage Percentage')
                ax3.set_ylabel('Number of Files')
                ax3.set_title('Coverage Distribution')
                ax3.axvline(x=float(self.min_coverage_var.get()), color='red', 
                           linestyle='--', label='Min Threshold')
                ax3.legend()
            
            # Top files by priority
            if self.coverage_gaps:
                top_gaps = self.coverage_gaps[:10]
                filenames = [os.path.basename(gap['filename'])[:20] for gap in top_gaps]
                priorities = [gap['priority_score'] for gap in top_gaps]
                
                ax4.barh(range(len(filenames)), priorities, alpha=0.7)
                ax4.set_yticks(range(len(filenames)))
                ax4.set_yticklabels(filenames)
                ax4.set_xlabel('Priority Score')
                ax4.set_title('Top Priority Files')
            
            plt.tight_layout()
            
        except Exception as e:
            print(f"Visualization error: {e}")
    
    def generate_test_suggestions(self):
        """Generate specific test case suggestions for coverage gaps"""
        if not self.coverage_gaps:
            messagebox.showwarning("Warning", "Please analyze coverage gaps first")
            return
        
        try:
            self.update_progress(10, "Generating test suggestions")
            self.status_label.config(text="Status: Generating test suggestions...")
            
            suggestions = []
            
            for gap in self.coverage_gaps[:10]:  # Focus on top 10 priority files
                file_suggestions = self.generate_file_test_suggestions(gap)
                if file_suggestions:
                    suggestions.extend(file_suggestions)
            
            # Display suggestions
            self.display_test_suggestions(suggestions)
            
            self.update_progress(100, "Test suggestions generated")
            self.status_label.config(text="Status: Test suggestions generated")
            
        except Exception as e:
            messagebox.showerror("Error", f"Test suggestion generation failed: {str(e)}")
            self.update_progress(0, f"Error: {str(e)}")
    
    def generate_file_test_suggestions(self, gap: Dict) -> List[Dict]:
        """Generate test suggestions for a specific file"""
        suggestions = []
        filename = gap['filename']
        
        try:
            file_path = os.path.join(self.project_path, filename)
            if not os.path.exists(file_path) or not filename.endswith('.py'):
                return suggestions
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            # Generate suggestions for uncovered functions
            for func_info in gap.get('uncovered_functions', []):
                func_name = func_info['name']
                
                # Find function node
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef) and node.name == func_name:
                        suggestion = self.create_function_test_suggestion(filename, node, func_info)
                        if suggestion:
                            suggestions.append(suggestion)
                        break
            
            # Generate suggestions for uncovered lines
            missed_lines = gap.get('missed_lines', [])
            if missed_lines:
                line_suggestions = self.create_line_test_suggestions(filename, missed_lines, content)
                suggestions.extend(line_suggestions)
            
        except Exception as e:
            print(f"Error generating suggestions for {filename}: {e}")
        
        return suggestions
    
    def create_function_test_suggestion(self, filename: str, func_node: ast.FunctionDef, 
                                      func_info: Dict) -> Optional[Dict]:
        """Create test suggestion for a specific function"""
        try:
            func_name = func_node.name
            args = [arg.arg for arg in func_node.args.args if arg.arg != 'self']
            
            # Determine test type based on function characteristics
            test_type = "unit_test"
            if func_name.startswith('_'):
                test_type = "private_method_test"
            elif any(keyword in func_name.lower() for keyword in ['init', 'setup', 'config']):
                test_type = "initialization_test"
            elif any(keyword in func_name.lower() for keyword in ['validate', 'check', 'verify']):
                test_type = "validation_test"
            
            # Generate test template
            test_template = self.generate_test_template(func_name, args, test_type)
            
            suggestion = {
                'type': 'function_test',
                'filename': filename,
                'function_name': func_name,
                'test_type': test_type,
                'priority': 'HIGH' if func_info['coverage_ratio'] < 0.5 else 'MEDIUM',
                'description': f"Test for function '{func_name}' with {len(args)} parameters",
                'test_template': test_template,
                'lines_to_cover': func_info['missed_lines']
            }
            
            return suggestion
            
        except Exception:
            return None
    
    def generate_test_template(self, func_name: str, args: List[str], test_type: str) -> str:
        """Generate test template code"""
        class_name = "TestClass"  # Simplified for demo
        
        template = f"""def test_{func_name}(self):
    \"\"\"Test {func_name} function.\"\"\"
    # Arrange
"""
        
        # Add parameter setup based on arguments
        for arg in args:
            if 'id' in arg.lower():
                template += f"    {arg} = 1\n"
            elif 'name' in arg.lower() or 'str' in arg.lower():
                template += f"    {arg} = 'test_value'\n"
            elif 'list' in arg.lower() or 'items' in arg.lower():
                template += f"    {arg} = []\n"
            elif 'dict' in arg.lower() or 'data' in arg.lower():
                template += f"    {arg} = {{}}\n"
            else:
                template += f"    {arg} = None  # TODO: Set appropriate test value\n"
        
        template += f"""
    # Act
    result = {class_name}().{func_name}({', '.join(args)})
    
    # Assert
    assert result is not None  # TODO: Add specific assertions
    # TODO: Add more test cases for edge cases and error conditions
"""
        
        return template
    
    def create_line_test_suggestions(self, filename: str, missed_lines: List[int], 
                                   content: str) -> List[Dict]:
        """Create test suggestions for specific uncovered lines"""
        suggestions = []
        lines = content.split('\n')
        
        # Group consecutive missed lines
        line_groups = []
        current_group = []
        
        for line_num in sorted(missed_lines):
            if current_group and line_num > current_group[-1] + 1:
                line_groups.append(current_group)
                current_group = [line_num]
            else:
                current_group.append(line_num)
        
        if current_group:
            line_groups.append(current_group)
        
        # Generate suggestions for each group
        for group in line_groups[:5]:  # Limit to 5 groups
            if len(group) >= 3:  # Only suggest for significant gaps
                start_line = group[0]
                end_line = group[-1]
                
                # Analyze the code in this range
                code_snippet = '\n'.join(lines[start_line-1:end_line])
                
                suggestion_type = "branch_test"
                if 'if' in code_snippet.lower():
                    suggestion_type = "conditional_test"
                elif 'except' in code_snippet.lower():
                    suggestion_type = "exception_test"
                elif 'else' in code_snippet.lower():
                    suggestion_type = "edge_case_test"
                
                suggestion = {
                    'type': 'line_coverage',
                    'filename': filename,
                    'line_range': f"{start_line}-{end_line}",
                    'suggestion_type': suggestion_type,
                    'priority': 'MEDIUM',
                    'description': f"Cover lines {start_line}-{end_line} ({suggestion_type})",
                    'code_snippet': code_snippet[:200] + "..." if len(code_snippet) > 200 else code_snippet,
                    'lines_to_cover': group
                }
                
                suggestions.append(suggestion)
        
        return suggestions
    
    def display_test_suggestions(self, suggestions: List[Dict]):
        """Display generated test suggestions"""
        # Analysis tab - Test suggestions
        analysis_text = f"""Test Generation Suggestions
{'='*50}

Total Suggestions: {len(suggestions)}

Priority Breakdown:
"""
        
        priority_counts = Counter(s['priority'] for s in suggestions)
        for priority, count in priority_counts.items():
            analysis_text += f"• {priority}: {count} suggestions\n"
        
        analysis_text += f"\nDetailed Suggestions:\n\n"
        
        for i, suggestion in enumerate(suggestions[:20], 1):  # Show top 20
            analysis_text += f"{i}. {suggestion['description']}\n"
            analysis_text += f"   File: {suggestion['filename']}\n"
            analysis_text += f"   Type: {suggestion.get('suggestion_type', suggestion['type'])}\n"
            analysis_text += f"   Priority: {suggestion['priority']}\n"
            
            if 'test_template' in suggestion:
                analysis_text += f"   Template:\n{suggestion['test_template'][:200]}...\n"
            elif 'code_snippet' in suggestion:
                analysis_text += f"   Code: {suggestion['code_snippet'][:100]}...\n"
            
            analysis_text += "\n" + "-" * 40 + "\n\n"
        
        self.update_results_tab("Analysis", analysis_text)
        
        # Save suggestions for export
        self.set_results_data({
            'coverage_data': self.coverage_data,
            'coverage_gaps': self.coverage_gaps,
            'test_suggestions': suggestions
        })
    
    def save_gap_analysis(self):
        """Save gap analysis results to database"""
        try:
            analysis_id = f"coverage_gap_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            input_data = {
                'project_path': self.project_path,
                'coverage_tool': self.coverage_tool.get(),
                'min_coverage_threshold': float(self.min_coverage_var.get()),
                'critical_coverage_threshold': float(self.critical_coverage_var.get())
            }
            
            summary = {
                'overall_coverage': self.coverage_data.get('overall_coverage', 0),
                'files_analyzed': len(self.coverage_data.get('files', {})),
                'gaps_found': len(self.coverage_gaps),
                'critical_gaps': len([g for g in self.coverage_gaps if g['severity'] == 'CRITICAL']),
                'high_priority_gaps': len([g for g in self.coverage_gaps if g['severity'] == 'HIGH'])
            }
            
            recommendations = []
            if self.coverage_gaps:
                recommendations.extend([
                    f"Focus on {len([g for g in self.coverage_gaps if g['severity'] in ['CRITICAL', 'HIGH']])} high-priority files",
                    "Implement suggested test cases to improve coverage",
                    "Set up automated coverage monitoring in CI/CD pipeline"
                ])
            
            self.save_analysis_result(
                analysis_id=analysis_id,
                input_data=input_data,
                results_summary=summary,
                detailed_findings=[],
                recommendations=recommendations,
                metrics={
                    'coverage_data': self.coverage_data,
                    'coverage_gaps': self.coverage_gaps[:50]  # Limit for storage
                }
            )
            
        except Exception as e:
            print(f"Error saving gap analysis: {e}")


def create_test_coverage_gap_analyzer(parent):
    """Factory function to create the Test Coverage Gap Analyzer tool"""
    return TestCoverageGapAnalyzer(parent)