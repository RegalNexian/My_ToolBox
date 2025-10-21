import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from base_tool import AdvancedToolFrame
from theme import style_button, style_label, style_entry, style_textbox, BG_COLOR, PANEL_COLOR, TEXT_COLOR
import ast
import os
import re
import json
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

TAB_NAME = "Technical Debt Calculator"

class TechnicalDebtAnalyzer:
    """Core technical debt analysis engine"""
    
    def __init__(self):
        self.reset_metrics()
        
        # Debt categories and their weights
        self.debt_categories = {
            'code_smells': {'weight': 1.0, 'description': 'Code smells and anti-patterns'},
            'complexity': {'weight': 1.5, 'description': 'High complexity functions and classes'},
            'duplication': {'weight': 1.2, 'description': 'Code duplication'},
            'documentation': {'weight': 0.8, 'description': 'Missing or poor documentation'},
            'testing': {'weight': 1.3, 'description': 'Insufficient test coverage'},
            'security': {'weight': 2.0, 'description': 'Security vulnerabilities'},
            'performance': {'weight': 1.1, 'description': 'Performance issues'},
            'maintainability': {'weight': 1.4, 'description': 'Maintainability issues'}
        }
        
        # Effort estimation factors (hours per issue)
        self.effort_factors = {
            'trivial': 0.5,
            'minor': 2.0,
            'major': 8.0,
            'critical': 24.0,
            'blocker': 40.0
        }
    
    def reset_metrics(self):
        """Reset all metrics for new analysis"""
        self.debt_issues = []
        self.total_debt_score = 0
        self.category_scores = {}
        self.file_metrics = {}
        
    def analyze_file(self, file_path):
        """Analyze a single file for technical debt"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if file_ext == '.py':
                return self._analyze_python_file(file_path, content)
            else:
                return self._analyze_generic_file(file_path, content)
                
        except Exception as e:
            raise Exception(f"Error analyzing file {file_path}: {e}")
    
    def analyze_directory(self, directory_path):
        """Analyze all files in a directory for technical debt"""
        results = []
        code_extensions = ['.py', '.js', '.java', '.cpp', '.c', '.cs', '.php', '.rb', '.go', '.rs']
        
        for root, dirs, files in os.walk(directory_path):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', 'node_modules', '.vscode', '.idea']]
            
            for file in files:
                if any(file.lower().endswith(ext) for ext in code_extensions):
                    file_path = os.path.join(root, file)
                    try:
                        file_result = self.analyze_file(file_path)
                        results.append(file_result)
                    except Exception as e:
                        print(f"Error analyzing {file_path}: {e}")
                        continue
        
        return self._aggregate_results(results)
    
    def _analyze_python_file(self, file_path, content):
        """Analyze Python file using AST parsing"""
        try:
            tree = ast.parse(content, filename=file_path)
            lines = content.split('\n')
            
            issues = []
            
            # Analyze AST nodes
            for node in ast.walk(tree):
                issues.extend(self._check_python_node(node, lines))
            
            # Check for general code smells
            issues.extend(self._check_code_smells(content, lines))
            
            # Check documentation
            issues.extend(self._check_documentation(content, lines))
            
            # Check for security issues
            issues.extend(self._check_security_issues(content, lines))
            
            return self._calculate_file_debt(file_path, issues, len(lines))
            
        except SyntaxError as e:
            return {
                'file_path': file_path,
                'error': f"Syntax error: {e}",
                'debt_score': 0,
                'issues': []
            }
    
    def _analyze_generic_file(self, file_path, content):
        """Generic analysis for non-Python files"""
        lines = content.split('\n')
        issues = []
        
        # Check for general code smells
        issues.extend(self._check_code_smells(content, lines))
        
        # Check documentation
        issues.extend(self._check_documentation(content, lines))
        
        # Check for basic complexity indicators
        issues.extend(self._check_generic_complexity(content, lines))
        
        return self._calculate_file_debt(file_path, issues, len(lines))
    
    def _check_python_node(self, node, lines):
        """Check Python AST node for debt issues"""
        issues = []
        
        # Check function complexity
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            complexity = self._calculate_function_complexity(node)
            if complexity > 10:
                severity = 'major' if complexity > 20 else 'minor'
                issues.append({
                    'category': 'complexity',
                    'severity': severity,
                    'line': node.lineno,
                    'description': f"Function '{node.name}' has high complexity ({complexity})",
                    'suggestion': "Consider breaking this function into smaller, more focused functions"
                })
            
            # Check function length
            if hasattr(node, 'end_lineno') and node.end_lineno:
                func_length = node.end_lineno - node.lineno
                if func_length > 50:
                    severity = 'major' if func_length > 100 else 'minor'
                    issues.append({
                        'category': 'maintainability',
                        'severity': severity,
                        'line': node.lineno,
                        'description': f"Function '{node.name}' is too long ({func_length} lines)",
                        'suggestion': "Break down into smaller functions for better maintainability"
                    })
            
            # Check for missing docstrings
            if not ast.get_docstring(node):
                issues.append({
                    'category': 'documentation',
                    'severity': 'minor',
                    'line': node.lineno,
                    'description': f"Function '{node.name}' lacks documentation",
                    'suggestion': "Add docstring to explain function purpose and parameters"
                })
        
        # Check class issues
        elif isinstance(node, ast.ClassDef):
            # Check for missing docstrings
            if not ast.get_docstring(node):
                issues.append({
                    'category': 'documentation',
                    'severity': 'minor',
                    'line': node.lineno,
                    'description': f"Class '{node.name}' lacks documentation",
                    'suggestion': "Add docstring to explain class purpose and usage"
                })
            
            # Check for too many methods
            methods = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            if len(methods) > 20:
                issues.append({
                    'category': 'maintainability',
                    'severity': 'major',
                    'line': node.lineno,
                    'description': f"Class '{node.name}' has too many methods ({len(methods)})",
                    'suggestion': "Consider splitting into multiple classes or using composition"
                })
        
        # Check for code smells
        elif isinstance(node, ast.Try):
            # Bare except clauses
            for handler in node.handlers:
                if handler.type is None:
                    issues.append({
                        'category': 'code_smells',
                        'severity': 'minor',
                        'line': handler.lineno,
                        'description': "Bare except clause catches all exceptions",
                        'suggestion': "Specify exception types or use 'except Exception:'"
                    })
        
        return issues
    
    def _check_code_smells(self, content, lines):
        """Check for general code smells"""
        issues = []
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Long lines
            if len(line) > 120:
                issues.append({
                    'category': 'code_smells',
                    'severity': 'trivial',
                    'line': line_num,
                    'description': f"Line too long ({len(line)} characters)",
                    'suggestion': "Break long lines for better readability"
                })
            
            # TODO/FIXME comments
            if re.search(r'\b(TODO|FIXME|HACK|XXX)\b', line_stripped, re.IGNORECASE):
                issues.append({
                    'category': 'maintainability',
                    'severity': 'minor',
                    'line': line_num,
                    'description': "TODO/FIXME comment indicates incomplete work",
                    'suggestion': "Address the TODO item or create a proper issue tracker entry"
                })
            
            # Magic numbers
            magic_number_pattern = r'\b(?<![\w.])\d{2,}\b(?![\w.])'
            if re.search(magic_number_pattern, line_stripped) and not line_stripped.strip().startswith('#'):
                issues.append({
                    'category': 'code_smells',
                    'severity': 'trivial',
                    'line': line_num,
                    'description': "Magic number found",
                    'suggestion': "Replace magic numbers with named constants"
                })
            
            # Commented out code
            if re.match(r'^\s*#\s*[a-zA-Z_].*[=();{}]', line_stripped):
                issues.append({
                    'category': 'code_smells',
                    'severity': 'trivial',
                    'line': line_num,
                    'description': "Commented out code",
                    'suggestion': "Remove commented code or use version control"
                })
        
        return issues
    
    def _check_documentation(self, content, lines):
        """Check documentation quality"""
        issues = []
        
        # Check for README or documentation files
        if 'README' not in content and 'documentation' not in content.lower():
            issues.append({
                'category': 'documentation',
                'severity': 'minor',
                'line': 1,
                'description': "No README or documentation references found",
                'suggestion': "Add README file or documentation comments"
            })
        
        # Check comment density
        comment_lines = len([line for line in lines if line.strip().startswith('#')])
        total_code_lines = len([line for line in lines if line.strip() and not line.strip().startswith('#')])
        
        if total_code_lines > 0:
            comment_ratio = comment_lines / total_code_lines
            if comment_ratio < 0.1:  # Less than 10% comments
                issues.append({
                    'category': 'documentation',
                    'severity': 'minor',
                    'line': 1,
                    'description': f"Low comment density ({comment_ratio:.1%})",
                    'suggestion': "Add more comments to explain complex logic"
                })
        
        return issues
    
    def _check_security_issues(self, content, lines):
        """Check for basic security issues"""
        issues = []
        
        security_patterns = [
            (r'password\s*=\s*["\'][^"\']+["\']', "Hardcoded password", 'critical'),
            (r'api_key\s*=\s*["\'][^"\']+["\']', "Hardcoded API key", 'critical'),
            (r'secret\s*=\s*["\'][^"\']+["\']', "Hardcoded secret", 'critical'),
            (r'eval\s*\(', "Use of eval() function", 'major'),
            (r'exec\s*\(', "Use of exec() function", 'major'),
            (r'shell=True', "Shell injection risk", 'major'),
            (r'pickle\.loads?\s*\(', "Unsafe pickle usage", 'major'),
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, description, severity in security_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append({
                        'category': 'security',
                        'severity': severity,
                        'line': line_num,
                        'description': description,
                        'suggestion': "Review and secure this code pattern"
                    })
        
        return issues
    
    def _check_generic_complexity(self, content, lines):
        """Check for complexity indicators in any language"""
        issues = []
        
        # Count nesting levels
        for line_num, line in enumerate(lines, 1):
            # Simple nesting detection based on indentation or braces
            indent_level = len(line) - len(line.lstrip())
            brace_level = line.count('{') - line.count('}')
            
            if indent_level > 24 or brace_level > 3:  # Deep nesting
                issues.append({
                    'category': 'complexity',
                    'severity': 'minor',
                    'line': line_num,
                    'description': "Deep nesting detected",
                    'suggestion': "Consider refactoring to reduce nesting levels"
                })
        
        return issues
    
    def _calculate_function_complexity(self, node):
        """Calculate cyclomatic complexity of a function"""
        complexity = 1  # Base complexity
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
            elif isinstance(child, (ast.And, ast.Or)):
                complexity += 1
        
        return complexity
    
    def _calculate_file_debt(self, file_path, issues, total_lines):
        """Calculate technical debt score for a file"""
        debt_score = 0
        category_counts = {cat: 0 for cat in self.debt_categories}
        
        for issue in issues:
            category = issue['category']
            severity = issue['severity']
            
            # Calculate debt points
            base_points = self.effort_factors.get(severity, 1.0)
            category_weight = self.debt_categories.get(category, {}).get('weight', 1.0)
            debt_points = base_points * category_weight
            
            debt_score += debt_points
            category_counts[category] += 1
        
        # Normalize by file size
        normalized_score = debt_score / max(total_lines / 100, 1)  # Per 100 lines
        
        return {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'debt_score': round(debt_score, 2),
            'normalized_score': round(normalized_score, 2),
            'total_lines': total_lines,
            'issue_count': len(issues),
            'issues': issues,
            'category_counts': category_counts,
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def _aggregate_results(self, file_results):
        """Aggregate results from multiple files"""
        if not file_results:
            return {}
        
        total_debt = sum(r.get('debt_score', 0) for r in file_results)
        total_issues = sum(r.get('issue_count', 0) for r in file_results)
        total_lines = sum(r.get('total_lines', 0) for r in file_results)
        
        # Aggregate category counts
        category_totals = {cat: 0 for cat in self.debt_categories}
        for result in file_results:
            for cat, count in result.get('category_counts', {}).items():
                category_totals[cat] += count
        
        # Sort files by debt score
        file_results.sort(key=lambda x: x.get('debt_score', 0), reverse=True)
        
        return {
            'summary': {
                'total_files': len(file_results),
                'total_debt_score': round(total_debt, 2),
                'average_debt_per_file': round(total_debt / len(file_results), 2),
                'total_issues': total_issues,
                'total_lines': total_lines,
                'debt_density': round(total_debt / max(total_lines / 1000, 1), 2),  # Per 1000 lines
                'category_totals': category_totals
            },
            'files': file_results,
            'analysis_timestamp': datetime.now().isoformat()
        }


class ToolFrame(AdvancedToolFrame):
    def __init__(self, master):
        super().__init__(master, {
            'name': 'Technical Debt Calculator',
            'tool_id': 'technical_debt_calculator',
            'category': 'Code Analysis'
        })
        
        self.analyzer = TechnicalDebtAnalyzer()
        self.current_results = None
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface"""
        # Setup advanced UI components
        self.setup_advanced_ui()
        
        # Main container
        main_container = tk.Frame(self, bg=BG_COLOR)
        main_container.pack(fill="both", expand=True, before=self.results_notebook)
        
        # Left panel for controls
        left_panel = tk.Frame(main_container, bg=PANEL_COLOR, width=350)
        left_panel.pack(side="left", fill="y", padx=5, pady=5)
        left_panel.pack_propagate(False)
        
        # Right panel for visualization
        right_panel = tk.Frame(main_container, bg=BG_COLOR)
        right_panel.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        
        self.setup_control_panel(left_panel)
        self.setup_visualization_panel(right_panel)
    
    def setup_control_panel(self, parent):
        """Setup the control panel"""
        # Title
        title_label = tk.Label(parent, text="💳 Technical Debt Calculator", 
                              bg=PANEL_COLOR, fg=TEXT_COLOR, font=("Consolas", 14, "bold"))
        title_label.pack(pady=10)
        
        # File/Directory selection
        selection_frame = tk.Frame(parent, bg=PANEL_COLOR)
        selection_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(selection_frame, text="Analysis Target:", bg=PANEL_COLOR, fg=TEXT_COLOR, 
                font=("Consolas", 10, "bold")).pack(anchor="w")
        
        self.target_path_var = tk.StringVar()
        target_entry = tk.Entry(selection_frame, textvariable=self.target_path_var, 
                               bg="#111111", fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
        target_entry.pack(fill="x", pady=2)
        
        button_frame = tk.Frame(selection_frame, bg=PANEL_COLOR)
        button_frame.pack(fill="x", pady=2)
        
        file_btn = tk.Button(button_frame, text="Select File", command=self.browse_file)
        style_button(file_btn)
        file_btn.pack(side="left", padx=2, fill="x", expand=True)
        
        dir_btn = tk.Button(button_frame, text="Select Directory", command=self.browse_directory)
        style_button(dir_btn)
        dir_btn.pack(side="right", padx=2, fill="x", expand=True)
        
        # Analysis options
        options_frame = tk.Frame(parent, bg=PANEL_COLOR)
        options_frame.pack(fill="x", padx=10, pady=10)
        
        tk.Label(options_frame, text="Analysis Options:", bg=PANEL_COLOR, fg=TEXT_COLOR, 
                font=("Consolas", 10, "bold")).pack(anchor="w")
        
        self.include_security_var = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Security Analysis", variable=self.include_security_var,
                      bg=PANEL_COLOR, fg=TEXT_COLOR, selectcolor="#111111").pack(anchor="w")
        
        self.include_complexity_var = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Complexity Analysis", variable=self.include_complexity_var,
                      bg=PANEL_COLOR, fg=TEXT_COLOR, selectcolor="#111111").pack(anchor="w")
        
        self.include_documentation_var = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Documentation Analysis", variable=self.include_documentation_var,
                      bg=PANEL_COLOR, fg=TEXT_COLOR, selectcolor="#111111").pack(anchor="w")
        
        # Debt thresholds
        threshold_frame = tk.Frame(parent, bg=PANEL_COLOR)
        threshold_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(threshold_frame, text="Debt Severity Thresholds:", bg=PANEL_COLOR, fg=TEXT_COLOR, 
                font=("Consolas", 10, "bold")).pack(anchor="w")
        
        # Low debt threshold
        low_frame = tk.Frame(threshold_frame, bg=PANEL_COLOR)
        low_frame.pack(fill="x", pady=1)
        tk.Label(low_frame, text="Low:", bg=PANEL_COLOR, fg=TEXT_COLOR, width=8).pack(side="left")
        self.low_debt_threshold = tk.Spinbox(low_frame, from_=1, to=100, value=10, width=10,
                                            bg="#111111", fg=TEXT_COLOR)
        self.low_debt_threshold.pack(side="left")
        
        # Medium debt threshold
        med_frame = tk.Frame(threshold_frame, bg=PANEL_COLOR)
        med_frame.pack(fill="x", pady=1)
        tk.Label(med_frame, text="Medium:", bg=PANEL_COLOR, fg=TEXT_COLOR, width=8).pack(side="left")
        self.med_debt_threshold = tk.Spinbox(med_frame, from_=1, to=200, value=50, width=10,
                                            bg="#111111", fg=TEXT_COLOR)
        self.med_debt_threshold.pack(side="left")
        
        # High debt threshold
        high_frame = tk.Frame(threshold_frame, bg=PANEL_COLOR)
        high_frame.pack(fill="x", pady=1)
        tk.Label(high_frame, text="High:", bg=PANEL_COLOR, fg=TEXT_COLOR, width=8).pack(side="left")
        self.high_debt_threshold = tk.Spinbox(high_frame, from_=1, to=500, value=100, width=10,
                                             bg="#111111", fg=TEXT_COLOR)
        self.high_debt_threshold.pack(side="left")
        
        # Action buttons
        action_frame = tk.Frame(parent, bg=PANEL_COLOR)
        action_frame.pack(fill="x", padx=10, pady=20)
        
        analyze_btn = tk.Button(action_frame, text="💳 Calculate Debt", command=self.analyze_debt)
        style_button(analyze_btn)
        analyze_btn.pack(fill="x", pady=2)
        
        estimate_btn = tk.Button(action_frame, text="⏱ Estimate Effort", command=self.estimate_effort)
        style_button(estimate_btn)
        estimate_btn.pack(fill="x", pady=2)
        
        clear_btn = tk.Button(action_frame, text="🗑 Clear Results", command=self.clear_results)
        style_button(clear_btn)
        clear_btn.pack(fill="x", pady=2)
    
    def setup_visualization_panel(self, parent):
        """Setup the visualization panel"""
        # Visualization title
        viz_title = tk.Label(parent, text="📊 Debt Analysis Visualization", 
                            bg=BG_COLOR, fg=TEXT_COLOR, font=("Consolas", 12, "bold"))
        viz_title.pack(pady=10)
        
        # Matplotlib figure frame
        self.viz_frame = tk.Frame(parent, bg=BG_COLOR)
        self.viz_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Initial placeholder
        placeholder_label = tk.Label(self.viz_frame, text="Analyze code to see technical debt visualization",
                                    bg=BG_COLOR, fg=TEXT_COLOR, font=("Consolas", 10))
        placeholder_label.pack(expand=True)
    
    def browse_file(self):
        """Browse and select a file for analysis"""
        file_path = filedialog.askopenfilename(
            title="Select Code File for Debt Analysis",
            filetypes=[
                ("Python Files", "*.py"),
                ("JavaScript Files", "*.js"),
                ("Java Files", "*.java"),
                ("C++ Files", "*.cpp;*.cc;*.cxx"),
                ("C Files", "*.c"),
                ("C# Files", "*.cs"),
                ("PHP Files", "*.php"),
                ("Ruby Files", "*.rb"),
                ("Go Files", "*.go"),
                ("Rust Files", "*.rs"),
                ("All Code Files", "*.py;*.js;*.java;*.cpp;*.c;*.cs;*.php;*.rb;*.go;*.rs"),
                ("All Files", "*.*")
            ]
        )
        
        if file_path:
            self.target_path_var.set(file_path)
    
    def browse_directory(self):
        """Browse and select a directory for analysis"""
        directory = filedialog.askdirectory(title="Select Directory for Debt Analysis")
        
        if directory:
            self.target_path_var.set(directory)
    
    def analyze_debt(self):
        """Analyze technical debt for the selected target"""
        target_path = self.target_path_var.get().strip()
        
        if not target_path:
            messagebox.showerror("Error", "Please select a file or directory to analyze.")
            return
        
        if not os.path.exists(target_path):
            messagebox.showerror("Error", "Selected path does not exist.")
            return
        
        try:
            self.update_progress(10, "Starting debt analysis...")
            
            if os.path.isfile(target_path):
                # Single file analysis
                self.update_progress(30, "Analyzing file...")
                results = self.analyzer.analyze_file(target_path)
                self.current_results = {'files': [results], 'summary': self._create_single_file_summary(results)}
            else:
                # Directory analysis
                self.update_progress(30, "Scanning directory...")
                results = self.analyzer.analyze_directory(target_path)
                self.current_results = results
            
            self.update_progress(70, "Generating reports...")
            
            # Update results display
            self.update_results_display()
            
            # Generate visualization
            self.generate_debt_visualization()
            
            self.update_progress(100, "Analysis complete!")
            
            # Save results to database
            self.save_analysis_result(
                analysis_id=f"debt_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                input_data={'target_path': target_path},
                results_summary=self.current_results.get('summary', {}),
                detailed_findings=self.current_results.get('files', []),
                recommendations=self.generate_recommendations(),
                metrics=self._extract_key_metrics()
            )
            
            summary = self.current_results.get('summary', {})
            messagebox.showinfo("Analysis Complete", 
                              f"Total Debt Score: {summary.get('total_debt_score', 0)}\n"
                              f"Files Analyzed: {summary.get('total_files', 0)}\n"
                              f"Issues Found: {summary.get('total_issues', 0)}")
            
        except Exception as e:
            self.update_progress(0, f"Error: {str(e)}")
            messagebox.showerror("Analysis Error", f"Failed to analyze debt:\n{str(e)}")
    
    def estimate_effort(self):
        """Estimate effort required to address technical debt"""
        if not self.current_results:
            messagebox.showwarning("No Data", "Please run debt analysis first.")
            return
        
        try:
            effort_estimate = self._calculate_effort_estimate()
            
            # Display effort estimation
            effort_text = f"""Effort Estimation Report
{'=' * 50}

Total Estimated Effort: {effort_estimate['total_hours']:.1f} hours ({effort_estimate['total_days']:.1f} days)

By Category:
"""
            for category, hours in effort_estimate['by_category'].items():
                if hours > 0:
                    effort_text += f"• {category.replace('_', ' ').title()}: {hours:.1f} hours\n"
            
            effort_text += f"""
By Priority:
• Critical Issues: {effort_estimate['by_priority']['critical']:.1f} hours
• Major Issues: {effort_estimate['by_priority']['major']:.1f} hours
• Minor Issues: {effort_estimate['by_priority']['minor']:.1f} hours
• Trivial Issues: {effort_estimate['by_priority']['trivial']:.1f} hours

Recommendations:
• Focus on critical and major issues first
• Allocate {effort_estimate['sprint_effort']:.1f} hours per 2-week sprint
• Estimated completion: {effort_estimate['estimated_sprints']} sprints
"""
            
            self.update_results_tab("Analysis", effort_text)
            
            messagebox.showinfo("Effort Estimation", 
                              f"Total effort: {effort_estimate['total_hours']:.1f} hours\n"
                              f"Estimated sprints: {effort_estimate['estimated_sprints']}")
            
        except Exception as e:
            messagebox.showerror("Estimation Error", f"Failed to estimate effort:\n{str(e)}")
    
    def _create_single_file_summary(self, file_result):
        """Create summary for single file analysis"""
        return {
            'total_files': 1,
            'total_debt_score': file_result.get('debt_score', 0),
            'average_debt_per_file': file_result.get('debt_score', 0),
            'total_issues': file_result.get('issue_count', 0),
            'total_lines': file_result.get('total_lines', 0),
            'debt_density': file_result.get('normalized_score', 0),
            'category_totals': file_result.get('category_counts', {})
        }
    
    def _calculate_effort_estimate(self):
        """Calculate effort estimation based on debt analysis"""
        if not self.current_results:
            return {}
        
        total_hours = 0
        by_category = {cat: 0 for cat in self.analyzer.debt_categories}
        by_priority = {'critical': 0, 'major': 0, 'minor': 0, 'trivial': 0, 'blocker': 0}
        
        files = self.current_results.get('files', [])
        
        for file_result in files:
            for issue in file_result.get('issues', []):
                severity = issue.get('severity', 'minor')
                category = issue.get('category', 'maintainability')
                
                effort_hours = self.analyzer.effort_factors.get(severity, 2.0)
                total_hours += effort_hours
                
                by_category[category] += effort_hours
                by_priority[severity] += effort_hours
        
        # Calculate sprint estimates (assuming 40 hours per sprint for debt work)
        sprint_capacity = 40
        estimated_sprints = max(1, int(total_hours / sprint_capacity) + (1 if total_hours % sprint_capacity > 0 else 0))
        
        return {
            'total_hours': total_hours,
            'total_days': total_hours / 8,  # 8 hours per day
            'by_category': by_category,
            'by_priority': by_priority,
            'sprint_effort': sprint_capacity,
            'estimated_sprints': estimated_sprints
        }
    
    def update_results_display(self):
        """Update the results tabs with debt analysis data"""
        if not self.current_results:
            return
        
        summary = self.current_results.get('summary', {})
        files = self.current_results.get('files', [])
        
        # Summary tab
        summary_text = f"""Technical Debt Analysis Summary
{'=' * 50}

Overall Metrics:
• Total Files Analyzed: {summary.get('total_files', 0)}
• Total Debt Score: {summary.get('total_debt_score', 0):.2f}
• Average Debt per File: {summary.get('average_debt_per_file', 0):.2f}
• Total Issues Found: {summary.get('total_issues', 0)}
• Total Lines of Code: {summary.get('total_lines', 0)}
• Debt Density: {summary.get('debt_density', 0):.2f} (per 1000 lines)

Issues by Category:
"""
        
        category_totals = summary.get('category_totals', {})
        for category, count in category_totals.items():
            if count > 0:
                category_name = category.replace('_', ' ').title()
                summary_text += f"• {category_name}: {count} issues\n"
        
        if files:
            summary_text += f"\nTop 5 Files by Debt Score:\n{'-' * 30}\n"
            for i, file_result in enumerate(files[:5], 1):
                summary_text += f"{i}. {file_result['file_name']} (Score: {file_result['debt_score']:.2f})\n"
        
        self.update_results_tab("Summary", summary_text)
        
        # Details tab
        details_text = "Detailed Debt Analysis\n" + "=" * 50 + "\n\n"
        
        for file_result in files[:10]:  # Show top 10 files
            details_text += f"File: {file_result['file_name']}\n"
            details_text += f"Path: {file_result['file_path']}\n"
            details_text += f"Debt Score: {file_result['debt_score']:.2f}\n"
            details_text += f"Issues: {file_result['issue_count']}\n"
            details_text += f"Lines: {file_result['total_lines']}\n\n"
            
            # Show top issues for this file
            issues = file_result.get('issues', [])
            if issues:
                details_text += "Top Issues:\n"
                for issue in issues[:5]:  # Show top 5 issues per file
                    details_text += f"  • Line {issue['line']}: {issue['description']} ({issue['severity']})\n"
                    details_text += f"    Suggestion: {issue['suggestion']}\n"
            
            details_text += "\n" + "-" * 50 + "\n\n"
        
        self.update_results_tab("Details", details_text)
        
        # Raw Data tab
        raw_data = json.dumps(self.current_results, indent=2, default=str)
        self.update_results_tab("Raw Data", raw_data)
        
        # Set results data for export
        self.set_results_data(self.current_results)
    
    def generate_recommendations(self):
        """Generate recommendations based on debt analysis"""
        if not self.current_results:
            return []
        
        recommendations = []
        summary = self.current_results.get('summary', {})
        
        total_debt = summary.get('total_debt_score', 0)
        
        if total_debt > 100:
            recommendations.append("High technical debt detected - consider dedicated refactoring sprints")
        
        category_totals = summary.get('category_totals', {})
        
        # Category-specific recommendations
        if category_totals.get('security', 0) > 0:
            recommendations.append("Address security issues immediately - they pose the highest risk")
        
        if category_totals.get('complexity', 0) > 5:
            recommendations.append("Focus on reducing code complexity through refactoring")
        
        if category_totals.get('documentation', 0) > 10:
            recommendations.append("Improve code documentation to enhance maintainability")
        
        if category_totals.get('duplication', 0) > 3:
            recommendations.append("Eliminate code duplication through extraction and reuse")
        
        return recommendations
    
    def _extract_key_metrics(self):
        """Extract key metrics for database storage"""
        if not self.current_results:
            return {}
        
        summary = self.current_results.get('summary', {})
        
        return {
            'total_debt_score': summary.get('total_debt_score', 0),
            'total_files': summary.get('total_files', 0),
            'total_issues': summary.get('total_issues', 0),
            'debt_density': summary.get('debt_density', 0),
            'average_debt_per_file': summary.get('average_debt_per_file', 0)
        }
    
    def generate_debt_visualization(self):
        """Generate visual debt analysis charts"""
        if not self.current_results:
            return
        
        # Clear existing visualization
        for widget in self.viz_frame.winfo_children():
            widget.destroy()
        
        try:
            # Create matplotlib figure
            fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(12, 10))
            fig.patch.set_facecolor('#1a1a1a')
            
            summary = self.current_results.get('summary', {})
            files = self.current_results.get('files', [])
            
            # 1. Debt by category (pie chart)
            category_totals = summary.get('category_totals', {})
            categories = [cat.replace('_', ' ').title() for cat, count in category_totals.items() if count > 0]
            counts = [count for count in category_totals.values() if count > 0]
            
            if categories:
                colors = plt.cm.Set3(np.linspace(0, 1, len(categories)))
                ax1.pie(counts, labels=categories, autopct='%1.1f%%', colors=colors, startangle=90)
                ax1.set_title('Issues by Category', color='white', fontsize=10, fontweight='bold')
            else:
                ax1.text(0.5, 0.5, 'No issues found', ha='center', va='center', transform=ax1.transAxes, color='white')
            
            # 2. Top files by debt score (bar chart)
            if files:
                top_files = files[:10]  # Top 10 files
                file_names = [f['file_name'][:20] + '...' if len(f['file_name']) > 20 else f['file_name'] for f in top_files]
                debt_scores = [f['debt_score'] for f in top_files]
                
                colors = ['red' if score > 100 else 'orange' if score > 50 else 'yellow' if score > 10 else 'green' 
                         for score in debt_scores]
                
                bars = ax2.barh(range(len(file_names)), debt_scores, color=colors, alpha=0.7)
                ax2.set_yticks(range(len(file_names)))
                ax2.set_yticklabels(file_names, color='white', fontsize=8)
                ax2.set_xlabel('Debt Score', color='white')
                ax2.set_title('Top Files by Debt Score', color='white', fontsize=10, fontweight='bold')
                ax2.tick_params(colors='white')
                ax2.set_facecolor('#2a2a2a')
                
                # Add value labels
                for i, (bar, score) in enumerate(zip(bars, debt_scores)):
                    ax2.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2,
                            f'{score:.1f}', va='center', color='white', fontsize=8)
            else:
                ax2.text(0.5, 0.5, 'No files analyzed', ha='center', va='center', transform=ax2.transAxes, color='white')
                ax2.set_facecolor('#2a2a2a')
            
            # 3. Debt distribution histogram
            if files:
                debt_scores = [f['debt_score'] for f in files]
                ax3.hist(debt_scores, bins=min(20, len(files)), color='skyblue', alpha=0.7, edgecolor='white')
                ax3.set_xlabel('Debt Score', color='white')
                ax3.set_ylabel('Number of Files', color='white')
                ax3.set_title('Debt Score Distribution', color='white', fontsize=10, fontweight='bold')
                ax3.tick_params(colors='white')
                ax3.set_facecolor('#2a2a2a')
            else:
                ax3.text(0.5, 0.5, 'No data for distribution', ha='center', va='center', transform=ax3.transAxes, color='white')
                ax3.set_facecolor('#2a2a2a')
            
            # 4. Debt vs File Size scatter plot
            if files:
                file_sizes = [f['total_lines'] for f in files]
                debt_scores = [f['debt_score'] for f in files]
                
                scatter = ax4.scatter(file_sizes, debt_scores, alpha=0.6, c=debt_scores, cmap='Reds')
                ax4.set_xlabel('File Size (Lines)', color='white')
                ax4.set_ylabel('Debt Score', color='white')
                ax4.set_title('Debt Score vs File Size', color='white', fontsize=10, fontweight='bold')
                ax4.tick_params(colors='white')
                ax4.set_facecolor('#2a2a2a')
                
                # Add colorbar
                cbar = plt.colorbar(scatter, ax=ax4)
                cbar.set_label('Debt Score', color='white')
                cbar.ax.yaxis.set_tick_params(color='white')
                cbar.ax.yaxis.set_ticklabels(cbar.ax.yaxis.get_ticklabels(), color='white')
            else:
                ax4.text(0.5, 0.5, 'No data for scatter plot', ha='center', va='center', transform=ax4.transAxes, color='white')
                ax4.set_facecolor('#2a2a2a')
            
            # Style all axes
            for ax in [ax1, ax2, ax3, ax4]:
                for spine in ax.spines.values():
                    spine.set_color('white')
            
            plt.tight_layout()
            
            # Embed in tkinter
            canvas = FigureCanvasTkAgg(fig, self.viz_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="both", expand=True)
            
        except Exception as e:
            error_label = tk.Label(self.viz_frame, text=f"Error generating visualization: {str(e)}",
                                 bg=BG_COLOR, fg="red", font=("Consolas", 10))
            error_label.pack(expand=True)
    
    def clear_results(self):
        """Clear all analysis results and visualizations"""
        self.current_results = None
        
        # Clear results tabs
        for tab_name in ["Summary", "Details", "Analysis", "Raw Data"]:
            self.update_results_tab(tab_name, "")
        
        # Clear visualization
        for widget in self.viz_frame.winfo_children():
            widget.destroy()
        
        placeholder_label = tk.Label(self.viz_frame, text="Analyze code to see technical debt visualization",
                                   bg=BG_COLOR, fg=TEXT_COLOR, font=("Consolas", 10))
        placeholder_label.pack(expand=True)
        
        # Reset progress
        self.update_progress(0, "Ready")
        
        messagebox.showinfo("Cleared", "All results have been cleared.")