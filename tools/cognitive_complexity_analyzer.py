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
import matplotlib.patches as patches
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

TAB_NAME = "Cognitive Complexity Analyzer"

class ComplexityAnalyzer:
    """Core complexity analysis engine supporting multiple programming languages"""
    
    def __init__(self):
        self.reset_metrics()
    
    def reset_metrics(self):
        """Reset all metrics for new analysis"""
        self.cognitive_complexity = 0
        self.cyclomatic_complexity = 1  # Base complexity is 1
        self.nesting_level = 0
        self.max_nesting = 0
        self.function_complexities = {}
        self.class_complexities = {}
        self.line_complexities = {}
        
    def analyze_python_file(self, file_path):
        """Analyze Python file using AST parsing"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content, filename=file_path)
            self.reset_metrics()
            
            # Walk through AST nodes
            for node in ast.walk(tree):
                self._analyze_node(node)
            
            return self._generate_results(file_path, content)
            
        except SyntaxError as e:
            raise Exception(f"Syntax error in Python file: {e}")
        except Exception as e:
            raise Exception(f"Error analyzing Python file: {e}")
    
    def analyze_javascript_file(self, file_path):
        """Analyze JavaScript file using regex patterns"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.reset_metrics()
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                complexity = self._analyze_js_line(line.strip())
                if complexity > 0:
                    self.line_complexities[line_num] = complexity
                    self.cognitive_complexity += complexity
            
            return self._generate_results(file_path, content)
            
        except Exception as e:
            raise Exception(f"Error analyzing JavaScript file: {e}")
    
    def analyze_generic_file(self, file_path):
        """Generic analysis for other file types using pattern matching"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.reset_metrics()
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                complexity = self._analyze_generic_line(line.strip())
                if complexity > 0:
                    self.line_complexities[line_num] = complexity
                    self.cognitive_complexity += complexity
            
            return self._generate_results(file_path, content)
            
        except Exception as e:
            raise Exception(f"Error analyzing file: {e}")
    
    def _analyze_node(self, node):
        """Analyze individual AST node for complexity"""
        # Increment cyclomatic complexity for decision points
        if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor)):
            self.cyclomatic_complexity += 1
            self.cognitive_complexity += 1 + self.nesting_level
            
        elif isinstance(node, ast.ExceptHandler):
            self.cyclomatic_complexity += 1
            self.cognitive_complexity += 1 + self.nesting_level
            
        elif isinstance(node, (ast.And, ast.Or)):
            self.cognitive_complexity += 1
            
        elif isinstance(node, ast.Lambda):
            self.cognitive_complexity += 1
            
        # Track nesting levels
        if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor, ast.With, ast.AsyncWith, ast.Try)):
            self.nesting_level += 1
            self.max_nesting = max(self.max_nesting, self.nesting_level)
            
            # Recursively analyze children
            for child in ast.iter_child_nodes(node):
                self._analyze_node(child)
                
            self.nesting_level -= 1
        
        # Track function complexities
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name = node.name
            old_complexity = self.cognitive_complexity
            old_cyclomatic = self.cyclomatic_complexity
            
            self.cognitive_complexity = 0
            self.cyclomatic_complexity = 1
            
            for child in ast.iter_child_nodes(node):
                self._analyze_node(child)
            
            self.function_complexities[func_name] = {
                'cognitive': self.cognitive_complexity,
                'cyclomatic': self.cyclomatic_complexity,
                'line': node.lineno
            }
            
            self.cognitive_complexity = old_complexity + self.cognitive_complexity
            self.cyclomatic_complexity = old_cyclomatic + self.cyclomatic_complexity
        
        # Track class complexities
        elif isinstance(node, ast.ClassDef):
            class_name = node.name
            old_complexity = self.cognitive_complexity
            
            self.cognitive_complexity = 0
            
            for child in ast.iter_child_nodes(node):
                self._analyze_node(child)
            
            self.class_complexities[class_name] = {
                'cognitive': self.cognitive_complexity,
                'line': node.lineno
            }
            
            self.cognitive_complexity = old_complexity + self.cognitive_complexity
        
        else:
            # Continue analyzing children
            for child in ast.iter_child_nodes(node):
                self._analyze_node(child)
    
    def _analyze_js_line(self, line):
        """Analyze JavaScript line for complexity patterns"""
        complexity = 0
        
        # Control flow statements
        if re.search(r'\b(if|while|for|switch)\b', line):
            complexity += 1
        
        # Logical operators
        complexity += len(re.findall(r'&&|\|\|', line))
        
        # Ternary operators
        complexity += len(re.findall(r'\?.*:', line))
        
        # Try-catch
        if re.search(r'\b(try|catch|finally)\b', line):
            complexity += 1
        
        return complexity
    
    def _analyze_generic_line(self, line):
        """Generic complexity analysis for any programming language"""
        complexity = 0
        
        # Common control flow keywords
        control_keywords = ['if', 'else', 'elif', 'while', 'for', 'switch', 'case', 'try', 'catch', 'except', 'finally']
        for keyword in control_keywords:
            if re.search(rf'\b{keyword}\b', line, re.IGNORECASE):
                complexity += 1
        
        # Logical operators (various syntaxes)
        logical_patterns = [r'&&', r'\|\|', r'\band\b', r'\bor\b', r'&amp;&amp;', r'\|\|']
        for pattern in logical_patterns:
            complexity += len(re.findall(pattern, line, re.IGNORECASE))
        
        return complexity
    
    def _generate_results(self, file_path, content):
        """Generate comprehensive analysis results"""
        lines = content.split('\n')
        total_lines = len(lines)
        non_empty_lines = len([line for line in lines if line.strip()])
        
        # Calculate complexity density
        complexity_density = self.cognitive_complexity / max(non_empty_lines, 1)
        
        # Determine complexity rating
        if self.cognitive_complexity <= 5:
            rating = "Low"
            color = "green"
        elif self.cognitive_complexity <= 15:
            rating = "Moderate"
            color = "yellow"
        elif self.cognitive_complexity <= 25:
            rating = "High"
            color = "orange"
        else:
            rating = "Very High"
            color = "red"
        
        return {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'total_lines': total_lines,
            'non_empty_lines': non_empty_lines,
            'cognitive_complexity': self.cognitive_complexity,
            'cyclomatic_complexity': self.cyclomatic_complexity,
            'complexity_density': round(complexity_density, 2),
            'max_nesting_level': self.max_nesting,
            'rating': rating,
            'rating_color': color,
            'function_complexities': self.function_complexities,
            'class_complexities': self.class_complexities,
            'line_complexities': self.line_complexities,
            'analysis_timestamp': datetime.now().isoformat()
        }


class ToolFrame(AdvancedToolFrame):
    def __init__(self, master):
        super().__init__(master, {
            'name': 'Cognitive Complexity Analyzer',
            'tool_id': 'cognitive_complexity_analyzer',
            'category': 'Code Analysis'
        })
        
        self.analyzer = ComplexityAnalyzer()
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
        """Setup the control panel with file selection and analysis options"""
        # Title
        title_label = tk.Label(parent, text="🧠 Cognitive Complexity Analyzer", 
                              bg=PANEL_COLOR, fg=TEXT_COLOR, font=("Consolas", 14, "bold"))
        title_label.pack(pady=10)
        
        # File selection
        file_frame = tk.Frame(parent, bg=PANEL_COLOR)
        file_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(file_frame, text="Select File:", bg=PANEL_COLOR, fg=TEXT_COLOR, 
                font=("Consolas", 10, "bold")).pack(anchor="w")
        
        self.file_path_var = tk.StringVar()
        file_entry = tk.Entry(file_frame, textvariable=self.file_path_var, 
                             bg="#111111", fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
        file_entry.pack(fill="x", pady=2)
        
        browse_btn = tk.Button(file_frame, text="Browse Files", command=self.browse_file)
        style_button(browse_btn)
        browse_btn.pack(fill="x", pady=2)
        
        # Directory analysis
        dir_btn = tk.Button(file_frame, text="Analyze Directory", command=self.analyze_directory)
        style_button(dir_btn)
        dir_btn.pack(fill="x", pady=2)
        
        # Analysis options
        options_frame = tk.Frame(parent, bg=PANEL_COLOR)
        options_frame.pack(fill="x", padx=10, pady=10)
        
        tk.Label(options_frame, text="Analysis Options:", bg=PANEL_COLOR, fg=TEXT_COLOR, 
                font=("Consolas", 10, "bold")).pack(anchor="w")
        
        self.include_functions_var = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Analyze Functions", variable=self.include_functions_var,
                      bg=PANEL_COLOR, fg=TEXT_COLOR, selectcolor="#111111").pack(anchor="w")
        
        self.include_classes_var = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Analyze Classes", variable=self.include_classes_var,
                      bg=PANEL_COLOR, fg=TEXT_COLOR, selectcolor="#111111").pack(anchor="w")
        
        self.show_heatmap_var = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Generate Heatmap", variable=self.show_heatmap_var,
                      bg=PANEL_COLOR, fg=TEXT_COLOR, selectcolor="#111111").pack(anchor="w")
        
        # Complexity thresholds
        threshold_frame = tk.Frame(parent, bg=PANEL_COLOR)
        threshold_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(threshold_frame, text="Complexity Thresholds:", bg=PANEL_COLOR, fg=TEXT_COLOR, 
                font=("Consolas", 10, "bold")).pack(anchor="w")
        
        # Low threshold
        low_frame = tk.Frame(threshold_frame, bg=PANEL_COLOR)
        low_frame.pack(fill="x", pady=1)
        tk.Label(low_frame, text="Low:", bg=PANEL_COLOR, fg=TEXT_COLOR, width=8).pack(side="left")
        self.low_threshold = tk.Spinbox(low_frame, from_=1, to=50, value=5, width=10,
                                       bg="#111111", fg=TEXT_COLOR)
        self.low_threshold.pack(side="left")
        
        # Moderate threshold
        mod_frame = tk.Frame(threshold_frame, bg=PANEL_COLOR)
        mod_frame.pack(fill="x", pady=1)
        tk.Label(mod_frame, text="Moderate:", bg=PANEL_COLOR, fg=TEXT_COLOR, width=8).pack(side="left")
        self.mod_threshold = tk.Spinbox(mod_frame, from_=1, to=50, value=15, width=10,
                                       bg="#111111", fg=TEXT_COLOR)
        self.mod_threshold.pack(side="left")
        
        # High threshold
        high_frame = tk.Frame(threshold_frame, bg=PANEL_COLOR)
        high_frame.pack(fill="x", pady=1)
        tk.Label(high_frame, text="High:", bg=PANEL_COLOR, fg=TEXT_COLOR, width=8).pack(side="left")
        self.high_threshold = tk.Spinbox(high_frame, from_=1, to=100, value=25, width=10,
                                        bg="#111111", fg=TEXT_COLOR)
        self.high_threshold.pack(side="left")
        
        # Action buttons
        action_frame = tk.Frame(parent, bg=PANEL_COLOR)
        action_frame.pack(fill="x", padx=10, pady=20)
        
        analyze_btn = tk.Button(action_frame, text="🔍 Analyze File", command=self.analyze_file)
        style_button(analyze_btn)
        analyze_btn.pack(fill="x", pady=2)
        
        clear_btn = tk.Button(action_frame, text="🗑 Clear Results", command=self.clear_results)
        style_button(clear_btn)
        clear_btn.pack(fill="x", pady=2)
    
    def setup_visualization_panel(self, parent):
        """Setup the visualization panel for complexity heatmaps"""
        # Visualization title
        viz_title = tk.Label(parent, text="📊 Complexity Visualization", 
                            bg=BG_COLOR, fg=TEXT_COLOR, font=("Consolas", 12, "bold"))
        viz_title.pack(pady=10)
        
        # Matplotlib figure frame
        self.viz_frame = tk.Frame(parent, bg=BG_COLOR)
        self.viz_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Initial placeholder
        placeholder_label = tk.Label(self.viz_frame, text="Select and analyze a file to see complexity visualization",
                                    bg=BG_COLOR, fg=TEXT_COLOR, font=("Consolas", 10))
        placeholder_label.pack(expand=True)
    
    def browse_file(self):
        """Browse and select a file for analysis"""
        file_path = filedialog.askopenfilename(
            title="Select Code File for Complexity Analysis",
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
            self.file_path_var.set(file_path)
    
    def analyze_file(self):
        """Analyze the selected file for cognitive complexity"""
        file_path = self.file_path_var.get().strip()
        
        if not file_path:
            messagebox.showerror("Error", "Please select a file to analyze.")
            return
        
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "Selected file does not exist.")
            return
        
        try:
            self.update_progress(10, "Starting analysis...")
            
            # Determine file type and use appropriate analyzer
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if file_ext == '.py':
                self.update_progress(30, "Parsing Python AST...")
                results = self.analyzer.analyze_python_file(file_path)
            elif file_ext == '.js':
                self.update_progress(30, "Analyzing JavaScript...")
                results = self.analyzer.analyze_javascript_file(file_path)
            else:
                self.update_progress(30, "Generic analysis...")
                results = self.analyzer.analyze_generic_file(file_path)
            
            self.update_progress(70, "Generating visualizations...")
            self.current_results = results
            
            # Update results tabs
            self.update_results_display()
            
            # Generate visualization
            if self.show_heatmap_var.get():
                self.generate_complexity_heatmap()
            
            self.update_progress(100, "Analysis complete!")
            
            # Save results to database
            self.save_analysis_result(
                analysis_id=f"complexity_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                input_data={'file_path': file_path},
                results_summary=results,
                detailed_findings=results.get('function_complexities', {}),
                recommendations=self.generate_recommendations(results),
                metrics={
                    'cognitive_complexity': results['cognitive_complexity'],
                    'cyclomatic_complexity': results['cyclomatic_complexity'],
                    'complexity_density': results['complexity_density']
                }
            )
            
            messagebox.showinfo("Analysis Complete", 
                              f"Cognitive Complexity: {results['cognitive_complexity']}\n"
                              f"Rating: {results['rating']}")
            
        except Exception as e:
            self.update_progress(0, f"Error: {str(e)}")
            messagebox.showerror("Analysis Error", f"Failed to analyze file:\n{str(e)}")
    
    def analyze_directory(self):
        """Analyze all code files in a directory"""
        directory = filedialog.askdirectory(title="Select Directory for Batch Analysis")
        
        if not directory:
            return
        
        try:
            # Find all code files
            code_extensions = ['.py', '.js', '.java', '.cpp', '.c', '.cs', '.php', '.rb', '.go', '.rs']
            code_files = []
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if any(file.lower().endswith(ext) for ext in code_extensions):
                        code_files.append(os.path.join(root, file))
            
            if not code_files:
                messagebox.showinfo("No Files", "No code files found in the selected directory.")
                return
            
            # Analyze each file
            batch_results = []
            total_files = len(code_files)
            
            for i, file_path in enumerate(code_files):
                try:
                    progress = (i / total_files) * 100
                    self.update_progress(progress, f"Analyzing {os.path.basename(file_path)}...")
                    
                    file_ext = os.path.splitext(file_path)[1].lower()
                    
                    if file_ext == '.py':
                        results = self.analyzer.analyze_python_file(file_path)
                    elif file_ext == '.js':
                        results = self.analyzer.analyze_javascript_file(file_path)
                    else:
                        results = self.analyzer.analyze_generic_file(file_path)
                    
                    batch_results.append(results)
                    
                except Exception as e:
                    print(f"Error analyzing {file_path}: {e}")
                    continue
            
            self.update_progress(100, "Batch analysis complete!")
            
            # Display batch results
            self.display_batch_results(batch_results)
            
        except Exception as e:
            messagebox.showerror("Batch Analysis Error", f"Failed to analyze directory:\n{str(e)}")
    
    def update_results_display(self):
        """Update the results tabs with analysis data"""
        if not self.current_results:
            return
        
        results = self.current_results
        
        # Summary tab
        summary_text = f"""File Analysis Summary
{'=' * 50}

File: {results['file_name']}
Path: {results['file_path']}
Analysis Time: {results['analysis_timestamp']}

Complexity Metrics:
• Cognitive Complexity: {results['cognitive_complexity']}
• Cyclomatic Complexity: {results['cyclomatic_complexity']}
• Complexity Density: {results['complexity_density']}
• Maximum Nesting Level: {results['max_nesting_level']}
• Overall Rating: {results['rating']}

File Statistics:
• Total Lines: {results['total_lines']}
• Non-empty Lines: {results['non_empty_lines']}
• Functions Analyzed: {len(results['function_complexities'])}
• Classes Analyzed: {len(results['class_complexities'])}
"""
        
        self.update_results_tab("Summary", summary_text)
        
        # Details tab
        details_text = "Detailed Analysis Results\n" + "=" * 50 + "\n\n"
        
        if results['function_complexities']:
            details_text += "Function Complexities:\n" + "-" * 30 + "\n"
            for func_name, func_data in results['function_complexities'].items():
                details_text += f"• {func_name} (Line {func_data['line']})\n"
                details_text += f"  Cognitive: {func_data['cognitive']}, Cyclomatic: {func_data['cyclomatic']}\n\n"
        
        if results['class_complexities']:
            details_text += "\nClass Complexities:\n" + "-" * 30 + "\n"
            for class_name, class_data in results['class_complexities'].items():
                details_text += f"• {class_name} (Line {class_data['line']})\n"
                details_text += f"  Cognitive: {class_data['cognitive']}\n\n"
        
        if results['line_complexities']:
            details_text += "\nLine-by-Line Complexity:\n" + "-" * 30 + "\n"
            for line_num, complexity in sorted(results['line_complexities'].items()):
                details_text += f"Line {line_num}: Complexity {complexity}\n"
        
        self.update_results_tab("Details", details_text)
        
        # Analysis tab with recommendations
        recommendations = self.generate_recommendations(results)
        analysis_text = f"""Analysis and Recommendations
{'=' * 50}

Complexity Assessment:
{recommendations['assessment']}

Recommendations:
"""
        for i, rec in enumerate(recommendations['recommendations'], 1):
            analysis_text += f"{i}. {rec}\n"
        
        analysis_text += f"\nRefactoring Priorities:\n"
        for priority in recommendations['priorities']:
            analysis_text += f"• {priority}\n"
        
        self.update_results_tab("Analysis", analysis_text)
        
        # Raw Data tab
        raw_data = json.dumps(results, indent=2, default=str)
        self.update_results_tab("Raw Data", raw_data)
        
        # Set results data for export
        self.set_results_data(results)
    
    def generate_recommendations(self, results):
        """Generate refactoring recommendations based on complexity analysis"""
        complexity = results['cognitive_complexity']
        
        # Assessment
        if complexity <= 5:
            assessment = "✅ Low complexity - Code is well-structured and maintainable."
        elif complexity <= 15:
            assessment = "⚠️ Moderate complexity - Consider minor refactoring for better maintainability."
        elif complexity <= 25:
            assessment = "🔶 High complexity - Refactoring recommended to improve code quality."
        else:
            assessment = "🔴 Very high complexity - Immediate refactoring required for maintainability."
        
        # General recommendations
        recommendations = []
        
        if complexity > 15:
            recommendations.append("Break down large functions into smaller, focused functions")
            recommendations.append("Reduce nesting levels by using early returns or guard clauses")
        
        if results['max_nesting_level'] > 3:
            recommendations.append("Reduce deep nesting - consider extracting nested logic into separate functions")
        
        if results['function_complexities']:
            high_complexity_funcs = [name for name, data in results['function_complexities'].items() 
                                   if data['cognitive'] > 10]
            if high_complexity_funcs:
                recommendations.append(f"Focus on refactoring high-complexity functions: {', '.join(high_complexity_funcs[:3])}")
        
        if results['complexity_density'] > 0.5:
            recommendations.append("Consider splitting the file - high complexity density indicates too much logic in one place")
        
        # Priorities
        priorities = []
        if results['function_complexities']:
            sorted_funcs = sorted(results['function_complexities'].items(), 
                                key=lambda x: x[1]['cognitive'], reverse=True)
            for func_name, func_data in sorted_funcs[:3]:
                if func_data['cognitive'] > 5:
                    priorities.append(f"Refactor '{func_name}' function (Complexity: {func_data['cognitive']})")
        
        return {
            'assessment': assessment,
            'recommendations': recommendations,
            'priorities': priorities
        }
    
    def generate_complexity_heatmap(self):
        """Generate visual complexity heatmap"""
        if not self.current_results:
            return
        
        # Clear existing visualization
        for widget in self.viz_frame.winfo_children():
            widget.destroy()
        
        try:
            # Create matplotlib figure
            fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(8, 10))
            fig.patch.set_facecolor('#1a1a1a')
            
            # Function complexity bar chart
            if self.current_results['function_complexities']:
                func_names = list(self.current_results['function_complexities'].keys())
                func_complexities = [data['cognitive'] for data in self.current_results['function_complexities'].values()]
                
                colors = ['green' if c <= 5 else 'yellow' if c <= 15 else 'orange' if c <= 25 else 'red' 
                         for c in func_complexities]
                
                bars = ax1.bar(range(len(func_names)), func_complexities, color=colors, alpha=0.7)
                ax1.set_xlabel('Functions', color='white')
                ax1.set_ylabel('Cognitive Complexity', color='white')
                ax1.set_title('Function Complexity Distribution', color='white', fontsize=12, fontweight='bold')
                ax1.set_xticks(range(len(func_names)))
                ax1.set_xticklabels(func_names, rotation=45, ha='right', color='white')
                ax1.tick_params(colors='white')
                ax1.set_facecolor('#2a2a2a')
                
                # Add value labels on bars
                for bar, complexity in zip(bars, func_complexities):
                    height = bar.get_height()
                    ax1.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                            f'{complexity}', ha='center', va='bottom', color='white', fontsize=8)
            else:
                ax1.text(0.5, 0.5, 'No functions found for analysis', 
                        ha='center', va='center', transform=ax1.transAxes, color='white')
                ax1.set_facecolor('#2a2a2a')
            
            # Overall complexity pie chart
            complexity = self.current_results['cognitive_complexity']
            low_threshold = int(self.low_threshold.get())
            mod_threshold = int(self.mod_threshold.get())
            high_threshold = int(self.high_threshold.get())
            
            if complexity <= low_threshold:
                colors = ['green', 'lightgray']
                sizes = [complexity, max(1, low_threshold - complexity)]
                labels = [f'Current ({complexity})', f'Low Threshold ({low_threshold})']
            elif complexity <= mod_threshold:
                colors = ['yellow', 'lightgray']
                sizes = [complexity, max(1, mod_threshold - complexity)]
                labels = [f'Current ({complexity})', f'Moderate Threshold ({mod_threshold})']
            elif complexity <= high_threshold:
                colors = ['orange', 'lightgray']
                sizes = [complexity, max(1, high_threshold - complexity)]
                labels = [f'Current ({complexity})', f'High Threshold ({high_threshold})']
            else:
                colors = ['red']
                sizes = [complexity]
                labels = [f'Very High ({complexity})']
            
            ax2.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
            ax2.set_title('Overall Complexity Rating', color='white', fontsize=12, fontweight='bold')
            
            # Style the figure
            for ax in [ax1, ax2]:
                ax.spines['bottom'].set_color('white')
                ax.spines['top'].set_color('white')
                ax.spines['right'].set_color('white')
                ax.spines['left'].set_color('white')
            
            plt.tight_layout()
            
            # Embed in tkinter
            canvas = FigureCanvasTkAgg(fig, self.viz_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="both", expand=True)
            
        except Exception as e:
            error_label = tk.Label(self.viz_frame, text=f"Error generating visualization: {str(e)}",
                                 bg=BG_COLOR, fg="red", font=("Consolas", 10))
            error_label.pack(expand=True)
    
    def display_batch_results(self, batch_results):
        """Display results from batch directory analysis"""
        if not batch_results:
            return
        
        # Sort by complexity
        batch_results.sort(key=lambda x: x['cognitive_complexity'], reverse=True)
        
        # Create summary
        total_files = len(batch_results)
        total_complexity = sum(r['cognitive_complexity'] for r in batch_results)
        avg_complexity = total_complexity / total_files if total_files > 0 else 0
        
        high_complexity_files = [r for r in batch_results if r['cognitive_complexity'] > 25]
        
        summary_text = f"""Batch Analysis Results
{'=' * 50}

Summary:
• Total Files Analyzed: {total_files}
• Total Complexity: {total_complexity}
• Average Complexity: {avg_complexity:.2f}
• High Complexity Files: {len(high_complexity_files)}

Top 10 Most Complex Files:
{'-' * 30}
"""
        
        for i, result in enumerate(batch_results[:10], 1):
            summary_text += f"{i:2d}. {result['file_name']} (Complexity: {result['cognitive_complexity']}, Rating: {result['rating']})\n"
        
        if high_complexity_files:
            summary_text += f"\nFiles Requiring Immediate Attention:\n{'-' * 30}\n"
            for result in high_complexity_files[:5]:
                summary_text += f"• {result['file_name']} (Complexity: {result['cognitive_complexity']})\n"
        
        self.update_results_tab("Summary", summary_text)
        
        # Set batch results for export
        self.set_results_data({
            'batch_summary': {
                'total_files': total_files,
                'total_complexity': total_complexity,
                'average_complexity': avg_complexity,
                'high_complexity_count': len(high_complexity_files)
            },
            'file_results': batch_results
        })
    
    def clear_results(self):
        """Clear all analysis results and visualizations"""
        self.current_results = None
        
        # Clear results tabs
        for tab_name in ["Summary", "Details", "Analysis", "Raw Data"]:
            self.update_results_tab(tab_name, "")
        
        # Clear visualization
        for widget in self.viz_frame.winfo_children():
            widget.destroy()
        
        placeholder_label = tk.Label(self.viz_frame, text="Select and analyze a file to see complexity visualization",
                                   bg=BG_COLOR, fg=TEXT_COLOR, font=("Consolas", 10))
        placeholder_label.pack(expand=True)
        
        # Reset progress
        self.update_progress(0, "Ready")
        
        messagebox.showinfo("Cleared", "All results have been cleared.")