# code_review_complexity_estimator.py - Code review complexity estimation and reviewer assignment tool
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import git
import os
import re
import ast
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Any, Optional, Tuple
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
from base_tool import AdvancedToolFrame
from utils.database import db_manager

TAB_NAME = "Code Review Complexity Estimator"

class ToolFrame(AdvancedToolFrame):
    """Code review complexity estimation and reviewer assignment optimization tool"""
    
    def __init__(self, master):
        tool_config = {
            'name': 'Code Review Complexity Estimator',
            'tool_id': 'code_review_complexity_estimator',
            'category': 'Project Management'
        }
        super().__init__(master, tool_config)
        
        self.repo = None
        self.review_history = []
        self.complexity_factors = {
            'lines_changed': 1.0,
            'files_changed': 2.0,
            'complexity_increase': 3.0,
            'new_files': 2.5,
            'test_coverage': -1.0,  # Negative because good tests reduce complexity
            'documentation': -0.5
        }
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface"""
        self.add_label("🔍 Code Review Complexity Estimator", ("Consolas", 16, "bold"))
        self.add_label("Estimate review complexity and optimize reviewer assignments")
        
        # Setup advanced UI components
        self.setup_advanced_ui()
        
        # Repository selection
        repo_frame = tk.Frame(self, bg=self.master.cget('bg'))
        repo_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(repo_frame, text="Git Repository:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.repo_path_var = tk.StringVar()
        repo_entry = tk.Entry(repo_frame, textvariable=self.repo_path_var, width=50)
        repo_entry.pack(side="left", padx=5, fill="x", expand=True)
        
        browse_btn = tk.Button(repo_frame, text="Browse", command=self.browse_repository)
        browse_btn.pack(side="right", padx=5)
        
        # Analysis mode selection
        mode_frame = tk.Frame(self, bg=self.master.cget('bg'))
        mode_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(mode_frame, text="Analysis Mode:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.analysis_mode = tk.StringVar(value="pull_request")
        mode_combo = ttk.Combobox(mode_frame, textvariable=self.analysis_mode,
                                 values=["pull_request", "commit_range", "file_changes"],
                                 state="readonly", width=20)
        mode_combo.pack(side="left", padx=5)
        
        # Input section based on mode
        self.create_input_sections()
        
        # Complexity factors configuration
        self.create_complexity_factors_section()
        
        # Reviewer database section
        self.create_reviewer_section()
        
        # Action buttons
        button_frame = tk.Frame(self, bg=self.master.cget('bg'))
        button_frame.pack(fill="x", padx=10, pady=10)
        
        self.analyze_btn = self.add_button("Analyze Complexity", self.analyze_complexity)
        self.suggest_reviewers_btn = self.add_button("Suggest Reviewers", self.suggest_reviewers)
        self.calibrate_btn = self.add_button("Calibrate Model", self.calibrate_model)
        
        self.suggest_reviewers_btn.config(state="disabled")
        
        # Status label
        self.status_label = tk.Label(self, text="Status: Ready", 
                                   bg=self.master.cget('bg'), fg="white")
        self.status_label.pack(pady=5)
    
    def create_input_sections(self):
        """Create input sections for different analysis modes"""
        # Pull Request Analysis
        self.pr_frame = tk.LabelFrame(self, text="Pull Request Analysis", 
                                     bg=self.master.cget('bg'), fg="white")
        self.pr_frame.pack(fill="x", padx=10, pady=5)
        
        pr_input_frame = tk.Frame(self.pr_frame, bg=self.master.cget('bg'))
        pr_input_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(pr_input_frame, text="PR Number/URL:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.pr_input_var = tk.StringVar()
        pr_entry = tk.Entry(pr_input_frame, textvariable=self.pr_input_var, width=40)
        pr_entry.pack(side="left", padx=5, fill="x", expand=True)
        
        # Commit Range Analysis
        self.commit_frame = tk.LabelFrame(self, text="Commit Range Analysis", 
                                         bg=self.master.cget('bg'), fg="white")
        self.commit_frame.pack(fill="x", padx=10, pady=5)
        
        commit_input_frame = tk.Frame(self.commit_frame, bg=self.master.cget('bg'))
        commit_input_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(commit_input_frame, text="From Commit:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        self.from_commit_var = tk.StringVar()
        tk.Entry(commit_input_frame, textvariable=self.from_commit_var, width=20).pack(side="left", padx=5)
        
        tk.Label(commit_input_frame, text="To Commit:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left", padx=(20, 0))
        self.to_commit_var = tk.StringVar()
        tk.Entry(commit_input_frame, textvariable=self.to_commit_var, width=20).pack(side="left", padx=5)
        
        # File Changes Analysis
        self.files_frame = tk.LabelFrame(self, text="File Changes Analysis", 
                                        bg=self.master.cget('bg'), fg="white")
        self.files_frame.pack(fill="x", padx=10, pady=5)
        
        files_input_frame = tk.Frame(self.files_frame, bg=self.master.cget('bg'))
        files_input_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(files_input_frame, text="Files to Analyze:", 
                bg=self.master.cget('bg'), fg="white").pack(anchor="w")
        
        self.files_text = tk.Text(files_input_frame, height=4, width=60,
                                 bg="#111111", fg="white", insertbackground="white")
        self.files_text.pack(fill="x", pady=5)
        
        tk.Button(files_input_frame, text="Browse Files", 
                 command=self.browse_files).pack(anchor="w")
    
    def create_complexity_factors_section(self):
        """Create complexity factors configuration section"""
        factors_frame = tk.LabelFrame(self, text="Complexity Factors", 
                                     bg=self.master.cget('bg'), fg="white")
        factors_frame.pack(fill="x", padx=10, pady=5)
        
        # Create factor adjustment controls
        self.factor_vars = {}
        
        factors_grid = tk.Frame(factors_frame, bg=self.master.cget('bg'))
        factors_grid.pack(fill="x", padx=5, pady=5)
        
        row = 0
        for factor, default_weight in self.complexity_factors.items():
            tk.Label(factors_grid, text=f"{factor.replace('_', ' ').title()}:", 
                    bg=self.master.cget('bg'), fg="white").grid(row=row, column=0, sticky="w", padx=5)
            
            var = tk.DoubleVar(value=default_weight)
            self.factor_vars[factor] = var
            
            scale = tk.Scale(factors_grid, from_=-2.0, to=5.0, resolution=0.1, 
                           orient="horizontal", variable=var, length=200,
                           bg=self.master.cget('bg'), fg="white")
            scale.grid(row=row, column=1, padx=5)
            
            tk.Label(factors_grid, text=f"{default_weight:.1f}", 
                    bg=self.master.cget('bg'), fg="white").grid(row=row, column=2, padx=5)
            
            row += 1
    
    def create_reviewer_section(self):
        """Create reviewer database section"""
        reviewer_frame = tk.LabelFrame(self, text="Reviewer Database", 
                                      bg=self.master.cget('bg'), fg="white")
        reviewer_frame.pack(fill="x", padx=10, pady=5)
        
        # Reviewer list
        list_frame = tk.Frame(reviewer_frame, bg=self.master.cget('bg'))
        list_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(list_frame, text="Available Reviewers:", 
                bg=self.master.cget('bg'), fg="white").pack(anchor="w")
        
        # Reviewer listbox with scrollbar
        listbox_frame = tk.Frame(list_frame, bg=self.master.cget('bg'))
        listbox_frame.pack(fill="x", pady=5)
        
        self.reviewer_listbox = tk.Listbox(listbox_frame, height=6, 
                                          bg="#111111", fg="white", selectmode="multiple")
        scrollbar = tk.Scrollbar(listbox_frame, orient="vertical", command=self.reviewer_listbox.yview)
        self.reviewer_listbox.configure(yscrollcommand=scrollbar.set)
        
        self.reviewer_listbox.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Add reviewer controls
        add_frame = tk.Frame(reviewer_frame, bg=self.master.cget('bg'))
        add_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(add_frame, text="Add Reviewer:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.new_reviewer_var = tk.StringVar()
        reviewer_entry = tk.Entry(add_frame, textvariable=self.new_reviewer_var, width=30)
        reviewer_entry.pack(side="left", padx=5)
        
        tk.Button(add_frame, text="Add", command=self.add_reviewer).pack(side="left", padx=5)
        tk.Button(add_frame, text="Remove", command=self.remove_reviewer).pack(side="left", padx=5)
        
        # Load existing reviewers
        self.load_reviewers()
    
    def browse_repository(self):
        """Browse for git repository directory"""
        directory = filedialog.askdirectory(title="Select Git Repository")
        if directory:
            self.repo_path_var.set(directory)
            self.load_repository(directory)
    
    def browse_files(self):
        """Browse for files to analyze"""
        files = filedialog.askopenfilenames(
            title="Select Files to Analyze",
            filetypes=[("Python files", "*.py"), ("JavaScript files", "*.js"), 
                      ("All files", "*.*")]
        )
        if files:
            file_list = "\n".join(files)
            self.files_text.delete("1.0", tk.END)
            self.files_text.insert("1.0", file_list)
    
    def load_repository(self, repo_path: str):
        """Load git repository"""
        try:
            self.repo = git.Repo(repo_path)
            self.status_label.config(text="Status: Repository loaded")
            
            # Load historical review data for calibration
            self.load_review_history()
            
        except git.exc.InvalidGitRepositoryError:
            messagebox.showerror("Error", "Selected directory is not a valid Git repository")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load repository: {str(e)}")
    
    def load_review_history(self):
        """Load historical review data for model calibration"""
        # This would typically load from a review system API (GitHub, GitLab, etc.)
        # For now, we'll simulate some historical data
        self.review_history = []
        
        try:
            # Analyze recent commits to build historical data
            commits = list(self.repo.iter_commits(max_count=100))
            
            for commit in commits:
                try:
                    stats = commit.stats.total
                    
                    # Simulate review time based on complexity
                    lines_changed = stats['lines']
                    files_changed = stats['files']
                    
                    # Simple heuristic for review time
                    estimated_time = (lines_changed * 0.5 + files_changed * 5) / 60  # hours
                    actual_time = estimated_time * (0.8 + np.random.random() * 0.4)  # Add some variance
                    
                    review_data = {
                        'commit_hash': commit.hexsha[:8],
                        'lines_changed': lines_changed,
                        'files_changed': files_changed,
                        'estimated_time': estimated_time,
                        'actual_time': actual_time,
                        'date': datetime.fromtimestamp(commit.committed_date)
                    }
                    
                    self.review_history.append(review_data)
                    
                except Exception:
                    continue
                    
        except Exception as e:
            print(f"Error loading review history: {e}")
    
    def add_reviewer(self):
        """Add a new reviewer to the database"""
        reviewer = self.new_reviewer_var.get().strip()
        if reviewer and reviewer not in self.reviewer_listbox.get(0, tk.END):
            self.reviewer_listbox.insert(tk.END, reviewer)
            self.new_reviewer_var.set("")
            self.save_reviewers()
    
    def remove_reviewer(self):
        """Remove selected reviewer from the database"""
        selection = self.reviewer_listbox.curselection()
        if selection:
            for index in reversed(selection):
                self.reviewer_listbox.delete(index)
            self.save_reviewers()
    
    def load_reviewers(self):
        """Load reviewers from database"""
        try:
            reviewers = db_manager.get_user_preference("code_review", "reviewers")
            if reviewers:
                for reviewer in reviewers:
                    self.reviewer_listbox.insert(tk.END, reviewer)
        except Exception as e:
            print(f"Error loading reviewers: {e}")
    
    def save_reviewers(self):
        """Save reviewers to database"""
        try:
            reviewers = list(self.reviewer_listbox.get(0, tk.END))
            db_manager.save_user_preference("code_review", "reviewers", reviewers)
        except Exception as e:
            print(f"Error saving reviewers: {e}")
    
    def analyze_complexity(self):
        """Analyze code review complexity based on selected mode"""
        if not self.repo:
            messagebox.showwarning("Warning", "Please select a Git repository first")
            return
        
        try:
            self.update_progress(10, "Starting complexity analysis")
            self.status_label.config(text="Status: Analyzing complexity...")
            
            mode = self.analysis_mode.get()
            
            if mode == "pull_request":
                complexity_data = self.analyze_pull_request()
            elif mode == "commit_range":
                complexity_data = self.analyze_commit_range()
            elif mode == "file_changes":
                complexity_data = self.analyze_file_changes()
            else:
                raise ValueError(f"Unknown analysis mode: {mode}")
            
            if not complexity_data:
                messagebox.showwarning("Warning", "No data found for analysis")
                return
            
            # Calculate complexity score
            self.update_progress(70, "Calculating complexity score")
            complexity_score = self.calculate_complexity_score(complexity_data)
            
            # Estimate review time
            estimated_time = self.estimate_review_time(complexity_score, complexity_data)
            
            # Generate recommendations
            recommendations = self.generate_recommendations(complexity_score, complexity_data)
            
            # Display results
            self.display_complexity_results(complexity_data, complexity_score, 
                                          estimated_time, recommendations)
            
            # Enable reviewer suggestions
            self.suggest_reviewers_btn.config(state="normal")
            
            self.update_progress(100, "Analysis complete")
            self.status_label.config(text="Status: Analysis complete")
            
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")
            self.update_progress(0, f"Error: {str(e)}")
    
    def analyze_pull_request(self) -> Dict:
        """Analyze pull request complexity (simulated)"""
        pr_input = self.pr_input_var.get().strip()
        if not pr_input:
            raise ValueError("Please enter a PR number or URL")
        
        # For demonstration, we'll analyze the latest commits
        # In a real implementation, this would fetch PR data from GitHub/GitLab API
        
        commits = list(self.repo.iter_commits(max_count=10))
        if not commits:
            return {}
        
        # Aggregate data from recent commits
        total_lines = 0
        total_files = 0
        file_types = Counter()
        complexity_metrics = []
        
        for commit in commits[:5]:  # Analyze last 5 commits as "PR"
            try:
                stats = commit.stats.total
                total_lines += stats['lines']
                total_files += stats['files']
                
                # Analyze changed files
                for file_path in commit.stats.files:
                    file_ext = os.path.splitext(file_path)[1]
                    file_types[file_ext] += 1
                    
                    # Calculate file complexity if it's a Python file
                    if file_ext == '.py':
                        complexity = self.calculate_file_complexity(file_path)
                        if complexity:
                            complexity_metrics.append(complexity)
                            
            except Exception:
                continue
        
        return {
            'type': 'pull_request',
            'pr_identifier': pr_input,
            'lines_changed': total_lines,
            'files_changed': total_files,
            'file_types': dict(file_types),
            'complexity_metrics': complexity_metrics,
            'commits_analyzed': min(5, len(commits))
        }
    
    def analyze_commit_range(self) -> Dict:
        """Analyze commit range complexity"""
        from_commit = self.from_commit_var.get().strip()
        to_commit = self.to_commit_var.get().strip()
        
        if not from_commit or not to_commit:
            raise ValueError("Please enter both from and to commit hashes")
        
        try:
            # Get commits in range
            commits = list(self.repo.iter_commits(f"{from_commit}..{to_commit}"))
            
            total_lines = 0
            total_files = 0
            file_types = Counter()
            complexity_metrics = []
            
            for commit in commits:
                try:
                    stats = commit.stats.total
                    total_lines += stats['lines']
                    total_files += stats['files']
                    
                    for file_path in commit.stats.files:
                        file_ext = os.path.splitext(file_path)[1]
                        file_types[file_ext] += 1
                        
                        if file_ext == '.py':
                            complexity = self.calculate_file_complexity(file_path)
                            if complexity:
                                complexity_metrics.append(complexity)
                                
                except Exception:
                    continue
            
            return {
                'type': 'commit_range',
                'from_commit': from_commit,
                'to_commit': to_commit,
                'lines_changed': total_lines,
                'files_changed': total_files,
                'file_types': dict(file_types),
                'complexity_metrics': complexity_metrics,
                'commits_analyzed': len(commits)
            }
            
        except Exception as e:
            raise ValueError(f"Invalid commit range: {str(e)}")
    
    def analyze_file_changes(self) -> Dict:
        """Analyze specific file changes complexity"""
        files_text = self.files_text.get("1.0", tk.END).strip()
        if not files_text:
            raise ValueError("Please specify files to analyze")
        
        file_paths = [f.strip() for f in files_text.split('\n') if f.strip()]
        
        total_lines = 0
        file_types = Counter()
        complexity_metrics = []
        
        for file_path in file_paths:
            if os.path.exists(file_path):
                # Count lines in file
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        lines = len(f.readlines())
                    total_lines += lines
                    
                    file_ext = os.path.splitext(file_path)[1]
                    file_types[file_ext] += 1
                    
                    if file_ext == '.py':
                        complexity = self.calculate_file_complexity(file_path)
                        if complexity:
                            complexity_metrics.append(complexity)
                            
                except Exception:
                    continue
        
        return {
            'type': 'file_changes',
            'files_analyzed': file_paths,
            'lines_changed': total_lines,
            'files_changed': len(file_paths),
            'file_types': dict(file_types),
            'complexity_metrics': complexity_metrics
        }
    
    def calculate_file_complexity(self, file_path: str) -> Optional[Dict]:
        """Calculate complexity metrics for a Python file"""
        try:
            if not os.path.exists(file_path) or not file_path.endswith('.py'):
                return None
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse AST
            tree = ast.parse(content)
            
            # Count various complexity indicators
            complexity_data = {
                'file_path': file_path,
                'lines_of_code': len(content.split('\n')),
                'functions': 0,
                'classes': 0,
                'imports': 0,
                'nested_depth': 0,
                'cyclomatic_complexity': 1  # Base complexity
            }
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    complexity_data['functions'] += 1
                elif isinstance(node, ast.ClassDef):
                    complexity_data['classes'] += 1
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    complexity_data['imports'] += 1
                elif isinstance(node, (ast.If, ast.While, ast.For, ast.Try)):
                    complexity_data['cyclomatic_complexity'] += 1
            
            return complexity_data
            
        except Exception as e:
            print(f"Error analyzing file {file_path}: {e}")
            return None
    
    def calculate_complexity_score(self, complexity_data: Dict) -> float:
        """Calculate overall complexity score based on factors"""
        score = 0.0
        
        # Update complexity factors from UI
        for factor, var in self.factor_vars.items():
            self.complexity_factors[factor] = var.get()
        
        # Base factors
        score += complexity_data.get('lines_changed', 0) * self.complexity_factors['lines_changed']
        score += complexity_data.get('files_changed', 0) * self.complexity_factors['files_changed']
        
        # File type complexity
        file_types = complexity_data.get('file_types', {})
        for file_type, count in file_types.items():
            if file_type in ['.py', '.js', '.java', '.cpp']:
                score += count * 2.0  # Code files are more complex
            elif file_type in ['.md', '.txt', '.rst']:
                score += count * 0.5  # Documentation is less complex
            else:
                score += count * 1.0  # Default complexity
        
        # Code complexity metrics
        complexity_metrics = complexity_data.get('complexity_metrics', [])
        if complexity_metrics:
            avg_cyclomatic = np.mean([m.get('cyclomatic_complexity', 1) for m in complexity_metrics])
            score += avg_cyclomatic * self.complexity_factors['complexity_increase']
        
        # Normalize score (0-100 scale)
        normalized_score = min(100, max(0, score / 10))
        
        return normalized_score
    
    def estimate_review_time(self, complexity_score: float, complexity_data: Dict) -> Dict:
        """Estimate review time based on complexity"""
        # Base time estimation (in hours)
        base_time = complexity_score * 0.1  # 0.1 hours per complexity point
        
        # Adjust based on specific factors
        lines_factor = complexity_data.get('lines_changed', 0) * 0.002  # 2 minutes per 100 lines
        files_factor = complexity_data.get('files_changed', 0) * 0.1    # 6 minutes per file
        
        estimated_hours = base_time + lines_factor + files_factor
        
        # Add confidence interval based on historical data
        confidence = 0.7  # Default confidence
        if self.review_history:
            # Calculate confidence based on historical accuracy
            historical_accuracy = self.calculate_historical_accuracy()
            confidence = max(0.5, min(0.9, historical_accuracy))
        
        return {
            'estimated_hours': estimated_hours,
            'estimated_minutes': estimated_hours * 60,
            'confidence': confidence,
            'range_low': estimated_hours * 0.7,
            'range_high': estimated_hours * 1.3
        }
    
    def calculate_historical_accuracy(self) -> float:
        """Calculate historical estimation accuracy"""
        if not self.review_history:
            return 0.7
        
        accuracies = []
        for review in self.review_history:
            estimated = review.get('estimated_time', 0)
            actual = review.get('actual_time', 0)
            
            if estimated > 0 and actual > 0:
                accuracy = 1 - abs(estimated - actual) / max(estimated, actual)
                accuracies.append(max(0, accuracy))
        
        return np.mean(accuracies) if accuracies else 0.7
    
    def generate_recommendations(self, complexity_score: float, complexity_data: Dict) -> List[str]:
        """Generate recommendations based on complexity analysis"""
        recommendations = []
        
        if complexity_score > 80:
            recommendations.append("CRITICAL: Very high complexity - consider breaking into smaller reviews")
            recommendations.append("Assign multiple experienced reviewers")
            recommendations.append("Schedule dedicated review time blocks")
        elif complexity_score > 60:
            recommendations.append("HIGH: Complex review - assign experienced reviewer")
            recommendations.append("Allow extra time for thorough review")
        elif complexity_score > 40:
            recommendations.append("MEDIUM: Standard complexity - normal review process")
        else:
            recommendations.append("LOW: Simple review - can be handled quickly")
        
        # Specific recommendations based on data
        lines_changed = complexity_data.get('lines_changed', 0)
        files_changed = complexity_data.get('files_changed', 0)
        
        if lines_changed > 1000:
            recommendations.append("Large changeset - consider reviewing in chunks")
        
        if files_changed > 20:
            recommendations.append("Many files changed - focus on architectural impact")
        
        file_types = complexity_data.get('file_types', {})
        if '.py' in file_types and file_types['.py'] > 10:
            recommendations.append("Many Python files - ensure code quality standards")
        
        complexity_metrics = complexity_data.get('complexity_metrics', [])
        if complexity_metrics:
            high_complexity_files = [m for m in complexity_metrics 
                                   if m.get('cyclomatic_complexity', 0) > 10]
            if high_complexity_files:
                recommendations.append("High complexity files detected - focus on logic review")
        
        return recommendations
    
    def display_complexity_results(self, complexity_data: Dict, complexity_score: float,
                                 estimated_time: Dict, recommendations: List[str]):
        """Display complexity analysis results"""
        # Summary tab
        summary_text = f"""Code Review Complexity Analysis
{'='*50}

Analysis Type: {complexity_data.get('type', 'Unknown').replace('_', ' ').title()}
Complexity Score: {complexity_score:.1f}/100

Change Summary:
• Lines Changed: {complexity_data.get('lines_changed', 0):,}
• Files Changed: {complexity_data.get('files_changed', 0)}
• Commits Analyzed: {complexity_data.get('commits_analyzed', 0)}

Time Estimation:
• Estimated Time: {estimated_time['estimated_hours']:.1f} hours ({estimated_time['estimated_minutes']:.0f} minutes)
• Confidence: {estimated_time['confidence']*100:.0f}%
• Range: {estimated_time['range_low']:.1f} - {estimated_time['range_high']:.1f} hours

Complexity Level: {self.get_complexity_level(complexity_score)}
"""
        
        self.update_results_tab("Summary", summary_text)
        
        # Details tab
        details_text = "Detailed Analysis:\n\n"
        
        file_types = complexity_data.get('file_types', {})
        if file_types:
            details_text += "File Types Distribution:\n"
            for file_type, count in sorted(file_types.items()):
                details_text += f"• {file_type or 'No extension'}: {count} files\n"
            details_text += "\n"
        
        complexity_metrics = complexity_data.get('complexity_metrics', [])
        if complexity_metrics:
            details_text += "Code Complexity Metrics:\n"
            for metric in complexity_metrics[:10]:  # Show top 10
                details_text += f"• {os.path.basename(metric['file_path'])}: "
                details_text += f"Cyclomatic: {metric['cyclomatic_complexity']}, "
                details_text += f"Functions: {metric['functions']}, "
                details_text += f"Classes: {metric['classes']}\n"
        
        self.update_results_tab("Details", details_text)
        
        # Analysis tab - Recommendations
        analysis_text = "Review Recommendations:\n\n"
        for i, rec in enumerate(recommendations, 1):
            analysis_text += f"{i}. {rec}\n\n"
        
        analysis_text += "\nComplexity Factors Used:\n"
        for factor, weight in self.complexity_factors.items():
            analysis_text += f"• {factor.replace('_', ' ').title()}: {weight:.1f}\n"
        
        self.update_results_tab("Analysis", analysis_text)
        
        # Create visualization
        self.create_complexity_visualization(complexity_data, complexity_score)
        
        # Save results
        self.save_complexity_analysis(complexity_data, complexity_score, estimated_time, recommendations)
    
    def get_complexity_level(self, score: float) -> str:
        """Get complexity level description"""
        if score >= 80:
            return "VERY HIGH"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "VERY LOW"
    
    def create_complexity_visualization(self, complexity_data: Dict, complexity_score: float):
        """Create visualization for complexity analysis"""
        try:
            fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(12, 10))
            
            # Complexity score gauge
            ax1.pie([complexity_score, 100-complexity_score], 
                   labels=['Complexity', 'Remaining'], 
                   colors=['red' if complexity_score > 60 else 'orange' if complexity_score > 40 else 'green', 'lightgray'],
                   startangle=90)
            ax1.set_title(f'Complexity Score: {complexity_score:.1f}/100')
            
            # File types distribution
            file_types = complexity_data.get('file_types', {})
            if file_types:
                types = list(file_types.keys())
                counts = list(file_types.values())
                
                ax2.bar(types, counts, alpha=0.7)
                ax2.set_title('File Types Distribution')
                ax2.set_ylabel('Number of Files')
                ax2.tick_params(axis='x', rotation=45)
            
            # Complexity factors contribution
            factors = list(self.complexity_factors.keys())
            weights = list(self.complexity_factors.values())
            
            ax3.barh(factors, weights, alpha=0.7)
            ax3.set_title('Complexity Factors Weights')
            ax3.set_xlabel('Weight')
            
            # Historical accuracy (if available)
            if self.review_history:
                estimated_times = [r.get('estimated_time', 0) for r in self.review_history[-20:]]
                actual_times = [r.get('actual_time', 0) for r in self.review_history[-20:]]
                
                ax4.scatter(estimated_times, actual_times, alpha=0.7)
                ax4.plot([0, max(max(estimated_times), max(actual_times))], 
                        [0, max(max(estimated_times), max(actual_times))], 'r--', alpha=0.5)
                ax4.set_xlabel('Estimated Time (hours)')
                ax4.set_ylabel('Actual Time (hours)')
                ax4.set_title('Estimation Accuracy')
            else:
                ax4.text(0.5, 0.5, 'No historical data', ha='center', va='center', 
                        transform=ax4.transAxes)
                ax4.set_title('Historical Data')
            
            plt.tight_layout()
            
        except Exception as e:
            print(f"Visualization error: {e}")
    
    def suggest_reviewers(self):
        """Suggest optimal reviewer assignments"""
        if not hasattr(self, 'current_complexity_score'):
            messagebox.showwarning("Warning", "Please run complexity analysis first")
            return
        
        reviewers = list(self.reviewer_listbox.get(0, tk.END))
        if not reviewers:
            messagebox.showwarning("Warning", "No reviewers available. Please add reviewers first.")
            return
        
        # Create reviewer suggestion window
        suggestion_window = tk.Toplevel(self)
        suggestion_window.title("Reviewer Suggestions")
        suggestion_window.geometry("500x400")
        suggestion_window.configure(bg=self.master.cget('bg'))
        
        tk.Label(suggestion_window, text="Reviewer Assignment Suggestions", 
                font=("Consolas", 14, "bold"), bg=self.master.cget('bg'), fg="white").pack(pady=10)
        
        # Suggestions text
        suggestions_text = tk.Text(suggestion_window, height=20, width=60, 
                                  bg="#111111", fg="white", wrap="word")
        suggestions_text.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Generate suggestions based on complexity
        complexity_score = getattr(self, 'current_complexity_score', 50)
        
        suggestion_content = f"""Reviewer Assignment Recommendations
{'='*50}

Complexity Score: {complexity_score:.1f}/100
Complexity Level: {self.get_complexity_level(complexity_score)}

Recommended Assignment Strategy:
"""
        
        if complexity_score >= 80:
            suggestion_content += """
• Assign 2-3 senior reviewers
• Stagger reviews (architectural first, then detailed)
• Schedule dedicated review sessions
• Consider pair review for critical sections

Suggested Reviewers:
"""
            # Suggest multiple reviewers for high complexity
            for i, reviewer in enumerate(reviewers[:3]):
                suggestion_content += f"• {reviewer} (Primary reviewer {i+1})\n"
                
        elif complexity_score >= 60:
            suggestion_content += """
• Assign 1-2 experienced reviewers
• Allow extra time for thorough review
• Focus on architectural and logic review

Suggested Reviewers:
"""
            for i, reviewer in enumerate(reviewers[:2]):
                suggestion_content += f"• {reviewer} (Reviewer {i+1})\n"
                
        elif complexity_score >= 40:
            suggestion_content += """
• Assign 1 experienced reviewer
• Standard review process
• Focus on code quality and standards

Suggested Reviewer:
"""
            if reviewers:
                suggestion_content += f"• {reviewers[0]} (Primary reviewer)\n"
                
        else:
            suggestion_content += """
• Can be reviewed by any available reviewer
• Quick review process
• Focus on basic standards and style

Suggested Reviewer:
"""
            if reviewers:
                suggestion_content += f"• {reviewers[-1]} (Any available reviewer)\n"
        
        suggestion_content += f"""

Review Time Allocation:
• Estimated time: {getattr(self, 'current_estimated_time', {}).get('estimated_hours', 1):.1f} hours
• Recommended deadline: {(datetime.now() + timedelta(days=2)).strftime('%Y-%m-%d')}

Additional Recommendations:
• Use review checklist for consistency
• Document review decisions and rationale
• Follow up on feedback implementation
"""
        
        suggestions_text.insert("1.0", suggestion_content)
        suggestions_text.config(state="disabled")
    
    def calibrate_model(self):
        """Calibrate the complexity estimation model"""
        if not self.review_history:
            messagebox.showwarning("Warning", "No historical data available for calibration")
            return
        
        try:
            # Simple calibration based on historical accuracy
            accuracy = self.calculate_historical_accuracy()
            
            calibration_text = f"""Model Calibration Results
{'='*40}

Historical Data Points: {len(self.review_history)}
Current Accuracy: {accuracy*100:.1f}%

Calibration Suggestions:
"""
            
            if accuracy < 0.6:
                calibration_text += """
• Model needs significant adjustment
• Consider revising complexity factors
• Collect more historical data
• Review estimation methodology
"""
            elif accuracy < 0.8:
                calibration_text += """
• Model performance is acceptable
• Minor adjustments may improve accuracy
• Continue collecting data for refinement
"""
            else:
                calibration_text += """
• Model performance is good
• Current factors appear well-calibrated
• Maintain current configuration
"""
            
            # Show calibration results
            messagebox.showinfo("Calibration Results", calibration_text)
            
        except Exception as e:
            messagebox.showerror("Error", f"Calibration failed: {str(e)}")
    
    def save_complexity_analysis(self, complexity_data: Dict, complexity_score: float,
                                estimated_time: Dict, recommendations: List[str]):
        """Save complexity analysis results"""
        try:
            analysis_id = f"complexity_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Store current results for reviewer suggestions
            self.current_complexity_score = complexity_score
            self.current_estimated_time = estimated_time
            
            input_data = {
                'analysis_mode': self.analysis_mode.get(),
                'repository_path': self.repo_path_var.get(),
                'complexity_factors': self.complexity_factors.copy()
            }
            
            summary = {
                'complexity_score': complexity_score,
                'estimated_hours': estimated_time['estimated_hours'],
                'confidence': estimated_time['confidence'],
                'complexity_level': self.get_complexity_level(complexity_score)
            }
            
            self.save_analysis_result(
                analysis_id=analysis_id,
                input_data=input_data,
                results_summary=summary,
                detailed_findings=[],
                recommendations=recommendations,
                metrics=complexity_data
            )
            
            # Set results for export
            export_data = {
                'complexity_data': complexity_data,
                'complexity_score': complexity_score,
                'estimated_time': estimated_time,
                'recommendations': recommendations
            }
            self.set_results_data(export_data)
            
        except Exception as e:
            print(f"Error saving analysis: {e}")


def create_code_review_complexity_estimator(parent):
    """Factory function to create the Code Review Complexity Estimator tool"""
    return CodeReviewComplexityEstimator(parent)