# commit_pattern_analyzer.py - Git commit pattern analysis and velocity tracking tool
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import git
import os
import re
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Any, Optional, Tuple
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import pandas as pd
from base_tool import AdvancedToolFrame
from utils.database import db_manager

TAB_NAME = "Commit Pattern Analyzer"

class ToolFrame(AdvancedToolFrame):
    """Git commit pattern analysis and development velocity tracking tool"""
    
    def __init__(self, master):
        tool_config = {
            'name': 'Commit Pattern Analyzer',
            'tool_id': 'commit_pattern_analyzer',
            'category': 'Project Management'
        }
        super().__init__(master, tool_config)
        
        self.repo = None
        self.commits_data = []
        self.analysis_results = {}
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface"""
        self.add_label("📊 Commit Pattern Analyzer", ("Consolas", 16, "bold"))
        self.add_label("Analyze git history, calculate development velocity, and predict project timelines")
        
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
        
        # Analysis options
        options_frame = tk.LabelFrame(self, text="Analysis Options", 
                                     bg=self.master.cget('bg'), fg="white")
        options_frame.pack(fill="x", padx=10, pady=5)
        
        # Time range
        time_frame = tk.Frame(options_frame, bg=self.master.cget('bg'))
        time_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(time_frame, text="Analysis Period:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.period_var = tk.StringVar(value="6_months")
        period_combo = ttk.Combobox(time_frame, textvariable=self.period_var,
                                   values=["1_month", "3_months", "6_months", "1_year", "all_time"],
                                   state="readonly", width=15)
        period_combo.pack(side="left", padx=5)
        
        # Branch selection
        tk.Label(time_frame, text="Branch:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left", padx=(20, 0))
        
        self.branch_var = tk.StringVar(value="main")
        self.branch_combo = ttk.Combobox(time_frame, textvariable=self.branch_var,
                                        width=15, state="readonly")
        self.branch_combo.pack(side="left", padx=5)
        
        # Analysis types
        analysis_frame = tk.Frame(options_frame, bg=self.master.cget('bg'))
        analysis_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(analysis_frame, text="Include:", bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.analyze_velocity = tk.BooleanVar(value=True)
        self.analyze_patterns = tk.BooleanVar(value=True)
        self.analyze_contributors = tk.BooleanVar(value=True)
        self.analyze_files = tk.BooleanVar(value=True)
        
        tk.Checkbutton(analysis_frame, text="Velocity", variable=self.analyze_velocity,
                      bg=self.master.cget('bg'), fg="white", selectcolor="#333333").pack(side="left", padx=5)
        tk.Checkbutton(analysis_frame, text="Patterns", variable=self.analyze_patterns,
                      bg=self.master.cget('bg'), fg="white", selectcolor="#333333").pack(side="left", padx=5)
        tk.Checkbutton(analysis_frame, text="Contributors", variable=self.analyze_contributors,
                      bg=self.master.cget('bg'), fg="white", selectcolor="#333333").pack(side="left", padx=5)
        tk.Checkbutton(analysis_frame, text="File Changes", variable=self.analyze_files,
                      bg=self.master.cget('bg'), fg="white", selectcolor="#333333").pack(side="left", padx=5)
        
        # Action buttons
        button_frame = tk.Frame(self, bg=self.master.cget('bg'))
        button_frame.pack(fill="x", padx=10, pady=10)
        
        self.analyze_btn = self.add_button("Analyze Repository", self.analyze_repository)
        self.predict_btn = self.add_button("Predict Timeline", self.predict_timeline)
        self.export_btn = self.add_button("Export Report", self.export_analysis_report)
        
        self.predict_btn.config(state="disabled")
        self.export_btn.config(state="disabled")
        
        # Status label
        self.status_label = tk.Label(self, text="Status: Ready", 
                                   bg=self.master.cget('bg'), fg="white")
        self.status_label.pack(pady=5)
    
    def browse_repository(self):
        """Browse for git repository directory"""
        directory = filedialog.askdirectory(title="Select Git Repository")
        if directory:
            self.repo_path_var.set(directory)
            self.load_repository_info(directory)
    
    def load_repository_info(self, repo_path: str):
        """Load repository information and populate branch list"""
        try:
            self.repo = git.Repo(repo_path)
            
            # Get available branches
            branches = [ref.name.split('/')[-1] for ref in self.repo.refs if isinstance(ref, git.RemoteReference)]
            local_branches = [ref.name for ref in self.repo.heads]
            
            all_branches = list(set(branches + local_branches))
            if 'main' not in all_branches and 'master' in all_branches:
                all_branches.insert(0, 'master')
            elif 'main' in all_branches:
                all_branches.insert(0, 'main')
            
            self.branch_combo['values'] = all_branches
            if all_branches:
                self.branch_combo.current(0)
            
            self.status_label.config(text=f"Status: Repository loaded - {len(all_branches)} branches found")
            
        except git.exc.InvalidGitRepositoryError:
            messagebox.showerror("Error", "Selected directory is not a valid Git repository")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load repository: {str(e)}")
    
    def analyze_repository(self):
        """Analyze the git repository for commit patterns and velocity"""
        if not self.repo:
            messagebox.showwarning("Warning", "Please select a Git repository first")
            return
        
        try:
            self.update_progress(10, "Starting repository analysis")
            self.status_label.config(text="Status: Analyzing repository...")
            
            # Get analysis parameters
            period = self.period_var.get()
            branch = self.branch_var.get()
            
            # Calculate date range
            end_date = datetime.now()
            if period == "1_month":
                start_date = end_date - timedelta(days=30)
            elif period == "3_months":
                start_date = end_date - timedelta(days=90)
            elif period == "6_months":
                start_date = end_date - timedelta(days=180)
            elif period == "1_year":
                start_date = end_date - timedelta(days=365)
            else:  # all_time
                start_date = None
            
            # Extract commit data
            self.update_progress(30, "Extracting commit data")
            self.commits_data = self.extract_commit_data(branch, start_date, end_date)
            
            if not self.commits_data:
                messagebox.showwarning("Warning", "No commits found in the specified time range")
                return
            
            # Perform analysis
            self.analysis_results = {}
            
            if self.analyze_velocity.get():
                self.update_progress(50, "Analyzing velocity")
                self.analysis_results['velocity'] = self.analyze_commit_velocity()
            
            if self.analyze_patterns.get():
                self.update_progress(60, "Analyzing patterns")
                self.analysis_results['patterns'] = self.analyze_commit_patterns()
            
            if self.analyze_contributors.get():
                self.update_progress(70, "Analyzing contributors")
                self.analysis_results['contributors'] = self.analyze_contributors_activity()
            
            if self.analyze_files.get():
                self.update_progress(80, "Analyzing file changes")
                self.analysis_results['files'] = self.analyze_file_changes()
            
            # Generate risk assessment
            self.update_progress(90, "Generating risk assessment")
            self.analysis_results['risks'] = self.assess_project_risks()
            
            # Display results
            self.display_analysis_results()
            
            # Enable additional buttons
            self.predict_btn.config(state="normal")
            self.export_btn.config(state="normal")
            
            self.update_progress(100, "Analysis complete")
            self.status_label.config(text="Status: Analysis complete")
            
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")
            self.update_progress(0, f"Error: {str(e)}")
    
    def extract_commit_data(self, branch: str, start_date: Optional[datetime], 
                           end_date: datetime) -> List[Dict]:
        """Extract commit data from the repository"""
        commits = []
        
        try:
            # Get commits from specified branch
            if branch in [ref.name for ref in self.repo.heads]:
                commit_iter = self.repo.iter_commits(branch)
            else:
                commit_iter = self.repo.iter_commits(f"origin/{branch}")
            
            for commit in commit_iter:
                commit_date = datetime.fromtimestamp(commit.committed_date)
                
                # Filter by date range
                if start_date and commit_date < start_date:
                    break
                if commit_date > end_date:
                    continue
                
                # Calculate commit complexity (lines changed)
                try:
                    stats = commit.stats.total
                    lines_changed = stats['lines']
                    files_changed = stats['files']
                except:
                    lines_changed = 0
                    files_changed = 0
                
                # Extract commit info
                commit_data = {
                    'hash': commit.hexsha[:8],
                    'author': commit.author.name,
                    'email': commit.author.email,
                    'date': commit_date,
                    'message': commit.message.strip(),
                    'lines_changed': lines_changed,
                    'files_changed': files_changed,
                    'insertions': stats.get('insertions', 0) if 'stats' in locals() else 0,
                    'deletions': stats.get('deletions', 0) if 'stats' in locals() else 0
                }
                
                # Categorize commit type
                commit_data['type'] = self.categorize_commit(commit.message)
                
                commits.append(commit_data)
        
        except Exception as e:
            print(f"Error extracting commits: {e}")
        
        return commits
    
    def categorize_commit(self, message: str) -> str:
        """Categorize commit based on message"""
        message_lower = message.lower()
        
        if any(keyword in message_lower for keyword in ['fix', 'bug', 'error', 'issue']):
            return 'bugfix'
        elif any(keyword in message_lower for keyword in ['feat', 'feature', 'add', 'new']):
            return 'feature'
        elif any(keyword in message_lower for keyword in ['refactor', 'cleanup', 'improve']):
            return 'refactor'
        elif any(keyword in message_lower for keyword in ['doc', 'readme', 'comment']):
            return 'documentation'
        elif any(keyword in message_lower for keyword in ['test', 'spec']):
            return 'test'
        elif any(keyword in message_lower for keyword in ['merge', 'pull']):
            return 'merge'
        else:
            return 'other'
    
    def analyze_commit_velocity(self) -> Dict:
        """Analyze development velocity metrics"""
        if not self.commits_data:
            return {}
        
        # Group commits by day/week/month
        daily_commits = defaultdict(int)
        daily_lines = defaultdict(int)
        weekly_commits = defaultdict(int)
        weekly_lines = defaultdict(int)
        
        for commit in self.commits_data:
            date = commit['date']
            day_key = date.strftime('%Y-%m-%d')
            week_key = date.strftime('%Y-W%U')
            
            daily_commits[day_key] += 1
            daily_lines[day_key] += commit['lines_changed']
            weekly_commits[week_key] += 1
            weekly_lines[week_key] += commit['lines_changed']
        
        # Calculate velocity metrics
        total_commits = len(self.commits_data)
        total_lines = sum(commit['lines_changed'] for commit in self.commits_data)
        total_days = (max(commit['date'] for commit in self.commits_data) - 
                     min(commit['date'] for commit in self.commits_data)).days + 1
        
        avg_commits_per_day = total_commits / total_days if total_days > 0 else 0
        avg_lines_per_day = total_lines / total_days if total_days > 0 else 0
        avg_lines_per_commit = total_lines / total_commits if total_commits > 0 else 0
        
        # Calculate trends
        recent_days = 14  # Last 2 weeks
        recent_commits = [c for c in self.commits_data 
                         if (datetime.now() - c['date']).days <= recent_days]
        
        recent_velocity = len(recent_commits) / recent_days if recent_days > 0 else 0
        velocity_trend = "increasing" if recent_velocity > avg_commits_per_day else "decreasing"
        
        return {
            'total_commits': total_commits,
            'total_lines_changed': total_lines,
            'analysis_period_days': total_days,
            'avg_commits_per_day': avg_commits_per_day,
            'avg_lines_per_day': avg_lines_per_day,
            'avg_lines_per_commit': avg_lines_per_commit,
            'recent_velocity': recent_velocity,
            'velocity_trend': velocity_trend,
            'daily_commits': dict(daily_commits),
            'weekly_commits': dict(weekly_commits),
            'daily_lines': dict(daily_lines),
            'weekly_lines': dict(weekly_lines)
        }
    
    def analyze_commit_patterns(self) -> Dict:
        """Analyze commit timing and frequency patterns"""
        if not self.commits_data:
            return {}
        
        # Analyze commit timing patterns
        hour_distribution = defaultdict(int)
        day_distribution = defaultdict(int)
        commit_types = defaultdict(int)
        
        for commit in self.commits_data:
            hour = commit['date'].hour
            day = commit['date'].strftime('%A')
            commit_type = commit['type']
            
            hour_distribution[hour] += 1
            day_distribution[day] += 1
            commit_types[commit_type] += 1
        
        # Find peak hours and days
        peak_hour = max(hour_distribution.items(), key=lambda x: x[1])[0] if hour_distribution else 0
        peak_day = max(day_distribution.items(), key=lambda x: x[1])[0] if day_distribution else "Unknown"
        
        # Analyze commit message patterns
        message_lengths = [len(commit['message']) for commit in self.commits_data]
        avg_message_length = np.mean(message_lengths) if message_lengths else 0
        
        # Analyze commit size patterns
        commit_sizes = [commit['lines_changed'] for commit in self.commits_data]
        small_commits = sum(1 for size in commit_sizes if size < 50)
        medium_commits = sum(1 for size in commit_sizes if 50 <= size < 200)
        large_commits = sum(1 for size in commit_sizes if size >= 200)
        
        return {
            'hour_distribution': dict(hour_distribution),
            'day_distribution': dict(day_distribution),
            'commit_types': dict(commit_types),
            'peak_hour': peak_hour,
            'peak_day': peak_day,
            'avg_message_length': avg_message_length,
            'commit_size_distribution': {
                'small': small_commits,
                'medium': medium_commits,
                'large': large_commits
            }
        }
    
    def analyze_contributors_activity(self) -> Dict:
        """Analyze contributor activity and collaboration patterns"""
        if not self.commits_data:
            return {}
        
        # Analyze contributor metrics
        contributor_commits = defaultdict(int)
        contributor_lines = defaultdict(int)
        contributor_files = defaultdict(set)
        
        for commit in self.commits_data:
            author = commit['author']
            contributor_commits[author] += 1
            contributor_lines[author] += commit['lines_changed']
            contributor_files[author].add(commit['files_changed'])
        
        # Calculate contributor statistics
        total_contributors = len(contributor_commits)
        active_contributors = sum(1 for commits in contributor_commits.values() if commits >= 5)
        
        # Find top contributors
        top_contributors = sorted(contributor_commits.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Calculate collaboration metrics
        bus_factor = min(3, len([c for c in contributor_commits.values() if c >= total_contributors * 0.1]))
        
        return {
            'total_contributors': total_contributors,
            'active_contributors': active_contributors,
            'top_contributors': top_contributors,
            'contributor_commits': dict(contributor_commits),
            'contributor_lines': dict(contributor_lines),
            'bus_factor': bus_factor,
            'collaboration_score': active_contributors / total_contributors if total_contributors > 0 else 0
        }
    
    def analyze_file_changes(self) -> Dict:
        """Analyze file change patterns and hotspots"""
        if not self.commits_data:
            return {}
        
        # This is a simplified analysis since we don't have detailed file info
        # In a real implementation, you'd analyze git diff data
        
        total_files_changed = sum(commit['files_changed'] for commit in self.commits_data)
        avg_files_per_commit = total_files_changed / len(self.commits_data) if self.commits_data else 0
        
        # Analyze commit complexity
        complex_commits = sum(1 for commit in self.commits_data if commit['lines_changed'] > 500)
        simple_commits = sum(1 for commit in self.commits_data if commit['lines_changed'] < 50)
        
        return {
            'total_files_changed': total_files_changed,
            'avg_files_per_commit': avg_files_per_commit,
            'complex_commits': complex_commits,
            'simple_commits': simple_commits,
            'complexity_ratio': complex_commits / len(self.commits_data) if self.commits_data else 0
        }
    
    def assess_project_risks(self) -> Dict:
        """Assess project risks based on commit patterns"""
        risks = []
        risk_score = 0
        
        if 'velocity' in self.analysis_results:
            velocity = self.analysis_results['velocity']
            
            # Low velocity risk
            if velocity['avg_commits_per_day'] < 1:
                risks.append("Low development velocity detected")
                risk_score += 2
            
            # Decreasing velocity trend
            if velocity['velocity_trend'] == 'decreasing':
                risks.append("Development velocity is decreasing")
                risk_score += 1
        
        if 'contributors' in self.analysis_results:
            contributors = self.analysis_results['contributors']
            
            # Bus factor risk
            if contributors['bus_factor'] <= 1:
                risks.append("Critical: Very low bus factor - project depends on single contributor")
                risk_score += 3
            elif contributors['bus_factor'] <= 2:
                risks.append("Low bus factor - limited contributor diversity")
                risk_score += 2
            
            # Low collaboration
            if contributors['collaboration_score'] < 0.3:
                risks.append("Low collaboration - few active contributors")
                risk_score += 1
        
        if 'files' in self.analysis_results:
            files = self.analysis_results['files']
            
            # High complexity commits
            if files['complexity_ratio'] > 0.2:
                risks.append("High ratio of complex commits - potential quality issues")
                risk_score += 1
        
        # Determine overall risk level
        if risk_score >= 5:
            risk_level = "high"
        elif risk_score >= 3:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            'risks': risks,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'recommendations': self.generate_risk_recommendations(risks)
        }
    
    def generate_risk_recommendations(self, risks: List[str]) -> List[str]:
        """Generate recommendations based on identified risks"""
        recommendations = []
        
        for risk in risks:
            if "velocity" in risk.lower():
                recommendations.append("Consider process improvements or additional resources")
            elif "bus factor" in risk.lower():
                recommendations.append("Encourage knowledge sharing and cross-training")
            elif "collaboration" in risk.lower():
                recommendations.append("Implement code review processes and pair programming")
            elif "complex commits" in risk.lower():
                recommendations.append("Break down large changes into smaller, focused commits")
        
        if not recommendations:
            recommendations.append("Project health appears good - maintain current practices")
        
        return recommendations
    
    def display_analysis_results(self):
        """Display analysis results in the UI"""
        # Summary tab
        summary_text = f"""Commit Pattern Analysis Results
{'='*50}

Repository Analysis Summary:
"""
        
        if 'velocity' in self.analysis_results:
            velocity = self.analysis_results['velocity']
            summary_text += f"""
Development Velocity:
• Total Commits: {velocity['total_commits']:,}
• Analysis Period: {velocity['analysis_period_days']} days
• Average Commits/Day: {velocity['avg_commits_per_day']:.2f}
• Average Lines/Day: {velocity['avg_lines_per_day']:.0f}
• Velocity Trend: {velocity['velocity_trend'].title()}
"""
        
        if 'contributors' in self.analysis_results:
            contributors = self.analysis_results['contributors']
            summary_text += f"""
Contributor Activity:
• Total Contributors: {contributors['total_contributors']}
• Active Contributors: {contributors['active_contributors']}
• Bus Factor: {contributors['bus_factor']}
• Collaboration Score: {contributors['collaboration_score']:.2f}
"""
        
        if 'risks' in self.analysis_results:
            risks = self.analysis_results['risks']
            summary_text += f"""
Risk Assessment:
• Risk Level: {risks['risk_level'].upper()}
• Risk Score: {risks['risk_score']}/10
• Issues Identified: {len(risks['risks'])}
"""
        
        self.update_results_tab("Summary", summary_text)
        
        # Details tab - Patterns and trends
        details_text = "Detailed Analysis:\n\n"
        
        if 'patterns' in self.analysis_results:
            patterns = self.analysis_results['patterns']
            details_text += f"""Commit Patterns:
• Peak Activity Hour: {patterns['peak_hour']}:00
• Peak Activity Day: {patterns['peak_day']}
• Average Message Length: {patterns['avg_message_length']:.0f} characters

Commit Types Distribution:
"""
            for commit_type, count in patterns['commit_types'].items():
                details_text += f"• {commit_type.title()}: {count} commits\n"
            
            details_text += f"""
Commit Size Distribution:
• Small commits (<50 lines): {patterns['commit_size_distribution']['small']}
• Medium commits (50-200 lines): {patterns['commit_size_distribution']['medium']}
• Large commits (>200 lines): {patterns['commit_size_distribution']['large']}
"""
        
        self.update_results_tab("Details", details_text)
        
        # Analysis tab - Risks and recommendations
        analysis_text = "Risk Analysis and Recommendations:\n\n"
        
        if 'risks' in self.analysis_results:
            risks = self.analysis_results['risks']
            
            analysis_text += f"Risk Level: {risks['risk_level'].upper()}\n\n"
            
            if risks['risks']:
                analysis_text += "Identified Risks:\n"
                for i, risk in enumerate(risks['risks'], 1):
                    analysis_text += f"{i}. {risk}\n"
                
                analysis_text += "\nRecommendations:\n"
                for i, rec in enumerate(risks['recommendations'], 1):
                    analysis_text += f"{i}. {rec}\n"
            else:
                analysis_text += "No significant risks identified. Project appears healthy."
        
        self.update_results_tab("Analysis", analysis_text)
        
        # Create visualizations
        self.create_commit_visualizations()
        
        # Save analysis results
        self.save_analysis_to_database()
    
    def create_commit_visualizations(self):
        """Create visualizations for commit analysis"""
        try:
            if 'velocity' in self.analysis_results:
                fig, axes = plt.subplots(2, 2, figsize=(12, 10))
                
                velocity = self.analysis_results['velocity']
                
                # Daily commits over time
                daily_data = velocity['daily_commits']
                if daily_data:
                    dates = sorted(daily_data.keys())
                    commits = [daily_data[date] for date in dates]
                    
                    axes[0, 0].plot(range(len(dates)), commits, 'b-', linewidth=2)
                    axes[0, 0].set_title('Daily Commit Activity')
                    axes[0, 0].set_ylabel('Commits per Day')
                    axes[0, 0].grid(True, alpha=0.3)
                
                # Commit types distribution
                if 'patterns' in self.analysis_results:
                    patterns = self.analysis_results['patterns']
                    commit_types = patterns['commit_types']
                    
                    if commit_types:
                        types = list(commit_types.keys())
                        counts = list(commit_types.values())
                        
                        axes[0, 1].pie(counts, labels=types, autopct='%1.1f%%')
                        axes[0, 1].set_title('Commit Types Distribution')
                
                # Hour distribution
                if 'patterns' in self.analysis_results:
                    hour_dist = patterns['hour_distribution']
                    if hour_dist:
                        hours = sorted(hour_dist.keys())
                        counts = [hour_dist[hour] for hour in hours]
                        
                        axes[1, 0].bar(hours, counts, alpha=0.7)
                        axes[1, 0].set_title('Commits by Hour of Day')
                        axes[1, 0].set_xlabel('Hour')
                        axes[1, 0].set_ylabel('Number of Commits')
                
                # Contributors activity
                if 'contributors' in self.analysis_results:
                    contributors = self.analysis_results['contributors']
                    top_contributors = contributors['top_contributors'][:10]
                    
                    if top_contributors:
                        names = [contrib[0][:15] for contrib in top_contributors]
                        commits = [contrib[1] for contrib in top_contributors]
                        
                        axes[1, 1].barh(range(len(names)), commits, alpha=0.7)
                        axes[1, 1].set_yticks(range(len(names)))
                        axes[1, 1].set_yticklabels(names)
                        axes[1, 1].set_title('Top Contributors')
                        axes[1, 1].set_xlabel('Number of Commits')
                
                plt.tight_layout()
                
        except Exception as e:
            print(f"Visualization error: {e}")
    
    def predict_timeline(self):
        """Predict project timeline based on historical data"""
        if not self.analysis_results or 'velocity' not in self.analysis_results:
            messagebox.showwarning("Warning", "Please run repository analysis first")
            return
        
        # Simple timeline prediction dialog
        prediction_window = tk.Toplevel(self)
        prediction_window.title("Timeline Prediction")
        prediction_window.geometry("400x300")
        prediction_window.configure(bg=self.master.cget('bg'))
        
        tk.Label(prediction_window, text="Timeline Prediction", 
                font=("Consolas", 14, "bold"), bg=self.master.cget('bg'), fg="white").pack(pady=10)
        
        # Input for remaining work
        input_frame = tk.Frame(prediction_window, bg=self.master.cget('bg'))
        input_frame.pack(fill="x", padx=20, pady=10)
        
        tk.Label(input_frame, text="Estimated remaining commits:", 
                bg=self.master.cget('bg'), fg="white").pack(anchor="w")
        
        remaining_commits_var = tk.StringVar(value="100")
        tk.Entry(input_frame, textvariable=remaining_commits_var, width=20).pack(anchor="w", pady=5)
        
        tk.Label(input_frame, text="Estimated remaining story points:", 
                bg=self.master.cget('bg'), fg="white").pack(anchor="w")
        
        remaining_points_var = tk.StringVar(value="50")
        tk.Entry(input_frame, textvariable=remaining_points_var, width=20).pack(anchor="w", pady=5)
        
        # Prediction results
        results_text = tk.Text(prediction_window, height=10, width=50, 
                              bg="#111111", fg="white", wrap="word")
        results_text.pack(fill="both", expand=True, padx=20, pady=10)
        
        def calculate_prediction():
            try:
                remaining_commits = int(remaining_commits_var.get())
                remaining_points = int(remaining_points_var.get())
                
                velocity = self.analysis_results['velocity']
                avg_commits_per_day = velocity['avg_commits_per_day']
                
                if avg_commits_per_day > 0:
                    days_needed = remaining_commits / avg_commits_per_day
                    completion_date = datetime.now() + timedelta(days=days_needed)
                    
                    # Calculate confidence based on velocity trend
                    confidence = 0.8 if velocity['velocity_trend'] == 'increasing' else 0.6
                    
                    prediction_text = f"""Timeline Prediction Results:

Remaining Work:
• Commits: {remaining_commits}
• Story Points: {remaining_points}

Current Velocity:
• Average commits/day: {avg_commits_per_day:.2f}
• Trend: {velocity['velocity_trend']}

Prediction:
• Estimated completion: {completion_date.strftime('%Y-%m-%d')}
• Days needed: {days_needed:.0f}
• Confidence level: {confidence*100:.0f}%

Risk Factors:
"""
                    
                    if 'risks' in self.analysis_results:
                        for risk in self.analysis_results['risks']['risks']:
                            prediction_text += f"• {risk}\n"
                    
                    results_text.delete(1.0, tk.END)
                    results_text.insert(1.0, prediction_text)
                else:
                    results_text.delete(1.0, tk.END)
                    results_text.insert(1.0, "Cannot predict timeline - insufficient velocity data")
                    
            except ValueError:
                messagebox.showerror("Error", "Please enter valid numbers")
        
        tk.Button(prediction_window, text="Calculate Prediction", 
                 command=calculate_prediction).pack(pady=10)
    
    def save_analysis_to_database(self):
        """Save analysis results to database"""
        try:
            analysis_id = f"commit_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            input_data = {
                'repository_path': self.repo_path_var.get(),
                'branch': self.branch_var.get(),
                'period': self.period_var.get(),
                'analysis_types': {
                    'velocity': self.analyze_velocity.get(),
                    'patterns': self.analyze_patterns.get(),
                    'contributors': self.analyze_contributors.get(),
                    'files': self.analyze_files.get()
                }
            }
            
            summary = {}
            if 'velocity' in self.analysis_results:
                summary.update(self.analysis_results['velocity'])
            if 'risks' in self.analysis_results:
                summary['risk_level'] = self.analysis_results['risks']['risk_level']
                summary['risk_score'] = self.analysis_results['risks']['risk_score']
            
            recommendations = []
            if 'risks' in self.analysis_results:
                recommendations = self.analysis_results['risks']['recommendations']
            
            self.save_analysis_result(
                analysis_id=analysis_id,
                input_data=input_data,
                results_summary=summary,
                detailed_findings=[],
                recommendations=recommendations,
                metrics=self.analysis_results
            )
            
            # Set results for export
            self.set_results_data(self.analysis_results)
            
        except Exception as e:
            print(f"Error saving analysis: {e}")
    
    def export_analysis_report(self):
        """Export comprehensive analysis report"""
        if not self.analysis_results:
            messagebox.showwarning("Warning", "No analysis results to export")
            return
        
        try:
            # Create comprehensive report
            report = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'repository': self.repo_path_var.get(),
                    'branch': self.branch_var.get(),
                    'analysis_period': self.period_var.get()
                },
                'analysis_results': self.analysis_results,
                'commits_data': self.commits_data[:100]  # Limit for export size
            }
            
            self.set_results_data(report)
            messagebox.showinfo("Export Ready", "Analysis report is ready for export. Use the export buttons below.")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to prepare export: {str(e)}")


def create_commit_pattern_analyzer(parent):
    """Factory function to create the Commit Pattern Analyzer tool"""
    return CommitPatternAnalyzer(parent)