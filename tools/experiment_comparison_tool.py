# experiment_comparison_tool.py - ML Experiment Comparison Tool
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import numpy as np
import json
import os
from datetime import datetime
from matplotlib.backends.backend_tkagg import FigureCanvasTk
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings('ignore')

from base_tool import AdvancedToolFrame
from utils.ml_utils import ml_utils
from utils.database import db_manager

TAB_NAME = "Experiment Comparison Tool"

class ToolFrame(AdvancedToolFrame):
    def __init__(self, master):
        tool_config = {
            'name': 'Experiment Comparison Tool',
            'tool_id': 'experiment_comparison_tool',
            'category': 'AI/ML Development'
        }
        super().__init__(master, tool_config)
        
        self.experiments = {}
        self.comparison_results = {}
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        self.add_label("🔬 Experiment Comparison Tool", ("Consolas", 16, "bold"))
        self.add_label("Systematically compare different ML experiments and results")
        
        # Experiment management section
        exp_frame = tk.Frame(self, bg=self.master.cget('bg'))
        exp_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(exp_frame, text="Experiment Management:", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(anchor="w")
        
        exp_buttons_frame = tk.Frame(exp_frame, bg=self.master.cget('bg'))
        exp_buttons_frame.pack(fill="x", pady=5)
        
        self.add_button_to_frame(exp_buttons_frame, "Load Experiment", self.load_experiment)
        self.add_button_to_frame(exp_buttons_frame, "Add Manual Entry", self.add_manual_experiment)
        self.add_button_to_frame(exp_buttons_frame, "Compare Experiments", self.compare_experiments)
        
        # Experiments list
        list_frame = tk.Frame(exp_frame, bg=self.master.cget('bg'))
        list_frame.pack(fill="x", pady=5)
        
        tk.Label(list_frame, text="Loaded Experiments:", 
                bg=self.master.cget('bg'), fg="white").pack(anchor="w")
        
        # Listbox with scrollbar
        listbox_frame = tk.Frame(list_frame, bg=self.master.cget('bg'))
        listbox_frame.pack(fill="x", pady=2)
        
        self.experiments_listbox = tk.Listbox(listbox_frame, height=6, 
                                             bg="#111111", fg="white")
        scrollbar = tk.Scrollbar(listbox_frame, orient="vertical")
        self.experiments_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.experiments_listbox.yview)
        
        self.experiments_listbox.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Comparison configuration
        config_frame = tk.Frame(self, bg=self.master.cget('bg'))
        config_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(config_frame, text="Comparison Configuration:", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(anchor="w")
        
        # Metrics to compare
        metrics_frame = tk.Frame(config_frame, bg=self.master.cget('bg'))
        metrics_frame.pack(fill="x", pady=2)
        
        tk.Label(metrics_frame, text="Metrics to Compare:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.metrics_var = tk.StringVar(value="accuracy,precision,recall,f1_score")
        metrics_entry = tk.Entry(metrics_frame, textvariable=self.metrics_var, 
                                width=50, bg="#111111", fg="white")
        metrics_entry.pack(side="left", padx=5)
        
        # Setup advanced UI components
        self.setup_advanced_ui()
        
        # Visualization area
        self.setup_visualization_area()
    
    def add_button_to_frame(self, frame, text, command):
        """Helper to add styled button to specific frame"""
        btn = tk.Button(frame, text=text, command=command, 
                       bg="#4ECDC4", fg="black", font=("Consolas", 10, "bold"),
                       relief="flat", padx=10, pady=5)
        btn.pack(side="left", padx=5)
        return btn
    
    def setup_visualization_area(self):
        """Setup matplotlib visualization area"""
        viz_frame = tk.Frame(self, bg=self.master.cget('bg'))
        viz_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        tk.Label(viz_frame, text="Experiment Comparison Visualization:", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(anchor="w")
        
        # Create matplotlib figure
        self.fig = Figure(figsize=(12, 8), facecolor='#1a1a1a')
        self.canvas = FigureCanvasTk(self.fig, viz_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        
        # Initial empty plot
        self.update_visualization()
    
    def load_experiment(self):
        """Load experiment data from file"""
        file_path = filedialog.askopenfilename(
            title="Select Experiment File",
            filetypes=[
                ("JSON files", "*.json"),
                ("CSV files", "*.csv"),
                ("All files", "*.*")
            ]
        )
        
        if not file_path:
            return
        
        try:
            self.update_progress(20, "Loading experiment...")
            
            if file_path.endswith('.json'):
                with open(file_path, 'r') as f:
                    exp_data = json.load(f)
            elif file_path.endswith('.csv'):
                # Assume CSV has experiment results
                df = pd.read_csv(file_path)
                exp_data = {
                    'name': os.path.basename(file_path).replace('.csv', ''),
                    'metrics': df.to_dict('records')[0] if len(df) > 0 else {},
                    'timestamp': datetime.now().isoformat()
                }
            else:
                messagebox.showerror("Error", "Unsupported file format")
                return
            
            # Validate experiment data
            if 'name' not in exp_data:
                exp_data['name'] = os.path.basename(file_path)
            
            if 'metrics' not in exp_data:
                exp_data['metrics'] = {}
            
            # Add to experiments
            exp_id = f"exp_{len(self.experiments) + 1}"
            self.experiments[exp_id] = exp_data
            
            # Update listbox
            self.update_experiments_list()
            
            self.update_progress(100, "Experiment loaded")
            messagebox.showinfo("Success", f"Experiment '{exp_data['name']}' loaded successfully!")
            
        except Exception as e:
            self.update_progress(0, "Error loading experiment")
            messagebox.showerror("Error", f"Failed to load experiment: {str(e)}")
    
    def add_manual_experiment(self):
        """Add experiment manually through dialog"""
        # Create dialog for manual entry
        exp_dialog = tk.Toplevel(self)
        exp_dialog.title("Add Experiment")
        exp_dialog.geometry("500x400")
        exp_dialog.configure(bg=self.master.cget('bg'))
        
        tk.Label(exp_dialog, text="Experiment Name:", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(pady=5)
        
        name_entry = tk.Entry(exp_dialog, width=40, bg="#111111", fg="white")
        name_entry.pack(pady=5)
        
        tk.Label(exp_dialog, text="Metrics (JSON format):", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(pady=5)
        
        metrics_text = tk.Text(exp_dialog, height=15, width=60, 
                              bg="#111111", fg="white", wrap="word")
        metrics_text.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Insert example
        example_metrics = '''{
    "accuracy": 0.85,
    "precision": 0.82,
    "recall": 0.88,
    "f1_score": 0.85,
    "auc_roc": 0.90,
    "training_time": 120.5,
    "model_type": "RandomForest"
}'''
        metrics_text.insert(1.0, example_metrics)
        
        def save_experiment():
            name = name_entry.get().strip()
            if not name:
                messagebox.showerror("Error", "Please enter experiment name")
                return
            
            try:
                metrics_json = metrics_text.get(1.0, tk.END).strip()
                metrics = json.loads(metrics_json)
                
                exp_data = {
                    'name': name,
                    'metrics': metrics,
                    'timestamp': datetime.now().isoformat(),
                    'source': 'manual_entry'
                }
                
                exp_id = f"exp_{len(self.experiments) + 1}"
                self.experiments[exp_id] = exp_data
                
                self.update_experiments_list()
                exp_dialog.destroy()
                messagebox.showinfo("Success", f"Experiment '{name}' added successfully!")
                
            except json.JSONDecodeError as e:
                messagebox.showerror("Error", f"Invalid JSON format: {str(e)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add experiment: {str(e)}")
        
        tk.Button(exp_dialog, text="Save Experiment", command=save_experiment,
                 bg="#4ECDC4", fg="black", font=("Consolas", 10, "bold")).pack(pady=10)
    
    def update_experiments_list(self):
        """Update the experiments listbox"""
        self.experiments_listbox.delete(0, tk.END)
        
        for exp_id, exp_data in self.experiments.items():
            name = exp_data.get('name', exp_id)
            timestamp = exp_data.get('timestamp', 'Unknown')
            metrics_count = len(exp_data.get('metrics', {}))
            
            display_text = f"{name} ({metrics_count} metrics) - {timestamp[:10]}"
            self.experiments_listbox.insert(tk.END, display_text)
    
    def compare_experiments(self):
        """Compare loaded experiments"""
        if len(self.experiments) < 2:
            messagebox.showwarning("Warning", "Please load at least 2 experiments for comparison")
            return
        
        try:
            self.update_progress(30, "Comparing experiments...")
            
            # Initialize comparison results
            self.comparison_results = {
                'timestamp': datetime.now().isoformat(),
                'experiments_compared': len(self.experiments),
                'metrics_analysis': {},
                'rankings': {},
                'summary': {}
            }
            
            # Get metrics to compare
            metrics_to_compare = [m.strip() for m in self.metrics_var.get().split(',')]
            
            # Collect all available metrics
            all_metrics = set()
            for exp_data in self.experiments.values():
                all_metrics.update(exp_data.get('metrics', {}).keys())
            
            # Filter to requested metrics that exist
            available_metrics = [m for m in metrics_to_compare if m in all_metrics]
            
            if not available_metrics:
                messagebox.showwarning("Warning", "No common metrics found for comparison")
                return
            
            self.update_progress(50, "Analyzing metrics...")
            
            # Analyze each metric
            for metric in available_metrics:
                metric_analysis = self.analyze_metric_across_experiments(metric)
                self.comparison_results['metrics_analysis'][metric] = metric_analysis
            
            # Generate rankings
            self.update_progress(70, "Generating rankings...")
            self.generate_experiment_rankings(available_metrics)
            
            # Generate summary
            self.generate_comparison_summary()
            
            # Display results
            self.display_comparison_results()
            
            # Update visualization
            self.update_visualization()
            
            # Save results
            analysis_id = f"exp_comparison_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.save_analysis_result(
                analysis_id=analysis_id,
                input_data={
                    'experiments_count': len(self.experiments),
                    'metrics_compared': available_metrics
                },
                results_summary=self.comparison_results['summary'],
                recommendations=self.comparison_results.get('recommendations', [])
            )
            
            # Set results for export
            self.set_results_data(self.comparison_results)
            
            self.update_progress(100, "Comparison complete")
            messagebox.showinfo("Success", "Experiment comparison completed!")
            
        except Exception as e:
            self.update_progress(0, "Error in comparison")
            messagebox.showerror("Error", f"Experiment comparison failed: {str(e)}")
    
    def analyze_metric_across_experiments(self, metric):
        """Analyze a specific metric across all experiments"""
        analysis = {
            'metric': metric,
            'experiment_values': {},
            'statistics': {}
        }
        
        values = []
        exp_names = []
        
        for exp_id, exp_data in self.experiments.items():
            metrics = exp_data.get('metrics', {})
            if metric in metrics:
                value = metrics[metric]
                if isinstance(value, (int, float)):
                    analysis['experiment_values'][exp_data['name']] = value
                    values.append(value)
                    exp_names.append(exp_data['name'])
        
        if values:
            analysis['statistics'] = {
                'mean': np.mean(values),
                'std': np.std(values),
                'min': np.min(values),
                'max': np.max(values),
                'range': np.max(values) - np.min(values),
                'best_experiment': exp_names[np.argmax(values)],
                'worst_experiment': exp_names[np.argmin(values)]
            }
        
        return analysis
    
    def generate_experiment_rankings(self, metrics):
        """Generate experiment rankings based on metrics"""
        rankings = {}
        
        # Calculate overall score for each experiment
        experiment_scores = {}
        
        for exp_id, exp_data in self.experiments.items():
            exp_name = exp_data['name']
            exp_metrics = exp_data.get('metrics', {})
            
            # Calculate normalized score across metrics
            scores = []
            for metric in metrics:
                if metric in exp_metrics:
                    value = exp_metrics[metric]
                    if isinstance(value, (int, float)):
                        # Normalize based on all experiments for this metric
                        all_values = []
                        for other_exp in self.experiments.values():
                            other_metrics = other_exp.get('metrics', {})
                            if metric in other_metrics and isinstance(other_metrics[metric], (int, float)):
                                all_values.append(other_metrics[metric])
                        
                        if len(all_values) > 1:
                            min_val, max_val = min(all_values), max(all_values)
                            if max_val > min_val:
                                normalized_score = (value - min_val) / (max_val - min_val)
                                scores.append(normalized_score)
            
            if scores:
                experiment_scores[exp_name] = np.mean(scores)
        
        # Sort by overall score
        sorted_experiments = sorted(experiment_scores.items(), key=lambda x: x[1], reverse=True)
        
        rankings['overall'] = {
            'ranking': [exp_name for exp_name, _ in sorted_experiments],
            'scores': dict(sorted_experiments)
        }
        
        # Individual metric rankings
        for metric in metrics:
            metric_values = {}
            for exp_id, exp_data in self.experiments.items():
                exp_name = exp_data['name']
                exp_metrics = exp_data.get('metrics', {})
                if metric in exp_metrics and isinstance(exp_metrics[metric], (int, float)):
                    metric_values[exp_name] = exp_metrics[metric]
            
            if metric_values:
                sorted_metric = sorted(metric_values.items(), key=lambda x: x[1], reverse=True)
                rankings[metric] = {
                    'ranking': [exp_name for exp_name, _ in sorted_metric],
                    'values': dict(sorted_metric)
                }
        
        self.comparison_results['rankings'] = rankings
    
    def generate_comparison_summary(self):
        """Generate comparison summary and recommendations"""
        summary = {
            'total_experiments': len(self.experiments),
            'metrics_analyzed': len(self.comparison_results['metrics_analysis']),
            'best_overall_experiment': None,
            'most_consistent_experiment': None
        }
        
        recommendations = []
        
        try:
            # Best overall experiment
            if 'overall' in self.comparison_results['rankings']:
                overall_ranking = self.comparison_results['rankings']['overall']['ranking']
                if overall_ranking:
                    summary['best_overall_experiment'] = overall_ranking[0]
                    recommendations.append(f"Best overall performer: {overall_ranking[0]}")
            
            # Analyze consistency across metrics
            consistency_scores = {}
            for exp_id, exp_data in self.experiments.items():
                exp_name = exp_data['name']
                ranks = []
                
                for metric, ranking_data in self.comparison_results['rankings'].items():
                    if metric != 'overall' and exp_name in ranking_data['ranking']:
                        rank = ranking_data['ranking'].index(exp_name) + 1
                        ranks.append(rank)
                
                if ranks:
                    consistency_scores[exp_name] = np.std(ranks)  # Lower std = more consistent
            
            if consistency_scores:
                most_consistent = min(consistency_scores, key=consistency_scores.get)
                summary['most_consistent_experiment'] = most_consistent
                recommendations.append(f"Most consistent across metrics: {most_consistent}")
            
            # Metric-specific insights
            for metric, analysis in self.comparison_results['metrics_analysis'].items():
                stats = analysis.get('statistics', {})
                if stats:
                    range_val = stats.get('range', 0)
                    mean_val = stats.get('mean', 0)
                    
                    if mean_val > 0 and range_val / mean_val > 0.2:  # High variability
                        recommendations.append(f"High variability in {metric} across experiments")
            
            # General recommendations
            if len(self.experiments) > 3:
                recommendations.append("Consider ensemble methods combining top performers")
            
            recommendations.append("Validate results with cross-validation or holdout sets")
            recommendations.append("Consider statistical significance testing for metric differences")
        
        except Exception as e:
            recommendations.append(f"Error generating insights: {str(e)}")
        
        summary['recommendations'] = recommendations
        self.comparison_results['summary'] = summary
        self.comparison_results['recommendations'] = recommendations
    
    def display_comparison_results(self):
        """Display experiment comparison results"""
        try:
            # Summary tab
            summary = "Experiment Comparison Results\\n\\n"
            summary_data = self.comparison_results['summary']
            
            summary += f"Experiments Compared: {summary_data['total_experiments']}\\n"
            summary += f"Metrics Analyzed: {summary_data['metrics_analyzed']}\\n\\n"
            
            if summary_data.get('best_overall_experiment'):
                summary += f"Best Overall: {summary_data['best_overall_experiment']}\\n"
            
            if summary_data.get('most_consistent_experiment'):
                summary += f"Most Consistent: {summary_data['most_consistent_experiment']}\\n\\n"
            
            # Top 3 experiments
            if 'overall' in self.comparison_results['rankings']:
                ranking = self.comparison_results['rankings']['overall']['ranking']
                scores = self.comparison_results['rankings']['overall']['scores']
                
                summary += "Top 3 Experiments:\\n"
                for i, exp_name in enumerate(ranking[:3], 1):
                    score = scores.get(exp_name, 0)
                    summary += f"{i}. {exp_name}: {score:.4f}\\n"
            
            # Recommendations
            if 'recommendations' in self.comparison_results:
                summary += "\\nRecommendations:\\n"
                for i, rec in enumerate(self.comparison_results['recommendations'][:3], 1):
                    summary += f"{i}. {rec}\\n"
            
            self.update_results_tab("Summary", summary)
            
            # Detailed results
            detailed_results = json.dumps(self.comparison_results, indent=2, default=str)
            self.update_results_tab("Details", detailed_results)
            
            # Analysis tab
            analysis_text = self.format_comparison_analysis()
            self.update_results_tab("Analysis", analysis_text)
        
        except Exception as e:
            self.update_results_tab("Summary", f"Error displaying results: {str(e)}")
    
    def format_comparison_analysis(self):
        """Format detailed comparison analysis"""
        analysis = "DETAILED EXPERIMENT COMPARISON\\n\\n"
        
        try:
            # Metric-by-metric analysis
            analysis += "=== METRIC ANALYSIS ===\\n\\n"
            
            for metric, metric_data in self.comparison_results['metrics_analysis'].items():
                analysis += f"Metric: {metric}\\n"
                
                stats = metric_data.get('statistics', {})
                if stats:
                    analysis += f"  Mean: {stats['mean']:.4f}\\n"
                    analysis += f"  Std Dev: {stats['std']:.4f}\\n"
                    analysis += f"  Range: {stats['min']:.4f} - {stats['max']:.4f}\\n"
                    analysis += f"  Best: {stats['best_experiment']} ({stats['max']:.4f})\\n"
                    analysis += f"  Worst: {stats['worst_experiment']} ({stats['min']:.4f})\\n"
                
                # Experiment values
                exp_values = metric_data.get('experiment_values', {})
                if exp_values:
                    analysis += "  Values by Experiment:\\n"
                    sorted_values = sorted(exp_values.items(), key=lambda x: x[1], reverse=True)
                    for exp_name, value in sorted_values:
                        analysis += f"    {exp_name}: {value:.4f}\\n"
                
                analysis += "\\n"
            
            # Rankings analysis
            analysis += "=== RANKINGS ===\\n\\n"
            
            for metric, ranking_data in self.comparison_results['rankings'].items():
                analysis += f"{metric.title()} Ranking:\\n"
                ranking = ranking_data['ranking']
                
                for i, exp_name in enumerate(ranking, 1):
                    analysis += f"  {i}. {exp_name}\\n"
                
                analysis += "\\n"
        
        except Exception as e:
            analysis += f"Error formatting analysis: {str(e)}\\n"
        
        return analysis
    
    def update_visualization(self):
        """Update experiment comparison visualization"""
        self.fig.clear()
        
        if not self.comparison_results:
            ax = self.fig.add_subplot(111)
            ax.text(0.5, 0.5, 'No comparison results available\\nLoad experiments and run comparison', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=12, color='white')
            ax.set_facecolor('#1a1a1a')
            self.canvas.draw()
            return
        
        try:
            # Create subplots
            fig_rows = 2
            fig_cols = 2
            
            # Plot 1: Overall ranking
            ax1 = self.fig.add_subplot(fig_rows, fig_cols, 1)
            self.plot_overall_ranking(ax1)
            
            # Plot 2: Metric comparison
            ax2 = self.fig.add_subplot(fig_rows, fig_cols, 2)
            self.plot_metric_comparison(ax2)
            
            # Plot 3: Experiment scores
            ax3 = self.fig.add_subplot(fig_rows, fig_cols, 3)
            self.plot_experiment_scores(ax3)
            
            # Plot 4: Metric distribution
            ax4 = self.fig.add_subplot(fig_rows, fig_cols, 4)
            self.plot_metric_distribution(ax4)
        
        except Exception as e:
            ax = self.fig.add_subplot(111)
            ax.text(0.5, 0.5, f'Error creating visualization:\\n{str(e)}', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=10, color='white')
            ax.set_facecolor('#1a1a1a')
        
        self.fig.patch.set_facecolor('#1a1a1a')
        plt.tight_layout()
        self.canvas.draw()
    
    def plot_overall_ranking(self, ax):
        """Plot overall experiment ranking"""
        try:
            if 'overall' not in self.comparison_results['rankings']:
                ax.text(0.5, 0.5, 'No ranking data', ha='center', va='center', 
                       transform=ax.transAxes, color='white')
                ax.set_facecolor('#1a1a1a')
                return
            
            ranking_data = self.comparison_results['rankings']['overall']
            experiments = ranking_data['ranking'][:5]  # Top 5
            scores = [ranking_data['scores'][exp] for exp in experiments]
            
            # Truncate long names
            display_names = [exp[:15] + '...' if len(exp) > 15 else exp for exp in experiments]
            
            bars = ax.bar(display_names, scores, color='#4ECDC4', alpha=0.7)
            ax.set_title('Overall Experiment Ranking', fontsize=10, color='white')
            ax.set_ylabel('Normalized Score', color='white')
            ax.tick_params(colors='white')
            
            # Rotate x-axis labels
            plt.setp(ax.get_xticklabels(), rotation=45, ha='right')
            
            # Add value labels
            for bar, score in zip(bars, scores):
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height + max(scores) * 0.01,
                       f'{score:.3f}', ha='center', va='bottom', color='white', fontsize=8)
            
            ax.set_facecolor('#1a1a1a')
        
        except Exception as e:
            ax.text(0.5, 0.5, f'Error: {str(e)}', ha='center', va='center', 
                   transform=ax.transAxes, color='white', fontsize=8)
            ax.set_facecolor('#1a1a1a')
    
    def plot_metric_comparison(self, ax):
        """Plot side-by-side metric comparison"""
        try:
            metrics_analysis = self.comparison_results['metrics_analysis']
            
            if not metrics_analysis:
                ax.text(0.5, 0.5, 'No metrics data', ha='center', va='center', 
                       transform=ax.transAxes, color='white')
                ax.set_facecolor('#1a1a1a')
                return
            
            # Get first metric for detailed comparison
            first_metric = list(metrics_analysis.keys())[0]
            metric_data = metrics_analysis[first_metric]
            
            exp_values = metric_data.get('experiment_values', {})
            if exp_values:
                experiments = list(exp_values.keys())
                values = list(exp_values.values())
                
                # Truncate long names
                display_names = [exp[:10] + '...' if len(exp) > 10 else exp for exp in experiments]
                
                bars = ax.bar(display_names, values, color='#FF6B6B', alpha=0.7)
                ax.set_title(f'{first_metric.title()} Comparison', fontsize=10, color='white')
                ax.set_ylabel(first_metric.title(), color='white')
                ax.tick_params(colors='white')
                
                # Rotate x-axis labels
                plt.setp(ax.get_xticklabels(), rotation=45, ha='right')
                
                # Add value labels
                for bar, value in zip(bars, values):
                    height = bar.get_height()
                    ax.text(bar.get_x() + bar.get_width()/2., height + max(values) * 0.01,
                           f'{value:.3f}', ha='center', va='bottom', color='white', fontsize=8)
            else:
                ax.text(0.5, 0.5, 'No experiment values', ha='center', va='center', 
                       transform=ax.transAxes, color='white')
            
            ax.set_facecolor('#1a1a1a')
        
        except Exception as e:
            ax.text(0.5, 0.5, f'Error: {str(e)}', ha='center', va='center', 
                   transform=ax.transAxes, color='white', fontsize=8)
            ax.set_facecolor('#1a1a1a')
    
    def plot_experiment_scores(self, ax):
        """Plot experiment scores radar/spider chart (simplified as bar chart)"""
        try:
            if 'overall' not in self.comparison_results['rankings']:
                ax.text(0.5, 0.5, 'No scores data', ha='center', va='center', 
                       transform=ax.transAxes, color='white')
                ax.set_facecolor('#1a1a1a')
                return
            
            scores_data = self.comparison_results['rankings']['overall']['scores']
            
            experiments = list(scores_data.keys())
            scores = list(scores_data.values())
            
            # Horizontal bar chart
            y_pos = np.arange(len(experiments))
            bars = ax.barh(y_pos, scores, color='#4ECDC4', alpha=0.7)
            
            ax.set_yticks(y_pos)
            ax.set_yticklabels([exp[:15] + '...' if len(exp) > 15 else exp for exp in experiments])
            ax.set_xlabel('Overall Score', color='white')
            ax.set_title('Experiment Scores', fontsize=10, color='white')
            ax.tick_params(colors='white')
            
            # Add value labels
            for bar, score in zip(bars, scores):
                width = bar.get_width()
                ax.text(width + max(scores) * 0.01, bar.get_y() + bar.get_height()/2,
                       f'{score:.3f}', ha='left', va='center', color='white', fontsize=8)
            
            ax.set_facecolor('#1a1a1a')
        
        except Exception as e:
            ax.text(0.5, 0.5, f'Error: {str(e)}', ha='center', va='center', 
                   transform=ax.transAxes, color='white', fontsize=8)
            ax.set_facecolor('#1a1a1a')
    
    def plot_metric_distribution(self, ax):
        """Plot distribution of metric values"""
        try:
            metrics_analysis = self.comparison_results['metrics_analysis']
            
            if not metrics_analysis:
                ax.text(0.5, 0.5, 'No metrics data', ha='center', va='center', 
                       transform=ax.transAxes, color='white')
                ax.set_facecolor('#1a1a1a')
                return
            
            # Collect all metric values
            all_values = []
            for metric_data in metrics_analysis.values():
                exp_values = metric_data.get('experiment_values', {})
                all_values.extend(exp_values.values())
            
            if all_values:
                ax.hist(all_values, bins=10, color='#4ECDC4', alpha=0.7, edgecolor='white')
                ax.set_title('Metric Values Distribution', fontsize=10, color='white')
                ax.set_xlabel('Metric Value', color='white')
                ax.set_ylabel('Frequency', color='white')
                ax.tick_params(colors='white')
            else:
                ax.text(0.5, 0.5, 'No metric values', ha='center', va='center', 
                       transform=ax.transAxes, color='white')
            
            ax.set_facecolor('#1a1a1a')
        
        except Exception as e:
            ax.text(0.5, 0.5, f'Error: {str(e)}', ha='center', va='center', 
                   transform=ax.transAxes, color='white', fontsize=8)
            ax.set_facecolor('#1a1a1a')


# Tool is loaded via ToolFrame class