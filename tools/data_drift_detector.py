# data_drift_detector.py - Data Drift Detection Tool for ML Models
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
from scipy import stats
import warnings
warnings.filterwarnings('ignore')

from base_tool import AdvancedToolFrame
from utils.ml_utils import ml_utils
from utils.database import db_manager

TAB_NAME = "Data Drift Detector"

class ToolFrame(AdvancedToolFrame):
    def __init__(self, master):
        tool_config = {
            'name': 'Data Drift Detector',
            'tool_id': 'data_drift_detector',
            'category': 'AI/ML Development'
        }
        super().__init__(master, tool_config)
        
        self.reference_data = None
        self.current_data = None
        self.drift_results = {}
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        self.add_label("📈 Data Drift Detector", ("Consolas", 16, "bold"))
        self.add_label("Identify when production data differs from training data")
        
        # Data loading section
        data_frame = tk.Frame(self, bg=self.master.cget('bg'))
        data_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(data_frame, text="Data Management:", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(anchor="w")
        
        data_buttons_frame = tk.Frame(data_frame, bg=self.master.cget('bg'))
        data_buttons_frame.pack(fill="x", pady=5)
        
        self.add_button_to_frame(data_buttons_frame, "Load Reference Data", self.load_reference_data)
        self.add_button_to_frame(data_buttons_frame, "Load Current Data", self.load_current_data)
        self.add_button_to_frame(data_buttons_frame, "Detect Drift", self.detect_drift)
        
        # Data info display
        self.data_info_text = tk.Text(data_frame, height=4, width=80, 
                                     bg="#111111", fg="white", wrap="word")
        self.data_info_text.pack(fill="x", pady=5)
        
        # Configuration section
        config_frame = tk.Frame(self, bg=self.master.cget('bg'))
        config_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(config_frame, text="Drift Detection Configuration:", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(anchor="w")
        
        # Significance threshold
        threshold_frame = tk.Frame(config_frame, bg=self.master.cget('bg'))
        threshold_frame.pack(fill="x", pady=2)
        
        tk.Label(threshold_frame, text="Significance Threshold:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.threshold_var = tk.StringVar(value="0.05")
        threshold_entry = tk.Entry(threshold_frame, textvariable=self.threshold_var, 
                                  width=10, bg="#111111", fg="white")
        threshold_entry.pack(side="left", padx=5)
        
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
        
        tk.Label(viz_frame, text="Drift Analysis Visualization:", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(anchor="w")
        
        # Create matplotlib figure
        self.fig = Figure(figsize=(12, 8), facecolor='#1a1a1a')
        self.canvas = FigureCanvasTk(self.fig, viz_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        
        # Initial empty plot
        self.update_visualization()
    
    def load_reference_data(self):
        """Load reference (baseline) data"""
        file_path = filedialog.askopenfilename(
            title="Select Reference Data",
            filetypes=[
                ("CSV files", "*.csv"),
                ("Excel files", "*.xlsx"),
                ("All files", "*.*")
            ]
        )
        
        if not file_path:
            return
        
        try:
            self.update_progress(20, "Loading reference data...")
            
            if file_path.endswith('.csv'):
                self.reference_data = pd.read_csv(file_path)
            elif file_path.endswith('.xlsx'):
                self.reference_data = pd.read_excel(file_path)
            else:
                messagebox.showerror("Error", "Unsupported file format")
                return
            
            # Update display
            info_text = f"Reference Data Loaded:\\n"
            info_text += f"Shape: {self.reference_data.shape}\\n"
            info_text += f"Columns: {', '.join(self.reference_data.columns[:5].tolist())}{'...' if len(self.reference_data.columns) > 5 else ''}"
            
            self.data_info_text.delete(1.0, tk.END)
            self.data_info_text.insert(1.0, info_text)
            
            self.update_progress(100, "Reference data loaded")
            messagebox.showinfo("Success", "Reference data loaded successfully!")
            
        except Exception as e:
            self.update_progress(0, "Error loading reference data")
            messagebox.showerror("Error", f"Failed to load reference data: {str(e)}")
    
    def load_current_data(self):
        """Load current (production) data"""
        file_path = filedialog.askopenfilename(
            title="Select Current Data",
            filetypes=[
                ("CSV files", "*.csv"),
                ("Excel files", "*.xlsx"),
                ("All files", "*.*")
            ]
        )
        
        if not file_path:
            return
        
        try:
            self.update_progress(20, "Loading current data...")
            
            if file_path.endswith('.csv'):
                self.current_data = pd.read_csv(file_path)
            elif file_path.endswith('.xlsx'):
                self.current_data = pd.read_excel(file_path)
            else:
                messagebox.showerror("Error", "Unsupported file format")
                return
            
            # Update display
            current_text = self.data_info_text.get(1.0, tk.END).strip()
            info_text = current_text + f"\\n\\nCurrent Data Loaded:\\n"
            info_text += f"Shape: {self.current_data.shape}\\n"
            info_text += f"Columns: {', '.join(self.current_data.columns[:5].tolist())}{'...' if len(self.current_data.columns) > 5 else ''}"
            
            self.data_info_text.delete(1.0, tk.END)
            self.data_info_text.insert(1.0, info_text)
            
            self.update_progress(100, "Current data loaded")
            messagebox.showinfo("Success", "Current data loaded successfully!")
            
        except Exception as e:
            self.update_progress(0, "Error loading current data")
            messagebox.showerror("Error", f"Failed to load current data: {str(e)}")
    
    def detect_drift(self):
        """Detect data drift between reference and current data"""
        if self.reference_data is None:
            messagebox.showwarning("Warning", "Please load reference data first")
            return
        
        if self.current_data is None:
            messagebox.showwarning("Warning", "Please load current data first")
            return
        
        try:
            self.update_progress(30, "Detecting data drift...")
            
            # Initialize results
            self.drift_results = {
                'timestamp': datetime.now().isoformat(),
                'reference_shape': self.reference_data.shape,
                'current_shape': self.current_data.shape,
                'threshold': float(self.threshold_var.get()),
                'drift_detected': False,
                'feature_drift': {},
                'summary': {}
            }
            
            # Get common columns
            common_columns = set(self.reference_data.columns) & set(self.current_data.columns)
            
            if not common_columns:
                messagebox.showerror("Error", "No common columns found between datasets")
                return
            
            # Analyze drift for each feature
            drift_count = 0
            total_features = len(common_columns)
            
            for i, column in enumerate(common_columns):
                progress = 30 + (i + 1) * (60 / total_features)
                self.update_progress(progress, f"Analyzing {column}...")
                
                drift_result = self.analyze_feature_drift(column)
                self.drift_results['feature_drift'][column] = drift_result
                
                if drift_result['drift_detected']:
                    drift_count += 1
            
            # Calculate summary statistics
            self.drift_results['summary'] = {
                'total_features': total_features,
                'features_with_drift': drift_count,
                'drift_percentage': (drift_count / total_features) * 100,
                'overall_drift_detected': drift_count > 0
            }
            
            self.drift_results['drift_detected'] = self.drift_results['summary']['overall_drift_detected']
            
            # Generate recommendations
            self.generate_drift_recommendations()
            
            # Display results
            self.display_drift_results()
            
            # Update visualization
            self.update_visualization()
            
            # Save results
            analysis_id = f"drift_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.save_analysis_result(
                analysis_id=analysis_id,
                input_data={
                    'reference_shape': self.reference_data.shape,
                    'current_shape': self.current_data.shape,
                    'threshold': float(self.threshold_var.get())
                },
                results_summary=self.drift_results['summary'],
                recommendations=self.drift_results.get('recommendations', [])
            )
            
            # Set results for export
            self.set_results_data(self.drift_results)
            
            self.update_progress(100, "Drift detection complete")
            
            # Show alert if drift detected
            if self.drift_results['drift_detected']:
                messagebox.showwarning(
                    "Data Drift Detected", 
                    f"Drift detected in {drift_count}/{total_features} features!\\n"
                    f"Check the analysis results for details."
                )
            else:
                messagebox.showinfo("No Drift Detected", "No significant data drift found.")
            
        except Exception as e:
            self.update_progress(0, "Error in drift detection")
            messagebox.showerror("Error", f"Drift detection failed: {str(e)}")
    
    def analyze_feature_drift(self, column):
        """Analyze drift for a specific feature"""
        result = {
            'column': column,
            'drift_detected': False,
            'test_type': 'unknown',
            'statistic': None,
            'p_value': None,
            'effect_size': None
        }
        
        try:
            ref_data = self.reference_data[column].dropna()
            cur_data = self.current_data[column].dropna()
            
            if len(ref_data) == 0 or len(cur_data) == 0:
                result['error'] = 'No valid data for comparison'
                return result
            
            threshold = float(self.threshold_var.get())
            
            # Determine if numerical or categorical
            if pd.api.types.is_numeric_dtype(ref_data):
                # Numerical feature - use Kolmogorov-Smirnov test
                statistic, p_value = stats.ks_2samp(ref_data, cur_data)
                result['test_type'] = 'Kolmogorov-Smirnov'
                result['statistic'] = statistic
                result['p_value'] = p_value
                result['drift_detected'] = p_value < threshold
                
                # Calculate effect size (Cohen's d for means)
                ref_mean, ref_std = ref_data.mean(), ref_data.std()
                cur_mean, cur_std = cur_data.mean(), cur_data.std()
                
                if ref_std > 0 and cur_std > 0:
                    pooled_std = np.sqrt(((len(ref_data) - 1) * ref_std**2 + (len(cur_data) - 1) * cur_std**2) / 
                                       (len(ref_data) + len(cur_data) - 2))
                    if pooled_std > 0:
                        result['effect_size'] = abs(ref_mean - cur_mean) / pooled_std
                
                # Additional statistics
                result['reference_stats'] = {
                    'mean': ref_mean,
                    'std': ref_std,
                    'min': ref_data.min(),
                    'max': ref_data.max()
                }
                result['current_stats'] = {
                    'mean': cur_mean,
                    'std': cur_std,
                    'min': cur_data.min(),
                    'max': cur_data.max()
                }
            
            else:
                # Categorical feature - use Chi-square test
                ref_counts = ref_data.value_counts()
                cur_counts = cur_data.value_counts()
                
                # Align categories
                all_categories = set(ref_counts.index) | set(cur_counts.index)
                ref_aligned = [ref_counts.get(cat, 0) for cat in all_categories]
                cur_aligned = [cur_counts.get(cat, 0) for cat in all_categories]
                
                if sum(ref_aligned) > 0 and sum(cur_aligned) > 0:
                    statistic, p_value = stats.chisquare(cur_aligned, ref_aligned)
                    result['test_type'] = 'Chi-square'
                    result['statistic'] = statistic
                    result['p_value'] = p_value
                    result['drift_detected'] = p_value < threshold
                    
                    # Calculate Cramér's V as effect size
                    n = sum(ref_aligned) + sum(cur_aligned)
                    k = len(all_categories)
                    if n > 0 and k > 1:
                        result['effect_size'] = np.sqrt(statistic / (n * (k - 1)))
                    
                    result['reference_distribution'] = dict(zip(all_categories, ref_aligned))
                    result['current_distribution'] = dict(zip(all_categories, cur_aligned))
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def generate_drift_recommendations(self):
        """Generate recommendations based on drift analysis"""
        recommendations = []
        
        try:
            summary = self.drift_results['summary']
            drift_percentage = summary['drift_percentage']
            
            if drift_percentage == 0:
                recommendations.append("No data drift detected. Continue monitoring with regular checks.")
            elif drift_percentage < 20:
                recommendations.append(f"Low drift detected ({drift_percentage:.1f}% of features). Monitor closely.")
            elif drift_percentage < 50:
                recommendations.append(f"Moderate drift detected ({drift_percentage:.1f}% of features). Consider model retraining.")
            else:
                recommendations.append(f"High drift detected ({drift_percentage:.1f}% of features). Immediate model retraining recommended.")
            
            # Feature-specific recommendations
            high_drift_features = []
            for feature, result in self.drift_results['feature_drift'].items():
                if result.get('drift_detected', False) and result.get('effect_size', 0) > 0.5:
                    high_drift_features.append(feature)
            
            if high_drift_features:
                recommendations.append(f"Features with high drift: {', '.join(high_drift_features[:5])}")
            
            # General recommendations
            recommendations.append("Implement automated drift monitoring in production.")
            recommendations.append("Set up alerts for drift detection above threshold.")
            recommendations.append("Consider adaptive models that can handle gradual drift.")
        
        except Exception as e:
            recommendations.append(f"Error generating recommendations: {str(e)}")
        
        self.drift_results['recommendations'] = recommendations
    
    def display_drift_results(self):
        """Display drift detection results"""
        try:
            # Summary tab
            summary = "Data Drift Detection Results\\n\\n"
            summary += f"Reference Data: {self.drift_results['reference_shape']}\\n"
            summary += f"Current Data: {self.drift_results['current_shape']}\\n"
            summary += f"Significance Threshold: {self.drift_results['threshold']}\\n\\n"
            
            summary_stats = self.drift_results['summary']
            summary += f"Overall Drift Detected: {'YES' if summary_stats['overall_drift_detected'] else 'NO'}\\n"
            summary += f"Features Analyzed: {summary_stats['total_features']}\\n"
            summary += f"Features with Drift: {summary_stats['features_with_drift']}\\n"
            summary += f"Drift Percentage: {summary_stats['drift_percentage']:.1f}%\\n\\n"
            
            # Top drifted features
            drifted_features = [(feature, result) for feature, result in self.drift_results['feature_drift'].items() 
                              if result.get('drift_detected', False)]
            
            if drifted_features:
                summary += "Features with Detected Drift:\\n"
                for feature, result in drifted_features[:5]:
                    p_val = result.get('p_value', 'N/A')
                    effect = result.get('effect_size', 'N/A')
                    summary += f"- {feature}: p={p_val:.4f if isinstance(p_val, float) else p_val}, effect={effect:.3f if isinstance(effect, float) else effect}\\n"
            
            # Recommendations
            if 'recommendations' in self.drift_results:
                summary += "\\nRecommendations:\\n"
                for i, rec in enumerate(self.drift_results['recommendations'][:3], 1):
                    summary += f"{i}. {rec}\\n"
            
            self.update_results_tab("Summary", summary)
            
            # Detailed results
            detailed_results = json.dumps(self.drift_results, indent=2, default=str)
            self.update_results_tab("Details", detailed_results)
            
            # Analysis tab with formatted results
            analysis_text = self.format_drift_analysis()
            self.update_results_tab("Analysis", analysis_text)
        
        except Exception as e:
            self.update_results_tab("Summary", f"Error displaying results: {str(e)}")
    
    def format_drift_analysis(self):
        """Format detailed drift analysis"""
        analysis = "DETAILED DRIFT ANALYSIS\\n\\n"
        
        try:
            for feature, result in self.drift_results['feature_drift'].items():
                analysis += f"Feature: {feature}\\n"
                analysis += f"Test: {result.get('test_type', 'Unknown')}\\n"
                analysis += f"Drift Detected: {'Yes' if result.get('drift_detected', False) else 'No'}\\n"
                
                if 'p_value' in result:
                    analysis += f"P-value: {result['p_value']:.6f}\\n"
                if 'effect_size' in result:
                    analysis += f"Effect Size: {result['effect_size']:.4f}\\n"
                
                # Add statistics for numerical features
                if 'reference_stats' in result:
                    ref_stats = result['reference_stats']
                    cur_stats = result['current_stats']
                    analysis += f"Reference Mean: {ref_stats['mean']:.4f} ± {ref_stats['std']:.4f}\\n"
                    analysis += f"Current Mean: {cur_stats['mean']:.4f} ± {cur_stats['std']:.4f}\\n"
                
                analysis += "\\n" + "-"*50 + "\\n\\n"
        
        except Exception as e:
            analysis += f"Error formatting analysis: {str(e)}\\n"
        
        return analysis
    
    def update_visualization(self):
        """Update drift visualization"""
        self.fig.clear()
        
        if not self.drift_results:
            ax = self.fig.add_subplot(111)
            ax.text(0.5, 0.5, 'No drift analysis data available\\nRun drift detection to see results', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=12, color='white')
            ax.set_facecolor('#1a1a1a')
            self.canvas.draw()
            return
        
        try:
            # Create subplots
            fig_rows = 2
            fig_cols = 2
            
            # Plot 1: Drift summary
            ax1 = self.fig.add_subplot(fig_rows, fig_cols, 1)
            self.plot_drift_summary(ax1)
            
            # Plot 2: P-value distribution
            ax2 = self.fig.add_subplot(fig_rows, fig_cols, 2)
            self.plot_pvalue_distribution(ax2)
            
            # Plot 3: Effect sizes
            ax3 = self.fig.add_subplot(fig_rows, fig_cols, 3)
            self.plot_effect_sizes(ax3)
            
            # Plot 4: Feature comparison (top drifted feature)
            ax4 = self.fig.add_subplot(fig_rows, fig_cols, 4)
            self.plot_feature_comparison(ax4)
        
        except Exception as e:
            ax = self.fig.add_subplot(111)
            ax.text(0.5, 0.5, f'Error creating visualization:\\n{str(e)}', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=10, color='white')
            ax.set_facecolor('#1a1a1a')
        
        self.fig.patch.set_facecolor('#1a1a1a')
        plt.tight_layout()
        self.canvas.draw()
    
    def plot_drift_summary(self, ax):
        """Plot drift detection summary"""
        try:
            summary = self.drift_results['summary']
            
            # Pie chart of drift vs no drift
            drift_count = summary['features_with_drift']
            no_drift_count = summary['total_features'] - drift_count
            
            sizes = [drift_count, no_drift_count]
            labels = ['Drift Detected', 'No Drift']
            colors = ['#FF6B6B', '#4ECDC4']
            
            wedges, texts, autotexts = ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%')
            ax.set_title('Drift Detection Summary', fontsize=10, color='white')
            
            # Style the text
            for text in texts:
                text.set_color('white')
            for autotext in autotexts:
                autotext.set_color('black')
            
            ax.set_facecolor('#1a1a1a')
        
        except Exception as e:
            ax.text(0.5, 0.5, f'Error: {str(e)}', ha='center', va='center', 
                   transform=ax.transAxes, color='white', fontsize=8)
            ax.set_facecolor('#1a1a1a')
    
    def plot_pvalue_distribution(self, ax):
        """Plot distribution of p-values"""
        try:
            p_values = []
            for result in self.drift_results['feature_drift'].values():
                if 'p_value' in result and result['p_value'] is not None:
                    p_values.append(result['p_value'])
            
            if p_values:
                ax.hist(p_values, bins=20, color='#4ECDC4', alpha=0.7, edgecolor='white')
                ax.axvline(self.drift_results['threshold'], color='red', linestyle='--', 
                          label=f'Threshold ({self.drift_results["threshold"]})')
                ax.set_title('P-value Distribution', fontsize=10, color='white')
                ax.set_xlabel('P-value', color='white')
                ax.set_ylabel('Frequency', color='white')
                ax.tick_params(colors='white')
                ax.legend()
            else:
                ax.text(0.5, 0.5, 'No p-values available', ha='center', va='center', 
                       transform=ax.transAxes, color='white')
            
            ax.set_facecolor('#1a1a1a')
        
        except Exception as e:
            ax.text(0.5, 0.5, f'Error: {str(e)}', ha='center', va='center', 
                   transform=ax.transAxes, color='white', fontsize=8)
            ax.set_facecolor('#1a1a1a')
    
    def plot_effect_sizes(self, ax):
        """Plot effect sizes for drifted features"""
        try:
            features = []
            effect_sizes = []
            
            for feature, result in self.drift_results['feature_drift'].items():
                if result.get('drift_detected', False) and 'effect_size' in result:
                    features.append(feature[:10] + '...' if len(feature) > 10 else feature)
                    effect_sizes.append(result['effect_size'])
            
            if features and effect_sizes:
                y_pos = np.arange(len(features))
                bars = ax.barh(y_pos, effect_sizes, color='#FF6B6B', alpha=0.7)
                
                ax.set_yticks(y_pos)
                ax.set_yticklabels(features)
                ax.set_xlabel('Effect Size', color='white')
                ax.set_title('Effect Sizes (Drifted Features)', fontsize=10, color='white')
                ax.tick_params(colors='white')
                
                # Add value labels
                for bar, size in zip(bars, effect_sizes):
                    width = bar.get_width()
                    ax.text(width + max(effect_sizes) * 0.01, bar.get_y() + bar.get_height()/2,
                           f'{size:.3f}', ha='left', va='center', color='white', fontsize=8)
            else:
                ax.text(0.5, 0.5, 'No effect size data', ha='center', va='center', 
                       transform=ax.transAxes, color='white')
            
            ax.set_facecolor('#1a1a1a')
        
        except Exception as e:
            ax.text(0.5, 0.5, f'Error: {str(e)}', ha='center', va='center', 
                   transform=ax.transAxes, color='white', fontsize=8)
            ax.set_facecolor('#1a1a1a')
    
    def plot_feature_comparison(self, ax):
        """Plot comparison for the most drifted feature"""
        try:
            # Find feature with highest effect size
            max_effect_feature = None
            max_effect_size = 0
            
            for feature, result in self.drift_results['feature_drift'].items():
                if result.get('drift_detected', False) and 'effect_size' in result:
                    if result['effect_size'] > max_effect_size:
                        max_effect_size = result['effect_size']
                        max_effect_feature = feature
            
            if max_effect_feature and 'reference_stats' in self.drift_results['feature_drift'][max_effect_feature]:
                result = self.drift_results['feature_drift'][max_effect_feature]
                ref_stats = result['reference_stats']
                cur_stats = result['current_stats']
                
                # Bar plot comparing means
                categories = ['Reference', 'Current']
                means = [ref_stats['mean'], cur_stats['mean']]
                stds = [ref_stats['std'], cur_stats['std']]
                
                bars = ax.bar(categories, means, yerr=stds, capsize=5, 
                             color=['#4ECDC4', '#FF6B6B'], alpha=0.7)
                
                ax.set_title(f'Feature Comparison: {max_effect_feature[:20]}', fontsize=10, color='white')
                ax.set_ylabel('Value', color='white')
                ax.tick_params(colors='white')
                
                # Add value labels
                for bar, mean, std in zip(bars, means, stds):
                    height = bar.get_height()
                    ax.text(bar.get_x() + bar.get_width()/2., height + std + max(means) * 0.01,
                           f'{mean:.3f}', ha='center', va='bottom', color='white', fontsize=8)
            else:
                ax.text(0.5, 0.5, 'No numerical drift data', ha='center', va='center', 
                       transform=ax.transAxes, color='white')
            
            ax.set_facecolor('#1a1a1a')
        
        except Exception as e:
            ax.text(0.5, 0.5, f'Error: {str(e)}', ha='center', va='center', 
                   transform=ax.transAxes, color='white', fontsize=8)
            ax.set_facecolor('#1a1a1a')


# Tool is loaded via ToolFrame class