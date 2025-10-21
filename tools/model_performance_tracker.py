# model_performance_tracker.py - AI/ML Model Performance Tracking Tool
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import numpy as np
import json
import pickle
import os
from datetime import datetime, timedelta
import threading
from matplotlib.backends.backend_tkagg import FigureCanvasTk
from matplotlib.figure import Figure
import matplotlib.pyplot as plt

from base_tool import AdvancedToolFrame
from utils.ml_utils import ml_utils
from utils.database import db_manager

TAB_NAME = "Model Performance Tracker"

class ToolFrame(AdvancedToolFrame):
    def __init__(self, master):
        tool_config = {
            'name': 'Model Performance Tracker',
            'tool_id': 'model_performance_tracker',
            'category': 'AI/ML Development'
        }
        super().__init__(master, tool_config)
        
        self.current_model = None
        self.baseline_metrics = None
        self.metrics_history = []
        self.monitoring_active = False
        
        self.setup_ui()
        self.load_saved_data()
    
    def setup_ui(self):
        """Setup the user interface"""
        self.add_label("🤖 Model Performance Tracker", ("Consolas", 16, "bold"))
        self.add_label("Monitor ML model metrics and detect performance degradation")
        
        # Model loading section
        model_frame = tk.Frame(self, bg=self.master.cget('bg'))
        model_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(model_frame, text="Model Management:", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(anchor="w")
        
        model_buttons_frame = tk.Frame(model_frame, bg=self.master.cget('bg'))
        model_buttons_frame.pack(fill="x", pady=5)
        
        self.add_button_to_frame(model_buttons_frame, "Load Model", self.load_model)
        self.add_button_to_frame(model_buttons_frame, "Load Test Data", self.load_test_data)
        self.add_button_to_frame(model_buttons_frame, "Set Baseline", self.set_baseline_metrics)
        
        # Model info display
        self.model_info_text = tk.Text(model_frame, height=3, width=80, 
                                      bg="#111111", fg="white", wrap="word")
        self.model_info_text.pack(fill="x", pady=5)
        
        # Monitoring controls
        monitor_frame = tk.Frame(self, bg=self.master.cget('bg'))
        monitor_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(monitor_frame, text="Performance Monitoring:", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(anchor="w")
        
        monitor_buttons_frame = tk.Frame(monitor_frame, bg=self.master.cget('bg'))
        monitor_buttons_frame.pack(fill="x", pady=5)
        
        self.add_button_to_frame(monitor_buttons_frame, "Run Performance Check", self.run_performance_check)
        self.add_button_to_frame(monitor_buttons_frame, "Detect Model Drift", self.detect_model_drift)
        self.add_button_to_frame(monitor_buttons_frame, "View History", self.view_metrics_history)
        
        # Drift threshold setting
        threshold_frame = tk.Frame(monitor_frame, bg=self.master.cget('bg'))
        threshold_frame.pack(fill="x", pady=2)
        
        tk.Label(threshold_frame, text="Drift Threshold (%):", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.drift_threshold_var = tk.StringVar(value="5.0")
        threshold_entry = tk.Entry(threshold_frame, textvariable=self.drift_threshold_var, 
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
        
        tk.Label(viz_frame, text="Performance Visualization:", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(anchor="w")
        
        # Create matplotlib figure
        self.fig = Figure(figsize=(12, 8), facecolor='#1a1a1a')
        self.canvas = FigureCanvasTk(self.fig, viz_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        
        # Initial empty plot
        self.update_visualization()
    
    def load_model(self):
        """Load a trained model"""
        file_path = filedialog.askopenfilename(
            title="Select Model File",
            filetypes=[
                ("Pickle files", "*.pkl"),
                ("Joblib files", "*.joblib"),
                ("All files", "*.*")
            ]
        )
        
        if not file_path:
            return
        
        try:
            self.update_progress(10, "Loading model...")
            
            # Load model based on file extension
            if file_path.endswith('.pkl'):
                with open(file_path, 'rb') as f:
                    self.current_model = pickle.load(f)
            elif file_path.endswith('.joblib'):
                import joblib
                self.current_model = joblib.load(file_path)
            else:
                messagebox.showerror("Error", "Unsupported model file format")
                return
            
            # Detect framework and get model info
            framework = ml_utils.detect_model_framework(self.current_model)
            
            model_info = f"Model loaded successfully!\\n"
            model_info += f"Framework: {framework}\\n"
            model_info += f"Model type: {type(self.current_model).__name__}\\n"
            model_info += f"File: {os.path.basename(file_path)}"
            
            self.model_info_text.delete(1.0, tk.END)
            self.model_info_text.insert(1.0, model_info)
            
            self.update_progress(100, "Model loaded")
            messagebox.showinfo("Success", "Model loaded successfully!")
            
        except Exception as e:
            self.update_progress(0, "Error loading model")
            messagebox.showerror("Error", f"Failed to load model: {str(e)}")
    
    def load_test_data(self):
        """Load test data for performance evaluation"""
        file_path = filedialog.askopenfilename(
            title="Select Test Data",
            filetypes=[
                ("CSV files", "*.csv"),
                ("Excel files", "*.xlsx"),
                ("Pickle files", "*.pkl"),
                ("All files", "*.*")
            ]
        )
        
        if not file_path:
            return
        
        try:
            self.update_progress(20, "Loading test data...")
            
            # Load data based on file extension
            if file_path.endswith('.csv'):
                self.test_data = pd.read_csv(file_path)
            elif file_path.endswith('.xlsx'):
                self.test_data = pd.read_excel(file_path)
            elif file_path.endswith('.pkl'):
                with open(file_path, 'rb') as f:
                    self.test_data = pickle.load(f)
            else:
                messagebox.showerror("Error", "Unsupported data file format")
                return
            
            # Validate data
            if not isinstance(self.test_data, (pd.DataFrame, dict, tuple)):
                messagebox.showerror("Error", "Test data must be a DataFrame, dict, or tuple")
                return
            
            data_info = f"Test data loaded: {len(self.test_data)} samples"
            if isinstance(self.test_data, pd.DataFrame):
                data_info += f", {len(self.test_data.columns)} features"
            
            # Update model info display
            current_text = self.model_info_text.get(1.0, tk.END).strip()
            if current_text:
                current_text += "\\n" + data_info
            else:
                current_text = data_info
            
            self.model_info_text.delete(1.0, tk.END)
            self.model_info_text.insert(1.0, current_text)
            
            self.update_progress(100, "Test data loaded")
            messagebox.showinfo("Success", "Test data loaded successfully!")
            
        except Exception as e:
            self.update_progress(0, "Error loading data")
            messagebox.showerror("Error", f"Failed to load test data: {str(e)}")
    
    def set_baseline_metrics(self):
        """Set baseline metrics for drift detection"""
        if not self.current_model:
            messagebox.showwarning("Warning", "Please load a model first")
            return
        
        if not hasattr(self, 'test_data'):
            messagebox.showwarning("Warning", "Please load test data first")
            return
        
        try:
            self.update_progress(30, "Calculating baseline metrics...")
            
            # Extract features and labels from test data
            X_test, y_test = self.extract_features_labels(self.test_data)
            
            # Make predictions
            y_pred = self.current_model.predict(X_test)
            
            # Get prediction probabilities if available
            y_prob = None
            if hasattr(self.current_model, 'predict_proba'):
                try:
                    y_prob = self.current_model.predict_proba(X_test)
                    if y_prob.shape[1] == 2:  # Binary classification
                        y_prob = y_prob[:, 1]
                except:
                    pass
            
            # Calculate metrics based on problem type
            if self.is_classification_problem(y_test):
                self.baseline_metrics = ml_utils.calculate_classification_metrics(y_test, y_pred, y_prob)
            else:
                self.baseline_metrics = ml_utils.calculate_regression_metrics(y_test, y_pred)
            
            # Add timestamp and model info
            self.baseline_metrics['timestamp'] = datetime.now().isoformat()
            self.baseline_metrics['model_type'] = type(self.current_model).__name__
            self.baseline_metrics['framework'] = ml_utils.detect_model_framework(self.current_model)
            
            # Save baseline metrics
            self.save_baseline_metrics()
            
            # Display baseline metrics in results tab
            baseline_summary = self.format_metrics_summary(self.baseline_metrics)
            self.update_results_tab("Summary", f"Baseline Metrics Set\\n\\n{baseline_summary}")
            
            self.update_progress(100, "Baseline metrics set")
            messagebox.showinfo("Success", "Baseline metrics calculated and saved!")
            
        except Exception as e:
            self.update_progress(0, "Error setting baseline")
            messagebox.showerror("Error", f"Failed to set baseline metrics: {str(e)}")
    
    def run_performance_check(self):
        """Run current performance check"""
        if not self.current_model:
            messagebox.showwarning("Warning", "Please load a model first")
            return
        
        if not hasattr(self, 'test_data'):
            messagebox.showwarning("Warning", "Please load test data first")
            return
        
        try:
            self.update_progress(40, "Running performance check...")
            
            # Extract features and labels
            X_test, y_test = self.extract_features_labels(self.test_data)
            
            # Make predictions
            y_pred = self.current_model.predict(X_test)
            
            # Get prediction probabilities if available
            y_prob = None
            if hasattr(self.current_model, 'predict_proba'):
                try:
                    y_prob = self.current_model.predict_proba(X_test)
                    if y_prob.shape[1] == 2:
                        y_prob = y_prob[:, 1]
                except:
                    pass
            
            # Calculate current metrics
            if self.is_classification_problem(y_test):
                current_metrics = ml_utils.calculate_classification_metrics(y_test, y_pred, y_prob)
            else:
                current_metrics = ml_utils.calculate_regression_metrics(y_test, y_pred)
            
            # Add metadata
            current_metrics['timestamp'] = datetime.now().isoformat()
            current_metrics['model_type'] = type(self.current_model).__name__
            
            # Add to history
            self.metrics_history.append({
                'timestamp': current_metrics['timestamp'],
                'metrics': current_metrics
            })
            
            # Save to database
            analysis_id = f"perf_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.save_analysis_result(
                analysis_id=analysis_id,
                input_data={'test_samples': len(y_test)},
                results_summary=current_metrics,
                metrics=current_metrics
            )
            
            # Display results
            metrics_summary = self.format_metrics_summary(current_metrics)
            self.update_results_tab("Summary", f"Current Performance Check\\n\\n{metrics_summary}")
            
            # Show detailed metrics
            detailed_info = json.dumps(current_metrics, indent=2)
            self.update_results_tab("Details", detailed_info)
            
            # Update visualization
            self.update_visualization()
            
            # Set results data for export
            self.set_results_data(current_metrics)
            
            self.update_progress(100, "Performance check complete")
            messagebox.showinfo("Success", "Performance check completed!")
            
        except Exception as e:
            self.update_progress(0, "Error in performance check")
            messagebox.showerror("Error", f"Performance check failed: {str(e)}")
    
    def detect_model_drift(self):
        """Detect model performance drift"""
        if not self.baseline_metrics:
            messagebox.showwarning("Warning", "Please set baseline metrics first")
            return
        
        if not self.metrics_history:
            messagebox.showwarning("Warning", "No performance history available. Run a performance check first.")
            return
        
        try:
            self.update_progress(50, "Detecting model drift...")
            
            # Get latest metrics
            latest_metrics = self.metrics_history[-1]['metrics']
            
            # Get drift threshold
            threshold = float(self.drift_threshold_var.get()) / 100.0
            
            # Detect drift
            drift_analysis = ml_utils.detect_model_drift(
                self.baseline_metrics, latest_metrics, threshold
            )
            
            # Format drift report
            drift_report = self.format_drift_report(drift_analysis)
            
            # Display results
            self.update_results_tab("Summary", f"Model Drift Analysis\\n\\n{drift_report}")
            
            # Show detailed drift analysis
            detailed_drift = json.dumps(drift_analysis, indent=2)
            self.update_results_tab("Analysis", detailed_drift)
            
            # Save drift analysis
            analysis_id = f"drift_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.save_analysis_result(
                analysis_id=analysis_id,
                input_data={'threshold': threshold, 'baseline_timestamp': self.baseline_metrics.get('timestamp')},
                results_summary=drift_analysis,
                recommendations=drift_analysis.get('recommendations', [])
            )
            
            # Set results for export
            self.set_results_data(drift_analysis)
            
            # Show alert if drift detected
            if drift_analysis.get('drift_detected', False):
                severity = drift_analysis.get('severity', 'unknown')
                messagebox.showwarning(
                    "Model Drift Detected", 
                    f"Model drift detected with {severity} severity!\\n"
                    f"Check the analysis results for details and recommendations."
                )
            
            self.update_progress(100, "Drift analysis complete")
            
        except Exception as e:
            self.update_progress(0, "Error in drift detection")
            messagebox.showerror("Error", f"Drift detection failed: {str(e)}")
    
    def view_metrics_history(self):
        """View metrics history and trends"""
        if not self.metrics_history:
            messagebox.showinfo("Info", "No metrics history available")
            return
        
        try:
            # Format history for display
            history_text = "Performance History:\\n\\n"
            
            for i, entry in enumerate(self.metrics_history[-10:]):  # Last 10 entries
                timestamp = entry['timestamp']
                metrics = entry['metrics']
                
                history_text += f"Entry {i+1} - {timestamp}\\n"
                history_text += self.format_metrics_summary(metrics)
                history_text += "\\n" + "-"*50 + "\\n\\n"
            
            self.update_results_tab("Details", history_text)
            
            # Update visualization with trends
            self.update_visualization()
            
            messagebox.showinfo("Success", "Metrics history displayed")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to display history: {str(e)}")
    
    def extract_features_labels(self, data):
        """Extract features and labels from test data"""
        if isinstance(data, pd.DataFrame):
            # Assume last column is target
            X = data.iloc[:, :-1].values
            y = data.iloc[:, -1].values
        elif isinstance(data, tuple) and len(data) == 2:
            X, y = data
        elif isinstance(data, dict) and 'X' in data and 'y' in data:
            X, y = data['X'], data['y']
        else:
            raise ValueError("Unsupported data format. Expected DataFrame, tuple (X, y), or dict with 'X' and 'y' keys")
        
        return np.array(X), np.array(y)
    
    def is_classification_problem(self, y):
        """Determine if this is a classification or regression problem"""
        # Check if target values are discrete/categorical
        unique_values = len(np.unique(y))
        total_values = len(y)
        
        # If unique values are less than 20% of total or less than 10, likely classification
        if unique_values < min(10, total_values * 0.2):
            return True
        
        # Check if values are integers
        if np.all(y == y.astype(int)):
            return True
        
        return False
    
    def format_metrics_summary(self, metrics):
        """Format metrics for display"""
        summary = ""
        
        # Classification metrics
        if 'accuracy' in metrics:
            summary += f"Accuracy: {metrics['accuracy']:.4f}\\n"
        if 'precision' in metrics:
            summary += f"Precision: {metrics['precision']:.4f}\\n"
        if 'recall' in metrics:
            summary += f"Recall: {metrics['recall']:.4f}\\n"
        if 'f1_score' in metrics:
            summary += f"F1 Score: {metrics['f1_score']:.4f}\\n"
        if 'auc_roc' in metrics and metrics['auc_roc'] is not None:
            summary += f"AUC-ROC: {metrics['auc_roc']:.4f}\\n"
        
        # Regression metrics
        if 'mse' in metrics:
            summary += f"MSE: {metrics['mse']:.4f}\\n"
        if 'rmse' in metrics:
            summary += f"RMSE: {metrics['rmse']:.4f}\\n"
        if 'mae' in metrics:
            summary += f"MAE: {metrics['mae']:.4f}\\n"
        if 'r2_score' in metrics:
            summary += f"R² Score: {metrics['r2_score']:.4f}\\n"
        
        return summary
    
    def format_drift_report(self, drift_analysis):
        """Format drift analysis report"""
        report = f"Drift Detected: {'Yes' if drift_analysis.get('drift_detected', False) else 'No'}\\n"
        report += f"Severity: {drift_analysis.get('severity', 'none').title()}\\n\\n"
        
        if 'drift_metrics' in drift_analysis:
            report += "Metric Drift Analysis:\\n"
            for metric, data in drift_analysis['drift_metrics'].items():
                report += f"\\n{metric.title()}:\\n"
                report += f"  Baseline: {data['baseline']:.4f}\\n"
                report += f"  Current: {data['current']:.4f}\\n"
                report += f"  Drift: {data['drift_percentage']:.2f}%\\n"
                report += f"  Drift Detected: {'Yes' if data['drift_detected'] else 'No'}\\n"
        
        if 'recommendations' in drift_analysis and drift_analysis['recommendations']:
            report += "\\nRecommendations:\\n"
            for i, rec in enumerate(drift_analysis['recommendations'], 1):
                report += f"{i}. {rec}\\n"
        
        return report
    
    def update_visualization(self):
        """Update performance visualization"""
        self.fig.clear()
        
        if not self.metrics_history:
            ax = self.fig.add_subplot(111)
            ax.text(0.5, 0.5, 'No performance data available\\nRun a performance check to see trends', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=12, color='white')
            ax.set_facecolor('#1a1a1a')
            self.canvas.draw()
            return
        
        try:
            # Create subplots for different metrics
            if len(self.metrics_history) > 1:
                # Multiple metrics over time
                fig_metrics = ['accuracy', 'f1_score', 'r2_score', 'rmse']
                available_metrics = []
                
                # Check which metrics are available
                for metric in fig_metrics:
                    if any(metric in entry['metrics'] for entry in self.metrics_history):
                        available_metrics.append(metric)
                
                if available_metrics:
                    n_plots = min(len(available_metrics), 4)
                    
                    for i, metric in enumerate(available_metrics[:n_plots]):
                        ax = self.fig.add_subplot(2, 2, i+1)
                        
                        # Extract data for this metric
                        timestamps = []
                        values = []
                        
                        for entry in self.metrics_history:
                            if metric in entry['metrics']:
                                timestamps.append(pd.to_datetime(entry['timestamp']))
                                values.append(entry['metrics'][metric])
                        
                        if timestamps and values:
                            ax.plot(timestamps, values, marker='o', linewidth=2, markersize=6, color='#4ECDC4')
                            ax.set_title(f'{metric.title()} Over Time', fontsize=10, color='white')
                            ax.set_ylabel(metric.title(), color='white')
                            ax.tick_params(colors='white')
                            ax.grid(True, alpha=0.3)
                            
                            # Add baseline line if available
                            if self.baseline_metrics and metric in self.baseline_metrics:
                                baseline_val = self.baseline_metrics[metric]
                                ax.axhline(y=baseline_val, color='red', linestyle='--', alpha=0.7, label='Baseline')
                                ax.legend()
                        
                        ax.set_facecolor('#1a1a1a')
                
            else:
                # Single performance check - show current metrics
                ax = self.fig.add_subplot(111)
                current_metrics = self.metrics_history[-1]['metrics']
                
                # Create bar chart of current metrics
                metrics_to_show = []
                values_to_show = []
                
                for metric in ['accuracy', 'precision', 'recall', 'f1_score', 'r2_score']:
                    if metric in current_metrics and current_metrics[metric] is not None:
                        metrics_to_show.append(metric.title())
                        values_to_show.append(current_metrics[metric])
                
                if metrics_to_show:
                    bars = ax.bar(metrics_to_show, values_to_show, color='#4ECDC4', alpha=0.7)
                    ax.set_title('Current Model Performance', fontsize=12, color='white')
                    ax.set_ylabel('Score', color='white')
                    ax.tick_params(colors='white')
                    
                    # Add value labels on bars
                    for bar, value in zip(bars, values_to_show):
                        height = bar.get_height()
                        ax.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                               f'{value:.3f}', ha='center', va='bottom', color='white')
                
                ax.set_facecolor('#1a1a1a')
        
        except Exception as e:
            ax = self.fig.add_subplot(111)
            ax.text(0.5, 0.5, f'Error creating visualization:\\n{str(e)}', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=10, color='white')
            ax.set_facecolor('#1a1a1a')
        
        self.fig.patch.set_facecolor('#1a1a1a')
        plt.tight_layout()
        self.canvas.draw()
    
    def save_baseline_metrics(self):
        """Save baseline metrics to database"""
        try:
            db_manager.save_user_preference(
                category='model_performance_tracker',
                preference_key='baseline_metrics',
                preference_value=self.baseline_metrics
            )
        except Exception as e:
            print(f"Error saving baseline metrics: {e}")
    
    def load_saved_data(self):
        """Load saved baseline metrics and history"""
        try:
            # Load baseline metrics
            saved_baseline = db_manager.get_user_preference(
                category='model_performance_tracker',
                preference_key='baseline_metrics'
            )
            if saved_baseline:
                self.baseline_metrics = saved_baseline
            
            # Load recent analysis results
            recent_results = db_manager.get_analysis_results(
                tool_id=self.tool_id, limit=20
            )
            
            # Convert to metrics history format
            for result in reversed(recent_results):  # Reverse to get chronological order
                if 'metrics' in result and result['metrics']:
                    self.metrics_history.append({
                        'timestamp': result['timestamp'],
                        'metrics': result['metrics']
                    })
        
        except Exception as e:
            print(f"Error loading saved data: {e}")


# Tool is loaded via ToolFrame class