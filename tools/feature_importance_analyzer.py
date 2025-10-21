# feature_importance_analyzer.py - Feature Importance Analysis Tool for ML Models
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import numpy as np
import json
import pickle
import os
from datetime import datetime
import threading
from matplotlib.backends.backend_tkagg import FigureCanvasTk
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.inspection import permutation_importance
from sklearn.feature_selection import SelectKBest, f_classif, f_regression, mutual_info_classif, mutual_info_regression
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
import warnings
warnings.filterwarnings('ignore')

from base_tool import AdvancedToolFrame
from utils.ml_utils import ml_utils
from utils.database import db_manager

TAB_NAME = "Feature Importance Analyzer"

class ToolFrame(AdvancedToolFrame):
    def __init__(self, master):
        tool_config = {
            'name': 'Feature Importance Analyzer',
            'tool_id': 'feature_importance_analyzer',
            'category': 'AI/ML Development'
        }
        super().__init__(master, tool_config)
        
        self.model = None
        self.X_data = None
        self.y_data = None
        self.feature_names = None
        self.importance_results = {}
        self.analysis_history = []
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        self.add_label("📊 Feature Importance Analyzer", ("Consolas", 16, "bold"))
        self.add_label("Understand which features contribute most to model predictions")
        
        # Model and data loading section
        data_frame = tk.Frame(self, bg=self.master.cget('bg'))
        data_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(data_frame, text="Model & Data Management:", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(anchor="w")
        
        data_buttons_frame = tk.Frame(data_frame, bg=self.master.cget('bg'))
        data_buttons_frame.pack(fill="x", pady=5)
        
        self.add_button_to_frame(data_buttons_frame, "Load Model", self.load_model)
        self.add_button_to_frame(data_buttons_frame, "Load Dataset", self.load_dataset)
        self.add_button_to_frame(data_buttons_frame, "Set Feature Names", self.set_feature_names)
        
        # Model info display
        self.model_info_text = tk.Text(data_frame, height=4, width=80, 
                                      bg="#111111", fg="white", wrap="word")
        self.model_info_text.pack(fill="x", pady=5)
        
        # Analysis configuration section
        config_frame = tk.Frame(self, bg=self.master.cget('bg'))
        config_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(config_frame, text="Analysis Configuration:", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(anchor="w")
        
        # Analysis method selection
        method_frame = tk.Frame(config_frame, bg=self.master.cget('bg'))
        method_frame.pack(fill="x", pady=2)
        
        tk.Label(method_frame, text="Analysis Methods:", 
                bg=self.master.cget('bg'), fg="white").pack(anchor="w")
        
        # Checkboxes for different methods
        self.methods_frame = tk.Frame(method_frame, bg=self.master.cget('bg'))
        self.methods_frame.pack(fill="x", pady=2)
        
        self.method_vars = {}
        methods = [
            ("Built-in Importance", "builtin"),
            ("Permutation Importance", "permutation"),
            ("Statistical Tests", "statistical"),
            ("Mutual Information", "mutual_info"),
            ("Correlation Analysis", "correlation")
        ]
        
        for i, (display_name, method_key) in enumerate(methods):
            var = tk.BooleanVar(value=True if i < 2 else False)  # Default first two methods
            self.method_vars[method_key] = var
            
            cb = tk.Checkbutton(self.methods_frame, text=display_name, variable=var,
                               bg=self.master.cget('bg'), fg="white", 
                               selectcolor="#4ECDC4", activebackground=self.master.cget('bg'))
            cb.pack(side="left", padx=10)
        
        # Top N features setting
        topn_frame = tk.Frame(config_frame, bg=self.master.cget('bg'))
        topn_frame.pack(fill="x", pady=2)
        
        tk.Label(topn_frame, text="Top N Features to Display:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.top_n_var = tk.StringVar(value="10")
        topn_entry = tk.Entry(topn_frame, textvariable=self.top_n_var, 
                             width=10, bg="#111111", fg="white")
        topn_entry.pack(side="left", padx=5)
        
        # Analysis controls
        analysis_buttons_frame = tk.Frame(config_frame, bg=self.master.cget('bg'))
        analysis_buttons_frame.pack(fill="x", pady=5)
        
        self.add_button_to_frame(analysis_buttons_frame, "Run Analysis", self.run_feature_analysis)
        self.add_button_to_frame(analysis_buttons_frame, "Compare Methods", self.compare_methods)
        self.add_button_to_frame(analysis_buttons_frame, "Feature Selection", self.feature_selection_analysis)
        
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
        
        tk.Label(viz_frame, text="Feature Importance Visualization:", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(anchor="w")
        
        # Create matplotlib figure
        self.fig = Figure(figsize=(12, 8), facecolor='#1a1a1a')
        self.canvas = FigureCanvasTk(self.fig, viz_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        
        # Initial empty plot
        self.update_visualization()
    
    def load_model(self):
        """Load a trained machine learning model"""
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
                    self.model = pickle.load(f)
            elif file_path.endswith('.joblib'):
                import joblib
                self.model = joblib.load(file_path)
            else:
                messagebox.showerror("Error", "Unsupported model file format")
                return
            
            # Detect framework and get model info
            framework = ml_utils.detect_model_framework(self.model)
            
            model_info = f"Model loaded successfully!\\n"
            model_info += f"Framework: {framework}\\n"
            model_info += f"Model type: {type(self.model).__name__}\\n"
            model_info += f"File: {os.path.basename(file_path)}\\n"
            
            # Check if model supports feature importance
            supports_importance = hasattr(self.model, 'feature_importances_') or hasattr(self.model, 'coef_')
            model_info += f"Built-in importance: {'Yes' if supports_importance else 'No'}"
            
            self.model_info_text.delete(1.0, tk.END)
            self.model_info_text.insert(1.0, model_info)
            
            self.update_progress(100, "Model loaded")
            messagebox.showinfo("Success", "Model loaded successfully!")
            
        except Exception as e:
            self.update_progress(0, "Error loading model")
            messagebox.showerror("Error", f"Failed to load model: {str(e)}")
    
    def load_dataset(self):
        """Load dataset for feature importance analysis"""
        file_path = filedialog.askopenfilename(
            title="Select Dataset File",
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
            self.update_progress(20, "Loading dataset...")
            
            # Load dataset based on file extension
            if file_path.endswith('.csv'):
                data = pd.read_csv(file_path)
            elif file_path.endswith('.xlsx'):
                data = pd.read_excel(file_path)
            elif file_path.endswith('.pkl'):
                with open(file_path, 'rb') as f:
                    data = pickle.load(f)
            else:
                messagebox.showerror("Error", "Unsupported file format")
                return
            
            # Extract features and target
            if isinstance(data, pd.DataFrame):
                self.X_data = data.iloc[:, :-1]
                self.y_data = data.iloc[:, -1]
                self.feature_names = self.X_data.columns.tolist()
            elif isinstance(data, tuple) and len(data) == 2:
                self.X_data, self.y_data = data
                if isinstance(self.X_data, pd.DataFrame):
                    self.feature_names = self.X_data.columns.tolist()
                else:
                    self.feature_names = [f"feature_{i}" for i in range(self.X_data.shape[1])]
            elif isinstance(data, dict) and 'X' in data and 'y' in data:
                self.X_data, self.y_data = data['X'], data['y']
                if isinstance(self.X_data, pd.DataFrame):
                    self.feature_names = self.X_data.columns.tolist()
                else:
                    self.feature_names = [f"feature_{i}" for i in range(self.X_data.shape[1])]
            else:
                messagebox.showerror("Error", "Unsupported data format")
                return
            
            # Convert to numpy arrays if needed
            if isinstance(self.X_data, pd.DataFrame):
                self.X_data = self.X_data.values
            if isinstance(self.y_data, pd.Series):
                self.y_data = self.y_data.values
            
            # Update model info display
            current_text = self.model_info_text.get(1.0, tk.END).strip()
            data_info = f"\\nDataset: {len(self.X_data)} samples, {self.X_data.shape[1]} features"
            data_info += f"\\nFeatures: {', '.join(self.feature_names[:5])}{'...' if len(self.feature_names) > 5 else ''}"
            
            self.model_info_text.delete(1.0, tk.END)
            self.model_info_text.insert(1.0, current_text + data_info)
            
            self.update_progress(100, "Dataset loaded")
            messagebox.showinfo("Success", "Dataset loaded successfully!")
            
        except Exception as e:
            self.update_progress(0, "Error loading dataset")
            messagebox.showerror("Error", f"Failed to load dataset: {str(e)}")
    
    def set_feature_names(self):
        """Set or modify feature names"""
        if self.X_data is None:
            messagebox.showwarning("Warning", "Please load a dataset first")
            return
        
        # Create dialog for feature names
        names_dialog = tk.Toplevel(self)
        names_dialog.title("Set Feature Names")
        names_dialog.geometry("600x400")
        names_dialog.configure(bg=self.master.cget('bg'))
        
        tk.Label(names_dialog, text="Feature Names (one per line):", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(pady=10)
        
        # Text widget for feature names
        names_text = tk.Text(names_dialog, height=15, width=70, 
                            bg="#111111", fg="white", wrap="word")
        names_text.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Insert current feature names
        if self.feature_names:
            names_text.insert(1.0, "\\n".join(self.feature_names))
        
        def apply_names():
            names_content = names_text.get(1.0, tk.END).strip()
            new_names = [name.strip() for name in names_content.split("\\n") if name.strip()]
            
            if len(new_names) != self.X_data.shape[1]:
                messagebox.showerror("Error", 
                                   f"Number of names ({len(new_names)}) doesn't match number of features ({self.X_data.shape[1]})")
                return
            
            self.feature_names = new_names
            
            # Update display
            current_text = self.model_info_text.get(1.0, tk.END).strip()
            # Remove old feature info and add new
            lines = current_text.split("\\n")
            new_lines = []
            for line in lines:
                if not line.startswith("Features:"):
                    new_lines.append(line)
            
            new_text = "\\n".join(new_lines)
            new_text += f"\\nFeatures: {', '.join(self.feature_names[:5])}{'...' if len(self.feature_names) > 5 else ''}"
            
            self.model_info_text.delete(1.0, tk.END)
            self.model_info_text.insert(1.0, new_text)
            
            names_dialog.destroy()
            messagebox.showinfo("Success", "Feature names updated!")
        
        tk.Button(names_dialog, text="Apply", command=apply_names,
                 bg="#4ECDC4", fg="black", font=("Consolas", 10, "bold")).pack(pady=10)
    
    def run_feature_analysis(self):
        """Run comprehensive feature importance analysis"""
        if self.model is None:
            messagebox.showwarning("Warning", "Please load a model first")
            return
        
        if self.X_data is None or self.y_data is None:
            messagebox.showwarning("Warning", "Please load a dataset first")
            return
        
        try:
            self.update_progress(30, "Running feature importance analysis...")
            
            # Initialize results
            self.importance_results = {
                'timestamp': datetime.now().isoformat(),
                'model_type': type(self.model).__name__,
                'n_features': self.X_data.shape[1],
                'n_samples': self.X_data.shape[0],
                'feature_names': self.feature_names,
                'methods': {}
            }
            
            # Run selected analysis methods
            selected_methods = [method for method, var in self.method_vars.items() if var.get()]
            
            for i, method in enumerate(selected_methods):
                progress = 30 + (i + 1) * (60 / len(selected_methods))
                self.update_progress(progress, f"Running {method} analysis...")
                
                if method == "builtin":
                    self.importance_results['methods']['builtin'] = self.analyze_builtin_importance()
                elif method == "permutation":
                    self.importance_results['methods']['permutation'] = self.analyze_permutation_importance()
                elif method == "statistical":
                    self.importance_results['methods']['statistical'] = self.analyze_statistical_importance()
                elif method == "mutual_info":
                    self.importance_results['methods']['mutual_info'] = self.analyze_mutual_information()
                elif method == "correlation":
                    self.importance_results['methods']['correlation'] = self.analyze_correlation_importance()
            
            # Generate feature rankings and recommendations
            self.update_progress(90, "Generating recommendations...")
            self.generate_feature_recommendations()
            
            # Display results
            self.display_analysis_results()
            
            # Update visualization
            self.update_visualization()
            
            # Save analysis results
            analysis_id = f"feature_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.save_analysis_result(
                analysis_id=analysis_id,
                input_data={
                    'model_type': type(self.model).__name__,
                    'n_features': self.X_data.shape[1],
                    'methods': selected_methods
                },
                results_summary=self.importance_results['methods'],
                recommendations=self.importance_results.get('recommendations', [])
            )
            
            # Add to history
            self.analysis_history.append(self.importance_results)
            
            # Set results for export
            self.set_results_data(self.importance_results)
            
            self.update_progress(100, "Analysis complete")
            messagebox.showinfo("Success", "Feature importance analysis completed!")
            
        except Exception as e:
            self.update_progress(0, "Error in analysis")
            messagebox.showerror("Error", f"Feature analysis failed: {str(e)}")
    
    def analyze_builtin_importance(self):
        """Analyze built-in feature importance from the model"""
        results = {'method': 'Built-in Model Importance'}
        
        try:
            importance_data = ml_utils.analyze_feature_importance(self.model, self.feature_names)
            
            if importance_data.get('error'):
                results['error'] = importance_data['error']
                results['available'] = False
            else:
                results['available'] = True
                results['importance_method'] = importance_data['method']
                results['feature_importance'] = importance_data['feature_importance']
                
                # Calculate statistics
                importances = list(importance_data['feature_importance'].values())
                results['statistics'] = {
                    'mean_importance': np.mean(importances),
                    'std_importance': np.std(importances),
                    'max_importance': np.max(importances),
                    'min_importance': np.min(importances)
                }
        
        except Exception as e:
            results['error'] = str(e)
            results['available'] = False
        
        return results
    
    def analyze_permutation_importance(self):
        """Analyze permutation-based feature importance"""
        results = {'method': 'Permutation Importance'}
        
        try:
            # Use a subset of data for faster computation if dataset is large
            if len(self.X_data) > 1000:
                indices = np.random.choice(len(self.X_data), 1000, replace=False)
                X_subset = self.X_data[indices]
                y_subset = self.y_data[indices]
            else:
                X_subset = self.X_data
                y_subset = self.y_data
            
            # Calculate permutation importance
            perm_importance = permutation_importance(
                self.model, X_subset, y_subset, 
                n_repeats=10, random_state=42, n_jobs=-1
            )
            
            # Create feature importance dictionary
            feature_importance = {}
            for i, importance in enumerate(perm_importance.importances_mean):
                feature_name = self.feature_names[i] if i < len(self.feature_names) else f"feature_{i}"
                feature_importance[feature_name] = importance
            
            # Sort by importance
            sorted_importance = dict(sorted(feature_importance.items(), 
                                          key=lambda x: x[1], reverse=True))
            
            results['available'] = True
            results['feature_importance'] = sorted_importance
            results['importance_std'] = {
                self.feature_names[i] if i < len(self.feature_names) else f"feature_{i}": std
                for i, std in enumerate(perm_importance.importances_std)
            }
            
            # Calculate statistics
            importances = perm_importance.importances_mean
            results['statistics'] = {
                'mean_importance': np.mean(importances),
                'std_importance': np.std(importances),
                'max_importance': np.max(importances),
                'min_importance': np.min(importances)
            }
        
        except Exception as e:
            results['error'] = str(e)
            results['available'] = False
        
        return results
    
    def analyze_statistical_importance(self):
        """Analyze feature importance using statistical tests"""
        results = {'method': 'Statistical Tests (F-score)'}
        
        try:
            # Determine if classification or regression
            is_classification = self.is_classification_problem()
            
            if is_classification:
                selector = SelectKBest(score_func=f_classif, k='all')
            else:
                selector = SelectKBest(score_func=f_regression, k='all')
            
            # Fit selector
            selector.fit(self.X_data, self.y_data)
            
            # Get scores
            scores = selector.scores_
            
            # Create feature importance dictionary
            feature_importance = {}
            for i, score in enumerate(scores):
                feature_name = self.feature_names[i] if i < len(self.feature_names) else f"feature_{i}"
                feature_importance[feature_name] = score
            
            # Sort by importance
            sorted_importance = dict(sorted(feature_importance.items(), 
                                          key=lambda x: x[1], reverse=True))
            
            results['available'] = True
            results['feature_importance'] = sorted_importance
            results['test_type'] = 'F-classification' if is_classification else 'F-regression'
            
            # Calculate statistics
            results['statistics'] = {
                'mean_importance': np.mean(scores),
                'std_importance': np.std(scores),
                'max_importance': np.max(scores),
                'min_importance': np.min(scores)
            }
        
        except Exception as e:
            results['error'] = str(e)
            results['available'] = False
        
        return results
    
    def analyze_mutual_information(self):
        """Analyze feature importance using mutual information"""
        results = {'method': 'Mutual Information'}
        
        try:
            # Determine if classification or regression
            is_classification = self.is_classification_problem()
            
            if is_classification:
                mi_scores = mutual_info_classif(self.X_data, self.y_data, random_state=42)
            else:
                mi_scores = mutual_info_regression(self.X_data, self.y_data, random_state=42)
            
            # Create feature importance dictionary
            feature_importance = {}
            for i, score in enumerate(mi_scores):
                feature_name = self.feature_names[i] if i < len(self.feature_names) else f"feature_{i}"
                feature_importance[feature_name] = score
            
            # Sort by importance
            sorted_importance = dict(sorted(feature_importance.items(), 
                                          key=lambda x: x[1], reverse=True))
            
            results['available'] = True
            results['feature_importance'] = sorted_importance
            results['mi_type'] = 'classification' if is_classification else 'regression'
            
            # Calculate statistics
            results['statistics'] = {
                'mean_importance': np.mean(mi_scores),
                'std_importance': np.std(mi_scores),
                'max_importance': np.max(mi_scores),
                'min_importance': np.min(mi_scores)
            }
        
        except Exception as e:
            results['error'] = str(e)
            results['available'] = False
        
        return results
    
    def analyze_correlation_importance(self):
        """Analyze feature importance using correlation with target"""
        results = {'method': 'Correlation with Target'}
        
        try:
            # Calculate correlations
            correlations = []
            for i in range(self.X_data.shape[1]):
                corr = np.corrcoef(self.X_data[:, i], self.y_data)[0, 1]
                correlations.append(abs(corr))  # Use absolute correlation
            
            # Create feature importance dictionary
            feature_importance = {}
            for i, corr in enumerate(correlations):
                feature_name = self.feature_names[i] if i < len(self.feature_names) else f"feature_{i}"
                feature_importance[feature_name] = corr if not np.isnan(corr) else 0.0
            
            # Sort by importance
            sorted_importance = dict(sorted(feature_importance.items(), 
                                          key=lambda x: x[1], reverse=True))
            
            results['available'] = True
            results['feature_importance'] = sorted_importance
            
            # Calculate statistics
            valid_correlations = [c for c in correlations if not np.isnan(c)]
            results['statistics'] = {
                'mean_importance': np.mean(valid_correlations),
                'std_importance': np.std(valid_correlations),
                'max_importance': np.max(valid_correlations),
                'min_importance': np.min(valid_correlations)
            }
        
        except Exception as e:
            results['error'] = str(e)
            results['available'] = False
        
        return results
    
    def generate_feature_recommendations(self):
        """Generate recommendations based on feature importance analysis"""
        recommendations = []
        
        try:
            methods = self.importance_results['methods']
            available_methods = [method for method, data in methods.items() 
                               if data.get('available', False)]
            
            if not available_methods:
                recommendations.append("No feature importance methods were successful. Check model compatibility and data quality.")
                self.importance_results['recommendations'] = recommendations
                return
            
            # Aggregate feature rankings across methods
            feature_rankings = self.aggregate_feature_rankings()
            
            if feature_rankings:
                top_features = list(feature_rankings.keys())[:5]
                recommendations.append(f"Top 5 most important features: {', '.join(top_features)}")
                
                # Check for low-importance features
                bottom_features = list(feature_rankings.keys())[-5:]
                recommendations.append(f"Consider removing low-importance features: {', '.join(bottom_features)}")
                
                # Feature selection recommendations
                n_features = len(feature_rankings)
                if n_features > 20:
                    recommendations.append(f"With {n_features} features, consider feature selection to improve model performance and interpretability.")
                
                # Method-specific recommendations
                if 'permutation' in available_methods:
                    recommendations.append("Permutation importance provides model-agnostic feature rankings.")
                
                if 'builtin' in available_methods:
                    recommendations.append("Built-in importance is fast but may be biased toward certain feature types.")
                
                # Consistency check
                if len(available_methods) > 1:
                    consistency_score = self.calculate_ranking_consistency()
                    if consistency_score < 0.5:
                        recommendations.append("Low consistency between methods suggests feature importance may be unstable. Consider ensemble methods.")
                    else:
                        recommendations.append("Good consistency between methods increases confidence in feature rankings.")
            
            # General recommendations
            recommendations.append("Validate feature importance with domain expertise.")
            recommendations.append("Consider feature interactions and non-linear relationships.")
            recommendations.append("Monitor feature importance changes over time.")
        
        except Exception as e:
            recommendations.append(f"Error generating recommendations: {str(e)}")
        
        self.importance_results['recommendations'] = recommendations
    
    def aggregate_feature_rankings(self):
        """Aggregate feature rankings across different methods"""
        methods = self.importance_results['methods']
        available_methods = {method: data for method, data in methods.items() 
                           if data.get('available', False)}
        
        if not available_methods:
            return {}
        
        # Collect all feature scores
        all_scores = {}
        
        for method, data in available_methods.items():
            feature_importance = data.get('feature_importance', {})
            
            # Normalize scores to 0-1 range
            if feature_importance:
                max_score = max(feature_importance.values())
                min_score = min(feature_importance.values())
                
                if max_score > min_score:
                    for feature, score in feature_importance.items():
                        normalized_score = (score - min_score) / (max_score - min_score)
                        
                        if feature not in all_scores:
                            all_scores[feature] = []
                        all_scores[feature].append(normalized_score)
        
        # Calculate average scores
        avg_scores = {}
        for feature, scores in all_scores.items():
            avg_scores[feature] = np.mean(scores)
        
        # Sort by average score
        return dict(sorted(avg_scores.items(), key=lambda x: x[1], reverse=True))
    
    def calculate_ranking_consistency(self):
        """Calculate consistency between different ranking methods"""
        methods = self.importance_results['methods']
        available_methods = {method: data for method, data in methods.items() 
                           if data.get('available', False)}
        
        if len(available_methods) < 2:
            return 1.0  # Perfect consistency with single method
        
        # Get rankings for each method
        rankings = {}
        for method, data in available_methods.items():
            feature_importance = data.get('feature_importance', {})
            if feature_importance:
                # Convert to ranking (1 = most important)
                sorted_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)
                rankings[method] = {feature: rank + 1 for rank, (feature, _) in enumerate(sorted_features)}
        
        if len(rankings) < 2:
            return 1.0
        
        # Calculate Spearman correlation between rankings
        from scipy.stats import spearmanr
        
        method_names = list(rankings.keys())
        correlations = []
        
        for i in range(len(method_names)):
            for j in range(i + 1, len(method_names)):
                method1, method2 = method_names[i], method_names[j]
                
                # Get common features
                common_features = set(rankings[method1].keys()) & set(rankings[method2].keys())
                
                if len(common_features) > 1:
                    ranks1 = [rankings[method1][feature] for feature in common_features]
                    ranks2 = [rankings[method2][feature] for feature in common_features]
                    
                    corr, _ = spearmanr(ranks1, ranks2)
                    if not np.isnan(corr):
                        correlations.append(corr)
        
        return np.mean(correlations) if correlations else 0.0
    
    def is_classification_problem(self):
        """Determine if this is a classification problem"""
        if self.y_data is None:
            return True  # Default assumption
        
        # Check if target values are discrete/categorical
        unique_values = len(np.unique(self.y_data))
        total_values = len(self.y_data)
        
        # If unique values are less than 20% of total or less than 10, likely classification
        return unique_values < min(10, total_values * 0.2)
    
    def compare_methods(self):
        """Compare different feature importance methods"""
        if not self.importance_results:
            messagebox.showwarning("Warning", "Please run feature analysis first")
            return
        
        try:
            # Create comparison analysis
            comparison_text = "FEATURE IMPORTANCE METHOD COMPARISON\\n\\n"
            
            methods = self.importance_results['methods']
            available_methods = {method: data for method, data in methods.items() 
                               if data.get('available', False)}
            
            if not available_methods:
                comparison_text += "No methods available for comparison."
                self.update_results_tab("Analysis", comparison_text)
                return
            
            # Method overview
            comparison_text += "Available Methods:\\n"
            for method, data in available_methods.items():
                comparison_text += f"- {data['method']}\\n"
            
            comparison_text += "\\n"
            
            # Top features comparison
            comparison_text += "Top 5 Features by Method:\\n\\n"
            
            for method, data in available_methods.items():
                feature_importance = data.get('feature_importance', {})
                if feature_importance:
                    top_features = list(feature_importance.keys())[:5]
                    comparison_text += f"{data['method']}:\\n"
                    for i, feature in enumerate(top_features, 1):
                        score = feature_importance[feature]
                        comparison_text += f"  {i}. {feature}: {score:.4f}\\n"
                    comparison_text += "\\n"
            
            # Consistency analysis
            if len(available_methods) > 1:
                consistency = self.calculate_ranking_consistency()
                comparison_text += f"Ranking Consistency Score: {consistency:.3f}\\n"
                comparison_text += f"Interpretation: {'High' if consistency > 0.7 else 'Moderate' if consistency > 0.4 else 'Low'} consistency\\n\\n"
            
            # Aggregated ranking
            aggregated_ranking = self.aggregate_feature_rankings()
            if aggregated_ranking:
                comparison_text += "Aggregated Feature Ranking (Average across methods):\\n"
                for i, (feature, score) in enumerate(list(aggregated_ranking.items())[:10], 1):
                    comparison_text += f"{i}. {feature}: {score:.4f}\\n"
            
            self.update_results_tab("Analysis", comparison_text)
            
            # Update visualization to show comparison
            self.update_visualization()
            
        except Exception as e:
            messagebox.showerror("Error", f"Method comparison failed: {str(e)}")
    
    def feature_selection_analysis(self):
        """Perform feature selection analysis"""
        if not self.importance_results:
            messagebox.showwarning("Warning", "Please run feature analysis first")
            return
        
        try:
            # Get aggregated rankings
            aggregated_ranking = self.aggregate_feature_rankings()
            
            if not aggregated_ranking:
                messagebox.showwarning("Warning", "No feature rankings available for selection analysis")
                return
            
            # Feature selection analysis
            selection_text = "FEATURE SELECTION ANALYSIS\\n\\n"
            
            total_features = len(aggregated_ranking)
            features_list = list(aggregated_ranking.keys())
            scores_list = list(aggregated_ranking.values())
            
            # Suggest different selection thresholds
            thresholds = [0.1, 0.25, 0.5, 0.75]
            
            selection_text += "Feature Selection Recommendations:\\n\\n"
            
            for threshold in thresholds:
                n_features = max(1, int(total_features * threshold))
                selected_features = features_list[:n_features]
                
                selection_text += f"Top {threshold*100:.0f}% ({n_features} features):\\n"
                selection_text += f"Features: {', '.join(selected_features[:5])}{'...' if n_features > 5 else ''}\\n"
                
                # Calculate cumulative importance
                cumulative_importance = sum(scores_list[:n_features]) / sum(scores_list)
                selection_text += f"Cumulative Importance: {cumulative_importance:.3f}\\n\\n"
            
            # Elbow method suggestion
            selection_text += "Elbow Method Analysis:\\n"
            selection_text += "Look for the 'elbow' in the feature importance curve to find optimal number of features.\\n\\n"
            
            # Feature removal suggestions
            low_importance_features = features_list[-5:]  # Bottom 5 features
            selection_text += f"Consider removing low-importance features:\\n"
            for feature in low_importance_features:
                score = aggregated_ranking[feature]
                selection_text += f"- {feature}: {score:.4f}\\n"
            
            self.update_results_tab("Analysis", selection_text)
            
        except Exception as e:
            messagebox.showerror("Error", f"Feature selection analysis failed: {str(e)}")
    
    def display_analysis_results(self):
        """Display feature importance analysis results"""
        try:
            # Summary tab
            summary = "Feature Importance Analysis Results\\n\\n"
            summary += f"Model: {self.importance_results['model_type']}\\n"
            summary += f"Features: {self.importance_results['n_features']}\\n"
            summary += f"Samples: {self.importance_results['n_samples']}\\n\\n"
            
            # Method results summary
            methods = self.importance_results['methods']
            successful_methods = [method for method, data in methods.items() 
                                if data.get('available', False)]
            
            summary += f"Successful Methods: {', '.join(successful_methods)}\\n\\n"
            
            # Top features from aggregated ranking
            aggregated_ranking = self.aggregate_feature_rankings()
            if aggregated_ranking:
                top_n = min(int(self.top_n_var.get()), len(aggregated_ranking))
                summary += f"Top {top_n} Features (Aggregated):\\n"
                for i, (feature, score) in enumerate(list(aggregated_ranking.items())[:top_n], 1):
                    summary += f"{i}. {feature}: {score:.4f}\\n"
            
            # Recommendations
            if 'recommendations' in self.importance_results:
                summary += "\\nRecommendations:\\n"
                for i, rec in enumerate(self.importance_results['recommendations'][:3], 1):
                    summary += f"{i}. {rec}\\n"
            
            self.update_results_tab("Summary", summary)
            
            # Detailed results
            detailed_results = json.dumps(self.importance_results, indent=2)
            self.update_results_tab("Details", detailed_results)
            
        except Exception as e:
            self.update_results_tab("Summary", f"Error displaying results: {str(e)}")
    
    def update_visualization(self):
        """Update feature importance visualization"""
        self.fig.clear()
        
        if not self.importance_results:
            ax = self.fig.add_subplot(111)
            ax.text(0.5, 0.5, 'No feature importance data available\\nRun analysis to see results', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=12, color='white')
            ax.set_facecolor('#1a1a1a')
            self.canvas.draw()
            return
        
        try:
            methods = self.importance_results['methods']
            available_methods = {method: data for method, data in methods.items() 
                               if data.get('available', False)}
            
            if not available_methods:
                ax = self.fig.add_subplot(111)
                ax.text(0.5, 0.5, 'No successful analysis methods', ha='center', va='center', 
                       transform=ax.transAxes, fontsize=12, color='white')
                ax.set_facecolor('#1a1a1a')
                self.canvas.draw()
                return
            
            # Determine subplot layout
            n_methods = len(available_methods)
            if n_methods == 1:
                rows, cols = 1, 1
            elif n_methods == 2:
                rows, cols = 1, 2
            elif n_methods <= 4:
                rows, cols = 2, 2
            else:
                rows, cols = 2, 3
            
            # Plot each method
            for i, (method, data) in enumerate(available_methods.items()):
                ax = self.fig.add_subplot(rows, cols, i + 1)
                self.plot_method_importance(ax, method, data)
            
            # If there's space, add aggregated plot
            if len(available_methods) > 1 and len(available_methods) < rows * cols:
                ax = self.fig.add_subplot(rows, cols, len(available_methods) + 1)
                self.plot_aggregated_importance(ax)
        
        except Exception as e:
            ax = self.fig.add_subplot(111)
            ax.text(0.5, 0.5, f'Error creating visualization:\\n{str(e)}', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=10, color='white')
            ax.set_facecolor('#1a1a1a')
        
        self.fig.patch.set_facecolor('#1a1a1a')
        plt.tight_layout()
        self.canvas.draw()
    
    def plot_method_importance(self, ax, method, data):
        """Plot feature importance for a specific method"""
        try:
            feature_importance = data.get('feature_importance', {})
            
            if not feature_importance:
                ax.text(0.5, 0.5, f'No data for {method}', ha='center', va='center', 
                       transform=ax.transAxes, color='white')
                ax.set_facecolor('#1a1a1a')
                return
            
            # Get top N features
            top_n = min(int(self.top_n_var.get()), len(feature_importance))
            items = list(feature_importance.items())[:top_n]
            features, importances = zip(*items)
            
            # Create horizontal bar plot
            y_pos = np.arange(len(features))
            bars = ax.barh(y_pos, importances, color='#4ECDC4', alpha=0.7)
            
            ax.set_yticks(y_pos)
            ax.set_yticklabels([f[:15] + '...' if len(f) > 15 else f for f in features], fontsize=8)
            ax.invert_yaxis()  # Top feature at top
            ax.set_xlabel('Importance', color='white', fontsize=8)
            ax.set_title(data['method'], fontsize=9, color='white')
            ax.tick_params(colors='white', labelsize=8)
            
            # Add value labels
            for i, (bar, importance) in enumerate(zip(bars, importances)):
                width = bar.get_width()
                ax.text(width + max(importances) * 0.01, bar.get_y() + bar.get_height()/2,
                       f'{importance:.3f}', ha='left', va='center', color='white', fontsize=7)
            
            ax.set_facecolor('#1a1a1a')
        
        except Exception as e:
            ax.text(0.5, 0.5, f'Error: {str(e)}', ha='center', va='center', 
                   transform=ax.transAxes, color='white', fontsize=8)
            ax.set_facecolor('#1a1a1a')
    
    def plot_aggregated_importance(self, ax):
        """Plot aggregated feature importance"""
        try:
            aggregated_ranking = self.aggregate_feature_rankings()
            
            if not aggregated_ranking:
                ax.text(0.5, 0.5, 'No aggregated data', ha='center', va='center', 
                       transform=ax.transAxes, color='white')
                ax.set_facecolor('#1a1a1a')
                return
            
            # Get top N features
            top_n = min(int(self.top_n_var.get()), len(aggregated_ranking))
            items = list(aggregated_ranking.items())[:top_n]
            features, scores = zip(*items)
            
            # Create horizontal bar plot
            y_pos = np.arange(len(features))
            bars = ax.barh(y_pos, scores, color='#FF6B6B', alpha=0.7)
            
            ax.set_yticks(y_pos)
            ax.set_yticklabels([f[:15] + '...' if len(f) > 15 else f for f in features], fontsize=8)
            ax.invert_yaxis()
            ax.set_xlabel('Aggregated Score', color='white', fontsize=8)
            ax.set_title('Aggregated Ranking', fontsize=9, color='white')
            ax.tick_params(colors='white', labelsize=8)
            
            # Add value labels
            for i, (bar, score) in enumerate(zip(bars, scores)):
                width = bar.get_width()
                ax.text(width + max(scores) * 0.01, bar.get_y() + bar.get_height()/2,
                       f'{score:.3f}', ha='left', va='center', color='white', fontsize=7)
            
            ax.set_facecolor('#1a1a1a')
        
        except Exception as e:
            ax.text(0.5, 0.5, f'Error: {str(e)}', ha='center', va='center', 
                   transform=ax.transAxes, color='white', fontsize=8)
            ax.set_facecolor('#1a1a1a')


# Tool is loaded via ToolFrame class