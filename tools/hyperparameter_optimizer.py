# hyperparameter_optimizer.py - Hyperparameter Optimization Tool for ML Models
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
from sklearn.model_selection import GridSearchCV, RandomizedSearchCV, cross_val_score
from sklearn.metrics import accuracy_score, mean_squared_error, r2_score
import warnings
warnings.filterwarnings('ignore')

from base_tool import AdvancedToolFrame
from utils.ml_utils import ml_utils
from utils.database import db_manager

TAB_NAME = "Hyperparameter Optimizer"

class ToolFrame(AdvancedToolFrame):
    def __init__(self, master):
        tool_config = {
            'name': 'Hyperparameter Optimizer',
            'tool_id': 'hyperparameter_optimizer',
            'category': 'AI/ML Development'
        }
        super().__init__(master, tool_config)
        
        self.model = None
        self.X_train = None
        self.y_train = None
        self.X_test = None
        self.y_test = None
        self.param_grid = {}
        self.optimization_results = {}
        self.best_params = None
        self.optimization_history = []
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        self.add_label("🎯 Hyperparameter Optimizer", ("Consolas", 16, "bold"))
        self.add_label("Automatically find optimal model configurations")
        
        # Model and data loading section
        data_frame = tk.Frame(self, bg=self.master.cget('bg'))
        data_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(data_frame, text="Model & Data Management:", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(anchor="w")
        
        data_buttons_frame = tk.Frame(data_frame, bg=self.master.cget('bg'))
        data_buttons_frame.pack(fill="x", pady=5)
        
        self.add_button_to_frame(data_buttons_frame, "Load Model", self.load_model)
        self.add_button_to_frame(data_buttons_frame, "Load Training Data", self.load_training_data)
        self.add_button_to_frame(data_buttons_frame, "Load Test Data", self.load_test_data)
        
        # Model info display
        self.model_info_text = tk.Text(data_frame, height=3, width=80, 
                                      bg="#111111", fg="white", wrap="word")
        self.model_info_text.pack(fill="x", pady=5)
        
        # Parameter configuration section
        param_frame = tk.Frame(self, bg=self.master.cget('bg'))
        param_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(param_frame, text="Parameter Configuration:", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(anchor="w")
        
        # Parameter grid input
        param_input_frame = tk.Frame(param_frame, bg=self.master.cget('bg'))
        param_input_frame.pack(fill="x", pady=5)
        
        tk.Label(param_input_frame, text="Parameter Grid (JSON format):", 
                bg=self.master.cget('bg'), fg="white").pack(anchor="w")
        
        self.param_grid_text = tk.Text(param_input_frame, height=6, width=80, 
                                      bg="#111111", fg="white", wrap="word")
        self.param_grid_text.pack(fill="x", pady=2)
        
        # Insert default parameter grid
        default_params = '''{
    "n_estimators": [50, 100, 200],
    "max_depth": [3, 5, 7, 10],
    "learning_rate": [0.01, 0.1, 0.2],
    "min_samples_split": [2, 5, 10]
}'''
        self.param_grid_text.insert(1.0, default_params)
        
        param_buttons_frame = tk.Frame(param_frame, bg=self.master.cget('bg'))
        param_buttons_frame.pack(fill="x", pady=5)
        
        self.add_button_to_frame(param_buttons_frame, "Load Common Params", self.load_common_params)
        self.add_button_to_frame(param_buttons_frame, "Validate Params", self.validate_params)
        
        # Optimization configuration section
        opt_frame = tk.Frame(self, bg=self.master.cget('bg'))
        opt_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(opt_frame, text="Optimization Configuration:", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(anchor="w")
        
        # Optimization method selection
        method_frame = tk.Frame(opt_frame, bg=self.master.cget('bg'))
        method_frame.pack(fill="x", pady=2)
        
        tk.Label(method_frame, text="Method:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.optimization_method = tk.StringVar(value="grid_search")
        method_combo = ttk.Combobox(method_frame, textvariable=self.optimization_method,
                                   values=["grid_search", "random_search", "bayesian_optimization"],
                                   state="readonly", width=20)
        method_combo.pack(side="left", padx=5)
        
        # Cross-validation folds
        cv_frame = tk.Frame(opt_frame, bg=self.master.cget('bg'))
        cv_frame.pack(fill="x", pady=2)
        
        tk.Label(cv_frame, text="CV Folds:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.cv_folds_var = tk.StringVar(value="5")
        cv_entry = tk.Entry(cv_frame, textvariable=self.cv_folds_var, 
                           width=10, bg="#111111", fg="white")
        cv_entry.pack(side="left", padx=5)
        
        # Number of iterations (for random search)
        iter_frame = tk.Frame(opt_frame, bg=self.master.cget('bg'))
        iter_frame.pack(fill="x", pady=2)
        
        tk.Label(iter_frame, text="Iterations (Random Search):", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.n_iter_var = tk.StringVar(value="50")
        iter_entry = tk.Entry(iter_frame, textvariable=self.n_iter_var, 
                             width=10, bg="#111111", fg="white")
        iter_entry.pack(side="left", padx=5)
        
        # Scoring metric
        scoring_frame = tk.Frame(opt_frame, bg=self.master.cget('bg'))
        scoring_frame.pack(fill="x", pady=2)
        
        tk.Label(scoring_frame, text="Scoring Metric:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.scoring_metric = tk.StringVar(value="accuracy")
        scoring_combo = ttk.Combobox(scoring_frame, textvariable=self.scoring_metric,
                                    values=["accuracy", "precision", "recall", "f1", "roc_auc", 
                                           "neg_mean_squared_error", "r2"],
                                    state="readonly", width=20)
        scoring_combo.pack(side="left", padx=5)
        
        # Optimization controls
        opt_buttons_frame = tk.Frame(opt_frame, bg=self.master.cget('bg'))
        opt_buttons_frame.pack(fill="x", pady=5)
        
        self.add_button_to_frame(opt_buttons_frame, "Start Optimization", self.start_optimization)
        self.add_button_to_frame(opt_buttons_frame, "Stop Optimization", self.stop_optimization)
        self.add_button_to_frame(opt_buttons_frame, "View Results", self.view_results)
        
        # Setup advanced UI components
        self.setup_advanced_ui()
        
        # Visualization area
        self.setup_visualization_area()
        
        # Optimization control variables
        self.optimization_running = False
        self.optimization_thread = None
    
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
        
        tk.Label(viz_frame, text="Optimization Results:", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(anchor="w")
        
        # Create matplotlib figure
        self.fig = Figure(figsize=(12, 8), facecolor='#1a1a1a')
        self.canvas = FigureCanvasTk(self.fig, viz_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        
        # Initial empty plot
        self.update_visualization()
    
    def load_model(self):
        """Load a machine learning model"""
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
            model_info += f"File: {os.path.basename(file_path)}"
            
            self.model_info_text.delete(1.0, tk.END)
            self.model_info_text.insert(1.0, model_info)
            
            # Load appropriate parameter grid for this model type
            self.load_model_specific_params()
            
            self.update_progress(100, "Model loaded")
            messagebox.showinfo("Success", "Model loaded successfully!")
            
        except Exception as e:
            self.update_progress(0, "Error loading model")
            messagebox.showerror("Error", f"Failed to load model: {str(e)}")
    
    def load_training_data(self):
        """Load training data"""
        file_path = filedialog.askopenfilename(
            title="Select Training Data",
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
            self.update_progress(20, "Loading training data...")
            
            # Load data based on file extension
            if file_path.endswith('.csv'):
                data = pd.read_csv(file_path)
            elif file_path.endswith('.xlsx'):
                data = pd.read_excel(file_path)
            elif file_path.endswith('.pkl'):
                with open(file_path, 'rb') as f:
                    data = pickle.load(f)
            else:
                messagebox.showerror("Error", "Unsupported data file format")
                return
            
            # Extract features and target
            if isinstance(data, pd.DataFrame):
                self.X_train = data.iloc[:, :-1].values
                self.y_train = data.iloc[:, -1].values
            elif isinstance(data, tuple) and len(data) == 2:
                self.X_train, self.y_train = data
            elif isinstance(data, dict) and 'X' in data and 'y' in data:
                self.X_train, self.y_train = data['X'], data['y']
            else:
                messagebox.showerror("Error", "Unsupported data format")
                return
            
            # Update model info display
            current_text = self.model_info_text.get(1.0, tk.END).strip()
            train_info = f"\\nTraining data: {len(self.X_train)} samples, {self.X_train.shape[1]} features"
            
            self.model_info_text.delete(1.0, tk.END)
            self.model_info_text.insert(1.0, current_text + train_info)
            
            self.update_progress(100, "Training data loaded")
            messagebox.showinfo("Success", "Training data loaded successfully!")
            
        except Exception as e:
            self.update_progress(0, "Error loading training data")
            messagebox.showerror("Error", f"Failed to load training data: {str(e)}")
    
    def load_test_data(self):
        """Load test data (optional)"""
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
                data = pd.read_csv(file_path)
            elif file_path.endswith('.xlsx'):
                data = pd.read_excel(file_path)
            elif file_path.endswith('.pkl'):
                with open(file_path, 'rb') as f:
                    data = pickle.load(f)
            else:
                messagebox.showerror("Error", "Unsupported data file format")
                return
            
            # Extract features and target
            if isinstance(data, pd.DataFrame):
                self.X_test = data.iloc[:, :-1].values
                self.y_test = data.iloc[:, -1].values
            elif isinstance(data, tuple) and len(data) == 2:
                self.X_test, self.y_test = data
            elif isinstance(data, dict) and 'X' in data and 'y' in data:
                self.X_test, self.y_test = data['X'], data['y']
            else:
                messagebox.showerror("Error", "Unsupported data format")
                return
            
            # Update model info display
            current_text = self.model_info_text.get(1.0, tk.END).strip()
            test_info = f"\\nTest data: {len(self.X_test)} samples"
            
            self.model_info_text.delete(1.0, tk.END)
            self.model_info_text.insert(1.0, current_text + test_info)
            
            self.update_progress(100, "Test data loaded")
            messagebox.showinfo("Success", "Test data loaded successfully!")
            
        except Exception as e:
            self.update_progress(0, "Error loading test data")
            messagebox.showerror("Error", f"Failed to load test data: {str(e)}")
    
    def load_model_specific_params(self):
        """Load parameter grid specific to the loaded model type"""
        if not self.model:
            return
        
        model_type = type(self.model).__name__.lower()
        
        # Define parameter grids for common models
        param_grids = {
            'randomforestclassifier': {
                "n_estimators": [50, 100, 200],
                "max_depth": [3, 5, 7, 10, None],
                "min_samples_split": [2, 5, 10],
                "min_samples_leaf": [1, 2, 4]
            },
            'randomforestregressor': {
                "n_estimators": [50, 100, 200],
                "max_depth": [3, 5, 7, 10, None],
                "min_samples_split": [2, 5, 10],
                "min_samples_leaf": [1, 2, 4]
            },
            'gradientboostingclassifier': {
                "n_estimators": [50, 100, 200],
                "learning_rate": [0.01, 0.1, 0.2],
                "max_depth": [3, 5, 7],
                "subsample": [0.8, 0.9, 1.0]
            },
            'gradientboostingregressor': {
                "n_estimators": [50, 100, 200],
                "learning_rate": [0.01, 0.1, 0.2],
                "max_depth": [3, 5, 7],
                "subsample": [0.8, 0.9, 1.0]
            },
            'svc': {
                "C": [0.1, 1, 10, 100],
                "gamma": ["scale", "auto", 0.001, 0.01, 0.1, 1],
                "kernel": ["rbf", "poly", "sigmoid"]
            },
            'svr': {
                "C": [0.1, 1, 10, 100],
                "gamma": ["scale", "auto", 0.001, 0.01, 0.1, 1],
                "kernel": ["rbf", "poly", "sigmoid"]
            },
            'logisticregression': {
                "C": [0.01, 0.1, 1, 10, 100],
                "penalty": ["l1", "l2"],
                "solver": ["liblinear", "saga"]
            },
            'xgbclassifier': {
                "n_estimators": [50, 100, 200],
                "learning_rate": [0.01, 0.1, 0.2],
                "max_depth": [3, 5, 7],
                "subsample": [0.8, 0.9, 1.0],
                "colsample_bytree": [0.8, 0.9, 1.0]
            },
            'xgbregressor': {
                "n_estimators": [50, 100, 200],
                "learning_rate": [0.01, 0.1, 0.2],
                "max_depth": [3, 5, 7],
                "subsample": [0.8, 0.9, 1.0],
                "colsample_bytree": [0.8, 0.9, 1.0]
            }
        }
        
        # Get parameter grid for this model type
        if model_type in param_grids:
            param_grid_json = json.dumps(param_grids[model_type], indent=2)
            self.param_grid_text.delete(1.0, tk.END)
            self.param_grid_text.insert(1.0, param_grid_json)
    
    def load_common_params(self):
        """Load common parameter configurations"""
        # Create a dialog to select common parameter sets
        param_dialog = tk.Toplevel(self)
        param_dialog.title("Select Parameter Set")
        param_dialog.geometry("400x300")
        param_dialog.configure(bg=self.master.cget('bg'))
        
        tk.Label(param_dialog, text="Select a parameter set:", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(pady=10)
        
        # Parameter set options
        param_sets = {
            "Random Forest (Quick)": {
                "n_estimators": [50, 100],
                "max_depth": [3, 5, 7],
                "min_samples_split": [2, 5]
            },
            "Random Forest (Comprehensive)": {
                "n_estimators": [50, 100, 200, 300],
                "max_depth": [3, 5, 7, 10, None],
                "min_samples_split": [2, 5, 10],
                "min_samples_leaf": [1, 2, 4],
                "max_features": ["auto", "sqrt", "log2"]
            },
            "SVM (Quick)": {
                "C": [0.1, 1, 10],
                "gamma": ["scale", 0.01, 0.1],
                "kernel": ["rbf", "poly"]
            },
            "Gradient Boosting (Quick)": {
                "n_estimators": [50, 100],
                "learning_rate": [0.1, 0.2],
                "max_depth": [3, 5]
            }
        }
        
        selected_set = tk.StringVar()
        
        for param_name in param_sets.keys():
            rb = tk.Radiobutton(param_dialog, text=param_name, variable=selected_set, 
                               value=param_name, bg=self.master.cget('bg'), fg="white",
                               selectcolor="#4ECDC4")
            rb.pack(anchor="w", padx=20, pady=2)
        
        def apply_params():
            if selected_set.get():
                param_grid_json = json.dumps(param_sets[selected_set.get()], indent=2)
                self.param_grid_text.delete(1.0, tk.END)
                self.param_grid_text.insert(1.0, param_grid_json)
                param_dialog.destroy()
        
        tk.Button(param_dialog, text="Apply", command=apply_params,
                 bg="#4ECDC4", fg="black", font=("Consolas", 10, "bold")).pack(pady=10)
    
    def validate_params(self):
        """Validate the parameter grid JSON"""
        try:
            param_text = self.param_grid_text.get(1.0, tk.END).strip()
            self.param_grid = json.loads(param_text)
            
            # Validate that parameters exist in the model
            if self.model:
                model_params = self.model.get_params().keys()
                invalid_params = [param for param in self.param_grid.keys() if param not in model_params]
                
                if invalid_params:
                    messagebox.showwarning("Warning", 
                                         f"Invalid parameters for this model: {', '.join(invalid_params)}")
                else:
                    messagebox.showinfo("Success", "Parameter grid is valid!")
            else:
                messagebox.showinfo("Success", "Parameter grid JSON is valid!")
        
        except json.JSONDecodeError as e:
            messagebox.showerror("Error", f"Invalid JSON format: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"Validation error: {str(e)}")
    
    def start_optimization(self):
        """Start hyperparameter optimization"""
        if not self.model:
            messagebox.showwarning("Warning", "Please load a model first")
            return
        
        if self.X_train is None or self.y_train is None:
            messagebox.showwarning("Warning", "Please load training data first")
            return
        
        try:
            # Validate parameters
            param_text = self.param_grid_text.get(1.0, tk.END).strip()
            self.param_grid = json.loads(param_text)
        except json.JSONDecodeError:
            messagebox.showerror("Error", "Invalid parameter grid JSON")
            return
        
        if self.optimization_running:
            messagebox.showwarning("Warning", "Optimization is already running")
            return
        
        # Start optimization in a separate thread
        self.optimization_running = True
        self.optimization_thread = threading.Thread(target=self.run_optimization)
        self.optimization_thread.daemon = True
        self.optimization_thread.start()
    
    def run_optimization(self):
        """Run the optimization process"""
        try:
            self.update_progress(10, "Starting optimization...")
            
            # Get optimization parameters
            method = self.optimization_method.get()
            cv_folds = int(self.cv_folds_var.get())
            scoring = self.scoring_metric.get()
            
            # Initialize results
            self.optimization_results = {
                'timestamp': datetime.now().isoformat(),
                'method': method,
                'cv_folds': cv_folds,
                'scoring': scoring,
                'param_grid': self.param_grid,
                'results': {}
            }
            
            self.update_progress(20, f"Running {method}...")
            
            if method == "grid_search":
                optimizer = GridSearchCV(
                    estimator=self.model,
                    param_grid=self.param_grid,
                    cv=cv_folds,
                    scoring=scoring,
                    n_jobs=-1,
                    verbose=1
                )
            
            elif method == "random_search":
                n_iter = int(self.n_iter_var.get())
                optimizer = RandomizedSearchCV(
                    estimator=self.model,
                    param_distributions=self.param_grid,
                    n_iter=n_iter,
                    cv=cv_folds,
                    scoring=scoring,
                    n_jobs=-1,
                    verbose=1,
                    random_state=42
                )
            
            elif method == "bayesian_optimization":
                # Placeholder for Bayesian optimization
                # Would require additional libraries like scikit-optimize
                messagebox.showinfo("Info", "Bayesian optimization requires additional setup. Using random search instead.")
                n_iter = int(self.n_iter_var.get())
                optimizer = RandomizedSearchCV(
                    estimator=self.model,
                    param_distributions=self.param_grid,
                    n_iter=n_iter,
                    cv=cv_folds,
                    scoring=scoring,
                    n_jobs=-1,
                    verbose=1,
                    random_state=42
                )
            
            self.update_progress(50, "Fitting optimizer...")
            
            # Fit the optimizer
            optimizer.fit(self.X_train, self.y_train)
            
            self.update_progress(80, "Processing results...")
            
            # Store results
            self.best_params = optimizer.best_params_
            self.optimization_results['results'] = {
                'best_params': optimizer.best_params_,
                'best_score': optimizer.best_score_,
                'best_estimator': str(optimizer.best_estimator_),
                'cv_results': {
                    'mean_test_score': optimizer.cv_results_['mean_test_score'].tolist(),
                    'std_test_score': optimizer.cv_results_['std_test_score'].tolist(),
                    'params': optimizer.cv_results_['params']
                }
            }
            
            # Test on test set if available
            if self.X_test is not None and self.y_test is not None:
                best_model = optimizer.best_estimator_
                y_pred = best_model.predict(self.X_test)
                
                if self.is_classification_problem():
                    test_score = accuracy_score(self.y_test, y_pred)
                    self.optimization_results['results']['test_accuracy'] = test_score
                else:
                    test_score = r2_score(self.y_test, y_pred)
                    self.optimization_results['results']['test_r2'] = test_score
            
            # Add to history
            self.optimization_history.append(self.optimization_results)
            
            # Save results
            analysis_id = f"hyperopt_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.save_analysis_result(
                analysis_id=analysis_id,
                input_data={
                    'method': method,
                    'param_grid': self.param_grid,
                    'cv_folds': cv_folds
                },
                results_summary=self.optimization_results['results'],
                recommendations=self.generate_recommendations()
            )
            
            self.update_progress(100, "Optimization complete")
            
            # Update UI in main thread
            self.after(0, self.display_optimization_results)
            
        except Exception as e:
            self.update_progress(0, f"Optimization error: {str(e)}")
            messagebox.showerror("Error", f"Optimization failed: {str(e)}")
        
        finally:
            self.optimization_running = False
    
    def stop_optimization(self):
        """Stop the running optimization"""
        if self.optimization_running:
            self.optimization_running = False
            messagebox.showinfo("Info", "Optimization will stop after current iteration")
        else:
            messagebox.showinfo("Info", "No optimization is currently running")
    
    def display_optimization_results(self):
        """Display optimization results in the UI"""
        if not self.optimization_results:
            return
        
        try:
            results = self.optimization_results['results']
            
            # Summary tab
            summary = "Hyperparameter Optimization Results\\n\\n"
            summary += f"Method: {self.optimization_results['method']}\\n"
            summary += f"CV Folds: {self.optimization_results['cv_folds']}\\n"
            summary += f"Scoring: {self.optimization_results['scoring']}\\n\\n"
            
            summary += "Best Parameters:\\n"
            for param, value in results['best_params'].items():
                summary += f"  {param}: {value}\\n"
            
            summary += f"\\nBest CV Score: {results['best_score']:.4f}\\n"
            
            if 'test_accuracy' in results:
                summary += f"Test Accuracy: {results['test_accuracy']:.4f}\\n"
            elif 'test_r2' in results:
                summary += f"Test R²: {results['test_r2']:.4f}\\n"
            
            self.update_results_tab("Summary", summary)
            
            # Detailed results
            detailed_results = json.dumps(self.optimization_results, indent=2)
            self.update_results_tab("Details", detailed_results)
            
            # Analysis tab
            analysis_text = self.format_optimization_analysis()
            self.update_results_tab("Analysis", analysis_text)
            
            # Update visualization
            self.update_visualization()
            
            # Set results for export
            self.set_results_data(self.optimization_results)
            
            messagebox.showinfo("Success", "Optimization completed successfully!")
        
        except Exception as e:
            messagebox.showerror("Error", f"Error displaying results: {str(e)}")
    
    def format_optimization_analysis(self):
        """Format optimization analysis for display"""
        if not self.optimization_results:
            return "No optimization results available"
        
        analysis = "HYPERPARAMETER OPTIMIZATION ANALYSIS\\n\\n"
        
        try:
            results = self.optimization_results['results']
            cv_results = results['cv_results']
            
            # Parameter importance analysis
            analysis += "=== PARAMETER PERFORMANCE ANALYSIS ===\\n\\n"
            
            # Get top 10 parameter combinations
            scores = cv_results['mean_test_score']
            params = cv_results['params']
            
            # Sort by score
            sorted_indices = np.argsort(scores)[::-1]  # Descending order
            
            analysis += "Top 10 Parameter Combinations:\\n"
            for i, idx in enumerate(sorted_indices[:10]):
                analysis += f"{i+1}. Score: {scores[idx]:.4f} ± {cv_results['std_test_score'][idx]:.4f}\\n"
                for param, value in params[idx].items():
                    analysis += f"   {param}: {value}\\n"
                analysis += "\\n"
            
            # Parameter sensitivity analysis
            analysis += "=== PARAMETER SENSITIVITY ===\\n\\n"
            
            # Analyze how each parameter affects performance
            param_effects = self.analyze_parameter_effects(params, scores)
            
            for param, effect_data in param_effects.items():
                analysis += f"{param}:\\n"
                analysis += f"  Best value: {effect_data['best_value']} (score: {effect_data['best_score']:.4f})\\n"
                analysis += f"  Worst value: {effect_data['worst_value']} (score: {effect_data['worst_score']:.4f})\\n"
                analysis += f"  Impact: {effect_data['impact']:.4f}\\n\\n"
        
        except Exception as e:
            analysis += f"Error in analysis: {str(e)}\\n"
        
        return analysis
    
    def analyze_parameter_effects(self, params, scores):
        """Analyze the effect of each parameter on performance"""
        param_effects = {}
        
        try:
            # Get all unique parameter names
            all_param_names = set()
            for param_dict in params:
                all_param_names.update(param_dict.keys())
            
            for param_name in all_param_names:
                # Group results by parameter value
                value_scores = {}
                
                for param_dict, score in zip(params, scores):
                    if param_name in param_dict:
                        value = param_dict[param_name]
                        if value not in value_scores:
                            value_scores[value] = []
                        value_scores[value].append(score)
                
                # Calculate average score for each value
                avg_scores = {}
                for value, score_list in value_scores.items():
                    avg_scores[value] = np.mean(score_list)
                
                if avg_scores:
                    best_value = max(avg_scores, key=avg_scores.get)
                    worst_value = min(avg_scores, key=avg_scores.get)
                    
                    param_effects[param_name] = {
                        'best_value': best_value,
                        'best_score': avg_scores[best_value],
                        'worst_value': worst_value,
                        'worst_score': avg_scores[worst_value],
                        'impact': avg_scores[best_value] - avg_scores[worst_value]
                    }
        
        except Exception as e:
            print(f"Error analyzing parameter effects: {e}")
        
        return param_effects
    
    def generate_recommendations(self):
        """Generate recommendations based on optimization results"""
        recommendations = []
        
        try:
            if not self.optimization_results:
                return recommendations
            
            results = self.optimization_results['results']
            best_score = results['best_score']
            
            # Score-based recommendations
            if best_score > 0.9:
                recommendations.append("Excellent performance achieved. Consider this configuration for production.")
            elif best_score > 0.8:
                recommendations.append("Good performance. Consider fine-tuning with narrower parameter ranges.")
            elif best_score > 0.7:
                recommendations.append("Moderate performance. Try different algorithms or feature engineering.")
            else:
                recommendations.append("Low performance. Consider data preprocessing, feature selection, or different algorithms.")
            
            # Method-specific recommendations
            method = self.optimization_results['method']
            if method == "grid_search":
                recommendations.append("Grid search completed. Consider random search for larger parameter spaces.")
            elif method == "random_search":
                recommendations.append("Random search completed. Consider Bayesian optimization for more efficient search.")
            
            # Parameter-specific recommendations
            best_params = results['best_params']
            
            # Check for boundary values
            for param, value in best_params.items():
                if param in self.param_grid:
                    param_values = self.param_grid[param]
                    if isinstance(param_values, list):
                        if value == min(param_values):
                            recommendations.append(f"Best {param} is at minimum tested value. Consider lower values.")
                        elif value == max(param_values):
                            recommendations.append(f"Best {param} is at maximum tested value. Consider higher values.")
            
            # General recommendations
            recommendations.append("Monitor model performance on validation data to prevent overfitting.")
            recommendations.append("Consider ensemble methods to improve robustness.")
            
        except Exception as e:
            recommendations.append(f"Error generating recommendations: {str(e)}")
        
        return recommendations
    
    def view_results(self):
        """View optimization results and history"""
        if not self.optimization_history:
            messagebox.showinfo("Info", "No optimization history available")
            return
        
        try:
            # Display history summary
            history_text = "Optimization History:\\n\\n"
            
            for i, result in enumerate(self.optimization_history[-5:], 1):  # Last 5 results
                history_text += f"Run {i} - {result['timestamp']}\\n"
                history_text += f"Method: {result['method']}\\n"
                history_text += f"Best Score: {result['results']['best_score']:.4f}\\n"
                history_text += f"Best Params: {result['results']['best_params']}\\n"
                history_text += "-" * 50 + "\\n\\n"
            
            self.update_results_tab("Details", history_text)
            
            # Update visualization with history
            self.update_visualization()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error viewing results: {str(e)}")
    
    def is_classification_problem(self):
        """Determine if this is a classification problem"""
        if self.y_train is None:
            return True  # Default assumption
        
        # Check if target values are discrete/categorical
        unique_values = len(np.unique(self.y_train))
        total_values = len(self.y_train)
        
        # If unique values are less than 20% of total or less than 10, likely classification
        return unique_values < min(10, total_values * 0.2)
    
    def update_visualization(self):
        """Update optimization visualization"""
        self.fig.clear()
        
        if not self.optimization_results:
            ax = self.fig.add_subplot(111)
            ax.text(0.5, 0.5, 'No optimization results available\\nRun optimization to see results', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=12, color='white')
            ax.set_facecolor('#1a1a1a')
            self.canvas.draw()
            return
        
        try:
            # Create subplots for different visualizations
            fig_rows = 2
            fig_cols = 2
            
            # Plot 1: Parameter importance
            ax1 = self.fig.add_subplot(fig_rows, fig_cols, 1)
            self.plot_parameter_importance(ax1)
            
            # Plot 2: Score distribution
            ax2 = self.fig.add_subplot(fig_rows, fig_cols, 2)
            self.plot_score_distribution(ax2)
            
            # Plot 3: Optimization history
            ax3 = self.fig.add_subplot(fig_rows, fig_cols, 3)
            self.plot_optimization_history(ax3)
            
            # Plot 4: Parameter correlation
            ax4 = self.fig.add_subplot(fig_rows, fig_cols, 4)
            self.plot_parameter_effects(ax4)
        
        except Exception as e:
            ax = self.fig.add_subplot(111)
            ax.text(0.5, 0.5, f'Error creating visualization:\\n{str(e)}', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=10, color='white')
            ax.set_facecolor('#1a1a1a')
        
        self.fig.patch.set_facecolor('#1a1a1a')
        plt.tight_layout()
        self.canvas.draw()
    
    def plot_parameter_importance(self, ax):
        """Plot parameter importance based on optimization results"""
        try:
            results = self.optimization_results['results']
            cv_results = results['cv_results']
            
            # Analyze parameter effects
            param_effects = self.analyze_parameter_effects(cv_results['params'], cv_results['mean_test_score'])
            
            if param_effects:
                params = list(param_effects.keys())
                impacts = [param_effects[param]['impact'] for param in params]
                
                bars = ax.bar(params, impacts, color='#4ECDC4', alpha=0.7)
                ax.set_title('Parameter Impact on Performance', fontsize=10, color='white')
                ax.set_ylabel('Performance Impact', color='white')
                ax.tick_params(colors='white')
                
                # Rotate x-axis labels for better readability
                plt.setp(ax.get_xticklabels(), rotation=45, ha='right')
                
                # Add value labels
                for bar, impact in zip(bars, impacts):
                    height = bar.get_height()
                    ax.text(bar.get_x() + bar.get_width()/2., height + max(impacts) * 0.01,
                           f'{impact:.3f}', ha='center', va='bottom', color='white', fontsize=8)
            else:
                ax.text(0.5, 0.5, 'No parameter impact data', ha='center', va='center', 
                       transform=ax.transAxes, color='white')
            
            ax.set_facecolor('#1a1a1a')
        
        except Exception as e:
            ax.text(0.5, 0.5, f'Error: {str(e)}', ha='center', va='center', 
                   transform=ax.transAxes, color='white', fontsize=8)
            ax.set_facecolor('#1a1a1a')
    
    def plot_score_distribution(self, ax):
        """Plot distribution of CV scores"""
        try:
            results = self.optimization_results['results']
            scores = results['cv_results']['mean_test_score']
            
            ax.hist(scores, bins=20, color='#4ECDC4', alpha=0.7, edgecolor='white')
            ax.axvline(results['best_score'], color='red', linestyle='--', 
                      label=f'Best Score: {results["best_score"]:.3f}')
            ax.set_title('CV Score Distribution', fontsize=10, color='white')
            ax.set_xlabel('CV Score', color='white')
            ax.set_ylabel('Frequency', color='white')
            ax.tick_params(colors='white')
            ax.legend()
            ax.set_facecolor('#1a1a1a')
        
        except Exception as e:
            ax.text(0.5, 0.5, f'Error: {str(e)}', ha='center', va='center', 
                   transform=ax.transAxes, color='white', fontsize=8)
            ax.set_facecolor('#1a1a1a')
    
    def plot_optimization_history(self, ax):
        """Plot optimization history over multiple runs"""
        try:
            if len(self.optimization_history) > 1:
                timestamps = [result['timestamp'] for result in self.optimization_history]
                best_scores = [result['results']['best_score'] for result in self.optimization_history]
                
                ax.plot(range(len(best_scores)), best_scores, marker='o', 
                       linewidth=2, markersize=6, color='#4ECDC4')
                ax.set_title('Optimization History', fontsize=10, color='white')
                ax.set_xlabel('Run Number', color='white')
                ax.set_ylabel('Best Score', color='white')
                ax.tick_params(colors='white')
                ax.grid(True, alpha=0.3)
            else:
                ax.text(0.5, 0.5, 'Single optimization run\\nRun multiple optimizations to see history', 
                       ha='center', va='center', transform=ax.transAxes, color='white')
            
            ax.set_facecolor('#1a1a1a')
        
        except Exception as e:
            ax.text(0.5, 0.5, f'Error: {str(e)}', ha='center', va='center', 
                   transform=ax.transAxes, color='white', fontsize=8)
            ax.set_facecolor('#1a1a1a')
    
    def plot_parameter_effects(self, ax):
        """Plot effects of individual parameters"""
        try:
            results = self.optimization_results['results']
            cv_results = results['cv_results']
            
            # Focus on one parameter for detailed analysis
            params = cv_results['params']
            scores = cv_results['mean_test_score']
            
            # Get the first parameter for visualization
            if params:
                first_param = list(params[0].keys())[0]
                
                # Group scores by parameter value
                param_values = {}
                for param_dict, score in zip(params, scores):
                    if first_param in param_dict:
                        value = param_dict[first_param]
                        if value not in param_values:
                            param_values[value] = []
                        param_values[value].append(score)
                
                # Calculate mean and std for each value
                values = list(param_values.keys())
                means = [np.mean(param_values[v]) for v in values]
                stds = [np.std(param_values[v]) for v in values]
                
                # Convert to string for plotting if needed
                if not all(isinstance(v, (int, float)) for v in values):
                    x_pos = range(len(values))
                    ax.bar(x_pos, means, yerr=stds, capsize=5, color='#4ECDC4', alpha=0.7)
                    ax.set_xticks(x_pos)
                    ax.set_xticklabels([str(v) for v in values])
                else:
                    ax.bar(values, means, yerr=stds, capsize=5, color='#4ECDC4', alpha=0.7)
                
                ax.set_title(f'Effect of {first_param}', fontsize=10, color='white')
                ax.set_xlabel(first_param, color='white')
                ax.set_ylabel('CV Score', color='white')
                ax.tick_params(colors='white')
            else:
                ax.text(0.5, 0.5, 'No parameter data', ha='center', va='center', 
                       transform=ax.transAxes, color='white')
            
            ax.set_facecolor('#1a1a1a')
        
        except Exception as e:
            ax.text(0.5, 0.5, f'Error: {str(e)}', ha='center', va='center', 
                   transform=ax.transAxes, color='white', fontsize=8)
            ax.set_facecolor('#1a1a1a')


# Tool is loaded via ToolFrame class