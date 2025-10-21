# dataset_bias_detector.py - Dataset Bias Detection Tool for AI/ML Fairness
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import numpy as np
import json
import os
from datetime import datetime
import threading
from matplotlib.backends.backend_tkagg import FigureCanvasTk
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
from collections import Counter

from base_tool import AdvancedToolFrame
from utils.ml_utils import ml_utils
from utils.database import db_manager

TAB_NAME = "Dataset Bias Detector"

class ToolFrame(AdvancedToolFrame):
    def __init__(self, master):
        tool_config = {
            'name': 'Dataset Bias Detector',
            'tool_id': 'dataset_bias_detector',
            'category': 'AI/ML Development'
        }
        super().__init__(master, tool_config)
        
        self.dataset = None
        self.protected_attributes = []
        self.target_column = None
        self.bias_analysis_results = {}
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        self.add_label("⚖️ Dataset Bias Detector", ("Consolas", 16, "bold"))
        self.add_label("Identify and mitigate fairness issues in training data")
        
        # Dataset loading section
        dataset_frame = tk.Frame(self, bg=self.master.cget('bg'))
        dataset_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(dataset_frame, text="Dataset Management:", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(anchor="w")
        
        dataset_buttons_frame = tk.Frame(dataset_frame, bg=self.master.cget('bg'))
        dataset_buttons_frame.pack(fill="x", pady=5)
        
        self.add_button_to_frame(dataset_buttons_frame, "Load Dataset", self.load_dataset)
        self.add_button_to_frame(dataset_buttons_frame, "Configure Analysis", self.configure_analysis)
        self.add_button_to_frame(dataset_buttons_frame, "Run Bias Analysis", self.run_bias_analysis)
        
        # Dataset info display
        self.dataset_info_text = tk.Text(dataset_frame, height=4, width=80, 
                                        bg="#111111", fg="white", wrap="word")
        self.dataset_info_text.pack(fill="x", pady=5)
        
        # Configuration section
        config_frame = tk.Frame(self, bg=self.master.cget('bg'))
        config_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(config_frame, text="Analysis Configuration:", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(anchor="w")
        
        # Protected attributes selection
        protected_frame = tk.Frame(config_frame, bg=self.master.cget('bg'))
        protected_frame.pack(fill="x", pady=2)
        
        tk.Label(protected_frame, text="Protected Attributes:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.protected_attrs_var = tk.StringVar()
        self.protected_attrs_entry = tk.Entry(protected_frame, textvariable=self.protected_attrs_var, 
                                             width=40, bg="#111111", fg="white")
        self.protected_attrs_entry.pack(side="left", padx=5)
        
        # Target column selection
        target_frame = tk.Frame(config_frame, bg=self.master.cget('bg'))
        target_frame.pack(fill="x", pady=2)
        
        tk.Label(target_frame, text="Target Column:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.target_column_var = tk.StringVar()
        self.target_column_entry = tk.Entry(target_frame, textvariable=self.target_column_var, 
                                           width=30, bg="#111111", fg="white")
        self.target_column_entry.pack(side="left", padx=5)
        
        # Bias metrics selection
        metrics_frame = tk.Frame(config_frame, bg=self.master.cget('bg'))
        metrics_frame.pack(fill="x", pady=5)
        
        tk.Label(metrics_frame, text="Bias Metrics:", 
                bg=self.master.cget('bg'), fg="white").pack(anchor="w")
        
        metrics_buttons_frame = tk.Frame(metrics_frame, bg=self.master.cget('bg'))
        metrics_buttons_frame.pack(fill="x", pady=2)
        
        self.add_button_to_frame(metrics_buttons_frame, "Statistical Parity", self.analyze_statistical_parity)
        self.add_button_to_frame(metrics_buttons_frame, "Equalized Odds", self.analyze_equalized_odds)
        self.add_button_to_frame(metrics_buttons_frame, "Demographic Parity", self.analyze_demographic_parity)
        
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
        
        tk.Label(viz_frame, text="Bias Analysis Visualization:", 
                bg=self.master.cget('bg'), fg="white", 
                font=("Consolas", 12, "bold")).pack(anchor="w")
        
        # Create matplotlib figure
        self.fig = Figure(figsize=(12, 8), facecolor='#1a1a1a')
        self.canvas = FigureCanvasTk(self.fig, viz_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        
        # Initial empty plot
        self.update_visualization()
    
    def load_dataset(self):
        """Load dataset for bias analysis"""
        file_path = filedialog.askopenfilename(
            title="Select Dataset File",
            filetypes=[
                ("CSV files", "*.csv"),
                ("Excel files", "*.xlsx"),
                ("Parquet files", "*.parquet"),
                ("All files", "*.*")
            ]
        )
        
        if not file_path:
            return
        
        try:
            self.update_progress(20, "Loading dataset...")
            
            # Load dataset based on file extension
            if file_path.endswith('.csv'):
                self.dataset = pd.read_csv(file_path)
            elif file_path.endswith('.xlsx'):
                self.dataset = pd.read_excel(file_path)
            elif file_path.endswith('.parquet'):
                self.dataset = pd.read_parquet(file_path)
            else:
                messagebox.showerror("Error", "Unsupported file format")
                return
            
            # Display dataset info
            dataset_info = f"Dataset loaded successfully!\\n"
            dataset_info += f"Shape: {self.dataset.shape[0]} rows, {self.dataset.shape[1]} columns\\n"
            dataset_info += f"Columns: {', '.join(self.dataset.columns.tolist())}\\n"
            dataset_info += f"File: {os.path.basename(file_path)}"
            
            self.dataset_info_text.delete(1.0, tk.END)
            self.dataset_info_text.insert(1.0, dataset_info)
            
            # Auto-suggest protected attributes (common demographic columns)
            suggested_attrs = self.suggest_protected_attributes()
            if suggested_attrs:
                self.protected_attrs_var.set(", ".join(suggested_attrs))
            
            self.update_progress(100, "Dataset loaded")
            messagebox.showinfo("Success", "Dataset loaded successfully!")
            
        except Exception as e:
            self.update_progress(0, "Error loading dataset")
            messagebox.showerror("Error", f"Failed to load dataset: {str(e)}")
    
    def suggest_protected_attributes(self):
        """Suggest potential protected attributes based on column names"""
        if self.dataset is None:
            return []
        
        # Common protected attribute keywords
        protected_keywords = [
            'gender', 'sex', 'race', 'ethnicity', 'age', 'religion', 
            'nationality', 'disability', 'sexual_orientation', 'marital_status',
            'income', 'education', 'occupation', 'zip_code', 'postal_code'
        ]
        
        suggested = []
        for col in self.dataset.columns:
            col_lower = col.lower()
            for keyword in protected_keywords:
                if keyword in col_lower:
                    suggested.append(col)
                    break
        
        return suggested[:3]  # Limit to top 3 suggestions
    
    def configure_analysis(self):
        """Configure bias analysis parameters"""
        if self.dataset is None:
            messagebox.showwarning("Warning", "Please load a dataset first")
            return
        
        # Parse protected attributes
        protected_attrs_text = self.protected_attrs_var.get().strip()
        if not protected_attrs_text:
            messagebox.showwarning("Warning", "Please specify protected attributes")
            return
        
        self.protected_attributes = [attr.strip() for attr in protected_attrs_text.split(',')]
        
        # Validate protected attributes exist in dataset
        missing_attrs = [attr for attr in self.protected_attributes if attr not in self.dataset.columns]
        if missing_attrs:
            messagebox.showerror("Error", f"Protected attributes not found in dataset: {', '.join(missing_attrs)}")
            return
        
        # Set target column
        target_col = self.target_column_var.get().strip()
        if target_col and target_col in self.dataset.columns:
            self.target_column = target_col
        else:
            # Auto-detect target column (last column or common target names)
            target_candidates = ['target', 'label', 'class', 'outcome', 'y']
            for candidate in target_candidates:
                if candidate in self.dataset.columns:
                    self.target_column = candidate
                    self.target_column_var.set(candidate)
                    break
            
            if not self.target_column:
                self.target_column = self.dataset.columns[-1]  # Use last column as default
                self.target_column_var.set(self.target_column)
        
        # Display configuration summary
        config_summary = f"Analysis Configuration:\\n"
        config_summary += f"Protected Attributes: {', '.join(self.protected_attributes)}\\n"
        config_summary += f"Target Column: {self.target_column}\\n"
        config_summary += f"Dataset Shape: {self.dataset.shape}"
        
        self.update_results_tab("Summary", config_summary)
        
        messagebox.showinfo("Success", "Analysis configuration completed!")
    
    def run_bias_analysis(self):
        """Run comprehensive bias analysis"""
        if self.dataset is None:
            messagebox.showwarning("Warning", "Please load a dataset first")
            return
        
        if not self.protected_attributes:
            messagebox.showwarning("Warning", "Please configure analysis first")
            return
        
        try:
            self.update_progress(30, "Running bias analysis...")
            
            # Initialize results
            self.bias_analysis_results = {
                'timestamp': datetime.now().isoformat(),
                'dataset_shape': self.dataset.shape,
                'protected_attributes': self.protected_attributes,
                'target_column': self.target_column,
                'bias_metrics': {},
                'recommendations': []
            }
            
            # Run different bias analyses
            self.update_progress(40, "Analyzing statistical parity...")
            self.bias_analysis_results['bias_metrics']['statistical_parity'] = self.calculate_statistical_parity()
            
            self.update_progress(60, "Analyzing demographic parity...")
            self.bias_analysis_results['bias_metrics']['demographic_parity'] = self.calculate_demographic_parity()
            
            self.update_progress(80, "Analyzing representation bias...")
            self.bias_analysis_results['bias_metrics']['representation_bias'] = self.calculate_representation_bias()
            
            # Generate recommendations
            self.generate_bias_recommendations()
            
            # Display results
            self.display_bias_results()
            
            # Update visualization
            self.update_visualization()
            
            # Save analysis results
            analysis_id = f"bias_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.save_analysis_result(
                analysis_id=analysis_id,
                input_data={
                    'dataset_shape': self.dataset.shape,
                    'protected_attributes': self.protected_attributes,
                    'target_column': self.target_column
                },
                results_summary=self.bias_analysis_results['bias_metrics'],
                recommendations=self.bias_analysis_results['recommendations']
            )
            
            # Set results for export
            self.set_results_data(self.bias_analysis_results)
            
            self.update_progress(100, "Bias analysis complete")
            messagebox.showinfo("Success", "Bias analysis completed!")
            
        except Exception as e:
            self.update_progress(0, "Error in bias analysis")
            messagebox.showerror("Error", f"Bias analysis failed: {str(e)}")
    
    def calculate_statistical_parity(self):
        """Calculate statistical parity metrics"""
        results = {}
        
        try:
            for attr in self.protected_attributes:
                if attr not in self.dataset.columns:
                    continue
                
                attr_results = {}
                
                # Get unique values for this protected attribute
                unique_values = self.dataset[attr].unique()
                
                if self.target_column and self.target_column in self.dataset.columns:
                    # Calculate positive outcome rates for each group
                    positive_rates = {}
                    
                    for value in unique_values:
                        group_data = self.dataset[self.dataset[attr] == value]
                        if len(group_data) > 0:
                            if self.dataset[self.target_column].dtype in ['object', 'category']:
                                # Categorical target - assume positive class is most common or '1', 'True', etc.
                                positive_class = self.get_positive_class()
                                positive_rate = (group_data[self.target_column] == positive_class).mean()
                            else:
                                # Numerical target - use mean
                                positive_rate = group_data[self.target_column].mean()
                            
                            positive_rates[str(value)] = positive_rate
                    
                    attr_results['positive_rates'] = positive_rates
                    
                    # Calculate statistical parity difference
                    if len(positive_rates) >= 2:
                        rates = list(positive_rates.values())
                        max_rate = max(rates)
                        min_rate = min(rates)
                        parity_difference = max_rate - min_rate
                        
                        attr_results['parity_difference'] = parity_difference
                        attr_results['bias_detected'] = parity_difference > 0.1  # 10% threshold
                        
                        # Calculate disparate impact ratio
                        if min_rate > 0:
                            disparate_impact = min_rate / max_rate
                            attr_results['disparate_impact_ratio'] = disparate_impact
                            attr_results['four_fifths_rule_violation'] = disparate_impact < 0.8
                
                # Group size analysis
                group_sizes = self.dataset[attr].value_counts().to_dict()
                attr_results['group_sizes'] = {str(k): v for k, v in group_sizes.items()}
                
                results[attr] = attr_results
        
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def calculate_demographic_parity(self):
        """Calculate demographic parity metrics"""
        results = {}
        
        try:
            for attr in self.protected_attributes:
                if attr not in self.dataset.columns:
                    continue
                
                attr_results = {}
                
                # Calculate representation in dataset
                total_count = len(self.dataset)
                group_counts = self.dataset[attr].value_counts()
                
                representation = {}
                for group, count in group_counts.items():
                    representation[str(group)] = {
                        'count': count,
                        'percentage': (count / total_count) * 100
                    }
                
                attr_results['representation'] = representation
                
                # Check for underrepresentation (less than expected)
                expected_representation = 100 / len(group_counts)  # Equal representation
                underrepresented_groups = []
                
                for group, data in representation.items():
                    if data['percentage'] < expected_representation * 0.5:  # Less than 50% of expected
                        underrepresented_groups.append(group)
                
                attr_results['underrepresented_groups'] = underrepresented_groups
                attr_results['representation_bias_detected'] = len(underrepresented_groups) > 0
                
                results[attr] = attr_results
        
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def calculate_representation_bias(self):
        """Calculate representation bias across protected attributes"""
        results = {}
        
        try:
            # Overall dataset statistics
            results['dataset_size'] = len(self.dataset)
            results['missing_data_analysis'] = {}
            
            # Analyze missing data patterns
            for attr in self.protected_attributes:
                if attr in self.dataset.columns:
                    missing_count = self.dataset[attr].isnull().sum()
                    missing_percentage = (missing_count / len(self.dataset)) * 100
                    
                    results['missing_data_analysis'][attr] = {
                        'missing_count': missing_count,
                        'missing_percentage': missing_percentage,
                        'bias_concern': missing_percentage > 5  # More than 5% missing
                    }
            
            # Intersectional bias analysis
            if len(self.protected_attributes) >= 2:
                intersectional_analysis = self.analyze_intersectional_bias()
                results['intersectional_bias'] = intersectional_analysis
            
            # Feature correlation with protected attributes
            correlation_analysis = self.analyze_feature_correlations()
            results['feature_correlations'] = correlation_analysis
        
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def analyze_intersectional_bias(self):
        """Analyze bias at intersections of protected attributes"""
        intersectional_results = {}
        
        try:
            # Take first two protected attributes for intersectional analysis
            attr1, attr2 = self.protected_attributes[0], self.protected_attributes[1]
            
            if attr1 in self.dataset.columns and attr2 in self.dataset.columns:
                # Create intersection groups
                intersection_groups = self.dataset.groupby([attr1, attr2]).size()
                
                intersectional_results['intersection_counts'] = {}
                for (val1, val2), count in intersection_groups.items():
                    key = f"{attr1}={val1}, {attr2}={val2}"
                    intersectional_results['intersection_counts'][key] = count
                
                # Identify underrepresented intersections
                total_intersections = len(intersection_groups)
                expected_count = len(self.dataset) / total_intersections
                
                underrepresented = []
                for (val1, val2), count in intersection_groups.items():
                    if count < expected_count * 0.3:  # Less than 30% of expected
                        underrepresented.append(f"{attr1}={val1}, {attr2}={val2}")
                
                intersectional_results['underrepresented_intersections'] = underrepresented
                intersectional_results['intersectional_bias_detected'] = len(underrepresented) > 0
        
        except Exception as e:
            intersectional_results['error'] = str(e)
        
        return intersectional_results
    
    def analyze_feature_correlations(self):
        """Analyze correlations between features and protected attributes"""
        correlation_results = {}
        
        try:
            # Get numerical columns
            numerical_cols = self.dataset.select_dtypes(include=[np.number]).columns.tolist()
            
            for attr in self.protected_attributes:
                if attr in self.dataset.columns:
                    attr_correlations = {}
                    
                    # Encode categorical protected attribute if needed
                    if self.dataset[attr].dtype == 'object':
                        # Use label encoding for correlation analysis
                        from sklearn.preprocessing import LabelEncoder
                        le = LabelEncoder()
                        encoded_attr = le.fit_transform(self.dataset[attr].fillna('missing'))
                    else:
                        encoded_attr = self.dataset[attr].fillna(0)
                    
                    # Calculate correlations with numerical features
                    high_correlations = []
                    for col in numerical_cols:
                        if col != attr:
                            correlation = np.corrcoef(encoded_attr, self.dataset[col].fillna(0))[0, 1]
                            if not np.isnan(correlation) and abs(correlation) > 0.3:  # Strong correlation
                                attr_correlations[col] = correlation
                                if abs(correlation) > 0.5:
                                    high_correlations.append(col)
                    
                    correlation_results[attr] = {
                        'correlations': attr_correlations,
                        'high_correlation_features': high_correlations,
                        'proxy_risk': len(high_correlations) > 0
                    }
        
        except Exception as e:
            correlation_results['error'] = str(e)
        
        return correlation_results
    
    def get_positive_class(self):
        """Determine the positive class for binary classification"""
        if self.target_column not in self.dataset.columns:
            return None
        
        unique_values = self.dataset[self.target_column].unique()
        
        # Common positive class indicators
        positive_indicators = ['1', 1, 'True', True, 'yes', 'Yes', 'positive', 'Positive']
        
        for indicator in positive_indicators:
            if indicator in unique_values:
                return indicator
        
        # If no clear positive indicator, use the most common class
        return self.dataset[self.target_column].mode().iloc[0] if len(self.dataset[self.target_column].mode()) > 0 else unique_values[0]
    
    def generate_bias_recommendations(self):
        """Generate recommendations based on bias analysis"""
        recommendations = []
        
        try:
            # Statistical parity recommendations
            stat_parity = self.bias_analysis_results['bias_metrics'].get('statistical_parity', {})
            for attr, results in stat_parity.items():
                if isinstance(results, dict) and results.get('bias_detected', False):
                    parity_diff = results.get('parity_difference', 0)
                    recommendations.append(
                        f"Statistical parity violation detected for {attr} "
                        f"(difference: {parity_diff:.3f}). Consider data augmentation or resampling."
                    )
                
                if isinstance(results, dict) and results.get('four_fifths_rule_violation', False):
                    recommendations.append(
                        f"Four-fifths rule violation for {attr}. "
                        f"Review selection criteria and consider bias mitigation techniques."
                    )
            
            # Demographic parity recommendations
            demo_parity = self.bias_analysis_results['bias_metrics'].get('demographic_parity', {})
            for attr, results in demo_parity.items():
                if isinstance(results, dict) and results.get('representation_bias_detected', False):
                    underrep = results.get('underrepresented_groups', [])
                    recommendations.append(
                        f"Underrepresented groups in {attr}: {', '.join(underrep)}. "
                        f"Consider targeted data collection or synthetic data generation."
                    )
            
            # Representation bias recommendations
            repr_bias = self.bias_analysis_results['bias_metrics'].get('representation_bias', {})
            
            # Missing data recommendations
            missing_analysis = repr_bias.get('missing_data_analysis', {})
            for attr, data in missing_analysis.items():
                if data.get('bias_concern', False):
                    recommendations.append(
                        f"High missing data rate for {attr} ({data['missing_percentage']:.1f}%). "
                        f"Investigate missing data patterns and consider imputation strategies."
                    )
            
            # Intersectional bias recommendations
            if repr_bias.get('intersectional_bias', {}).get('intersectional_bias_detected', False):
                recommendations.append(
                    "Intersectional bias detected. Consider stratified sampling and "
                    "intersectional fairness metrics in model evaluation."
                )
            
            # Feature correlation recommendations
            feature_corr = repr_bias.get('feature_correlations', {})
            for attr, data in feature_corr.items():
                if data.get('proxy_risk', False):
                    high_corr_features = data.get('high_correlation_features', [])
                    recommendations.append(
                        f"Proxy discrimination risk for {attr} through features: "
                        f"{', '.join(high_corr_features)}. Consider feature selection or fairness constraints."
                    )
            
            # General recommendations
            if not recommendations:
                recommendations.append("No significant bias detected. Continue monitoring with regular bias audits.")
            else:
                recommendations.append("Implement bias monitoring in your ML pipeline to track fairness metrics over time.")
                recommendations.append("Consider using fairness-aware machine learning algorithms.")
                recommendations.append("Establish bias testing protocols before model deployment.")
        
        except Exception as e:
            recommendations.append(f"Error generating recommendations: {str(e)}")
        
        self.bias_analysis_results['recommendations'] = recommendations
    
    def display_bias_results(self):
        """Display bias analysis results in the UI"""
        try:
            # Summary tab
            summary = "Dataset Bias Analysis Results\\n\\n"
            summary += f"Dataset: {self.bias_analysis_results['dataset_shape'][0]} rows, {self.bias_analysis_results['dataset_shape'][1]} columns\\n"
            summary += f"Protected Attributes: {', '.join(self.bias_analysis_results['protected_attributes'])}\\n"
            summary += f"Target Column: {self.bias_analysis_results['target_column']}\\n\\n"
            
            # Statistical parity summary
            stat_parity = self.bias_analysis_results['bias_metrics'].get('statistical_parity', {})
            bias_detected = any(
                isinstance(results, dict) and results.get('bias_detected', False) 
                for results in stat_parity.values()
            )
            summary += f"Statistical Parity Bias: {'DETECTED' if bias_detected else 'Not Detected'}\\n"
            
            # Demographic parity summary
            demo_parity = self.bias_analysis_results['bias_metrics'].get('demographic_parity', {})
            repr_bias_detected = any(
                isinstance(results, dict) and results.get('representation_bias_detected', False) 
                for results in demo_parity.values()
            )
            summary += f"Representation Bias: {'DETECTED' if repr_bias_detected else 'Not Detected'}\\n\\n"
            
            # Recommendations
            summary += "Key Recommendations:\\n"
            for i, rec in enumerate(self.bias_analysis_results['recommendations'][:3], 1):
                summary += f"{i}. {rec}\\n"
            
            self.update_results_tab("Summary", summary)
            
            # Detailed results
            detailed_results = json.dumps(self.bias_analysis_results, indent=2)
            self.update_results_tab("Details", detailed_results)
            
            # Analysis tab with formatted metrics
            analysis_text = self.format_bias_analysis()
            self.update_results_tab("Analysis", analysis_text)
        
        except Exception as e:
            self.update_results_tab("Summary", f"Error displaying results: {str(e)}")
    
    def format_bias_analysis(self):
        """Format bias analysis for display"""
        formatted = "DETAILED BIAS ANALYSIS\\n\\n"
        
        try:
            # Statistical Parity Analysis
            formatted += "=== STATISTICAL PARITY ANALYSIS ===\\n\\n"
            stat_parity = self.bias_analysis_results['bias_metrics'].get('statistical_parity', {})
            
            for attr, results in stat_parity.items():
                if isinstance(results, dict):
                    formatted += f"Protected Attribute: {attr}\\n"
                    
                    if 'positive_rates' in results:
                        formatted += "Positive Outcome Rates by Group:\\n"
                        for group, rate in results['positive_rates'].items():
                            formatted += f"  {group}: {rate:.4f}\\n"
                    
                    if 'parity_difference' in results:
                        formatted += f"Parity Difference: {results['parity_difference']:.4f}\\n"
                        formatted += f"Bias Detected: {'Yes' if results.get('bias_detected', False) else 'No'}\\n"
                    
                    if 'disparate_impact_ratio' in results:
                        formatted += f"Disparate Impact Ratio: {results['disparate_impact_ratio']:.4f}\\n"
                        formatted += f"Four-Fifths Rule Violation: {'Yes' if results.get('four_fifths_rule_violation', False) else 'No'}\\n"
                    
                    formatted += "\\n"
            
            # Demographic Parity Analysis
            formatted += "=== DEMOGRAPHIC PARITY ANALYSIS ===\\n\\n"
            demo_parity = self.bias_analysis_results['bias_metrics'].get('demographic_parity', {})
            
            for attr, results in demo_parity.items():
                if isinstance(results, dict):
                    formatted += f"Protected Attribute: {attr}\\n"
                    
                    if 'representation' in results:
                        formatted += "Group Representation:\\n"
                        for group, data in results['representation'].items():
                            formatted += f"  {group}: {data['count']} ({data['percentage']:.2f}%)\\n"
                    
                    if 'underrepresented_groups' in results:
                        underrep = results['underrepresented_groups']
                        if underrep:
                            formatted += f"Underrepresented Groups: {', '.join(underrep)}\\n"
                        else:
                            formatted += "No underrepresented groups detected\\n"
                    
                    formatted += "\\n"
            
            # Representation Bias Analysis
            formatted += "=== REPRESENTATION BIAS ANALYSIS ===\\n\\n"
            repr_bias = self.bias_analysis_results['bias_metrics'].get('representation_bias', {})
            
            if 'missing_data_analysis' in repr_bias:
                formatted += "Missing Data Analysis:\\n"
                for attr, data in repr_bias['missing_data_analysis'].items():
                    formatted += f"  {attr}: {data['missing_percentage']:.2f}% missing"
                    if data['bias_concern']:
                        formatted += " (CONCERN)"
                    formatted += "\\n"
                formatted += "\\n"
            
            if 'intersectional_bias' in repr_bias:
                intersectional = repr_bias['intersectional_bias']
                formatted += "Intersectional Bias Analysis:\\n"
                if intersectional.get('intersectional_bias_detected', False):
                    underrep_intersections = intersectional.get('underrepresented_intersections', [])
                    formatted += f"Underrepresented Intersections: {len(underrep_intersections)}\\n"
                    for intersection in underrep_intersections[:5]:  # Show first 5
                        formatted += f"  - {intersection}\\n"
                else:
                    formatted += "No significant intersectional bias detected\\n"
                formatted += "\\n"
        
        except Exception as e:
            formatted += f"Error formatting analysis: {str(e)}\\n"
        
        return formatted
    
    def analyze_statistical_parity(self):
        """Analyze statistical parity specifically"""
        if not self.bias_analysis_results:
            messagebox.showwarning("Warning", "Please run bias analysis first")
            return
        
        stat_parity = self.bias_analysis_results['bias_metrics'].get('statistical_parity', {})
        
        if not stat_parity:
            messagebox.showinfo("Info", "No statistical parity data available")
            return
        
        # Display statistical parity results
        results_text = "STATISTICAL PARITY ANALYSIS\\n\\n"
        
        for attr, results in stat_parity.items():
            if isinstance(results, dict):
                results_text += f"Protected Attribute: {attr}\\n"
                results_text += f"Bias Detected: {'Yes' if results.get('bias_detected', False) else 'No'}\\n"
                
                if 'parity_difference' in results:
                    results_text += f"Parity Difference: {results['parity_difference']:.4f}\\n"
                
                if 'positive_rates' in results:
                    results_text += "Positive Rates by Group:\\n"
                    for group, rate in results['positive_rates'].items():
                        results_text += f"  {group}: {rate:.4f}\\n"
                
                results_text += "\\n"
        
        self.update_results_tab("Analysis", results_text)
    
    def analyze_equalized_odds(self):
        """Analyze equalized odds (placeholder for future implementation)"""
        messagebox.showinfo("Info", "Equalized odds analysis requires model predictions. This feature will be available when integrated with model evaluation.")
    
    def analyze_demographic_parity(self):
        """Analyze demographic parity specifically"""
        if not self.bias_analysis_results:
            messagebox.showwarning("Warning", "Please run bias analysis first")
            return
        
        demo_parity = self.bias_analysis_results['bias_metrics'].get('demographic_parity', {})
        
        if not demo_parity:
            messagebox.showinfo("Info", "No demographic parity data available")
            return
        
        # Display demographic parity results
        results_text = "DEMOGRAPHIC PARITY ANALYSIS\\n\\n"
        
        for attr, results in demo_parity.items():
            if isinstance(results, dict):
                results_text += f"Protected Attribute: {attr}\\n"
                results_text += f"Representation Bias: {'Detected' if results.get('representation_bias_detected', False) else 'Not Detected'}\\n"
                
                if 'representation' in results:
                    results_text += "Group Representation:\\n"
                    for group, data in results['representation'].items():
                        results_text += f"  {group}: {data['count']} samples ({data['percentage']:.2f}%)\\n"
                
                if 'underrepresented_groups' in results:
                    underrep = results['underrepresented_groups']
                    if underrep:
                        results_text += f"Underrepresented: {', '.join(underrep)}\\n"
                
                results_text += "\\n"
        
        self.update_results_tab("Analysis", results_text)
    
    def update_visualization(self):
        """Update bias analysis visualization"""
        self.fig.clear()
        
        if not self.bias_analysis_results:
            ax = self.fig.add_subplot(111)
            ax.text(0.5, 0.5, 'No bias analysis data available\\nRun bias analysis to see visualizations', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=12, color='white')
            ax.set_facecolor('#1a1a1a')
            self.canvas.draw()
            return
        
        try:
            # Create subplots for different bias metrics
            fig_rows = 2
            fig_cols = 2
            
            # Plot 1: Statistical Parity Differences
            ax1 = self.fig.add_subplot(fig_rows, fig_cols, 1)
            self.plot_statistical_parity(ax1)
            
            # Plot 2: Group Representation
            ax2 = self.fig.add_subplot(fig_rows, fig_cols, 2)
            self.plot_group_representation(ax2)
            
            # Plot 3: Missing Data Analysis
            ax3 = self.fig.add_subplot(fig_rows, fig_cols, 3)
            self.plot_missing_data_analysis(ax3)
            
            # Plot 4: Feature Correlations
            ax4 = self.fig.add_subplot(fig_rows, fig_cols, 4)
            self.plot_feature_correlations(ax4)
        
        except Exception as e:
            ax = self.fig.add_subplot(111)
            ax.text(0.5, 0.5, f'Error creating visualization:\\n{str(e)}', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=10, color='white')
            ax.set_facecolor('#1a1a1a')
        
        self.fig.patch.set_facecolor('#1a1a1a')
        plt.tight_layout()
        self.canvas.draw()
    
    def plot_statistical_parity(self, ax):
        """Plot statistical parity differences"""
        try:
            stat_parity = self.bias_analysis_results['bias_metrics'].get('statistical_parity', {})
            
            attributes = []
            parity_diffs = []
            
            for attr, results in stat_parity.items():
                if isinstance(results, dict) and 'parity_difference' in results:
                    attributes.append(attr)
                    parity_diffs.append(results['parity_difference'])
            
            if attributes and parity_diffs:
                bars = ax.bar(attributes, parity_diffs, color='#FF6B6B', alpha=0.7)
                ax.set_title('Statistical Parity Differences', fontsize=10, color='white')
                ax.set_ylabel('Parity Difference', color='white')
                ax.tick_params(colors='white')
                ax.axhline(y=0.1, color='red', linestyle='--', alpha=0.7, label='Bias Threshold')
                ax.legend()
                
                # Add value labels
                for bar, value in zip(bars, parity_diffs):
                    height = bar.get_height()
                    ax.text(bar.get_x() + bar.get_width()/2., height + 0.005,
                           f'{value:.3f}', ha='center', va='bottom', color='white', fontsize=8)
            else:
                ax.text(0.5, 0.5, 'No statistical parity data', ha='center', va='center', 
                       transform=ax.transAxes, color='white')
            
            ax.set_facecolor('#1a1a1a')
        
        except Exception as e:
            ax.text(0.5, 0.5, f'Error: {str(e)}', ha='center', va='center', 
                   transform=ax.transAxes, color='white', fontsize=8)
            ax.set_facecolor('#1a1a1a')
    
    def plot_group_representation(self, ax):
        """Plot group representation"""
        try:
            demo_parity = self.bias_analysis_results['bias_metrics'].get('demographic_parity', {})
            
            if demo_parity and len(self.protected_attributes) > 0:
                # Use first protected attribute for visualization
                first_attr = self.protected_attributes[0]
                
                if first_attr in demo_parity:
                    representation = demo_parity[first_attr].get('representation', {})
                    
                    if representation:
                        groups = list(representation.keys())
                        percentages = [data['percentage'] for data in representation.values()]
                        
                        wedges, texts, autotexts = ax.pie(percentages, labels=groups, autopct='%1.1f%%', 
                                                         colors=plt.cm.Set3(np.linspace(0, 1, len(groups))))
                        ax.set_title(f'Group Representation: {first_attr}', fontsize=10, color='white')
                        
                        # Style the text
                        for text in texts:
                            text.set_color('white')
                        for autotext in autotexts:
                            autotext.set_color('black')
                    else:
                        ax.text(0.5, 0.5, 'No representation data', ha='center', va='center', 
                               transform=ax.transAxes, color='white')
                else:
                    ax.text(0.5, 0.5, 'No data for first attribute', ha='center', va='center', 
                           transform=ax.transAxes, color='white')
            else:
                ax.text(0.5, 0.5, 'No demographic data', ha='center', va='center', 
                       transform=ax.transAxes, color='white')
            
            ax.set_facecolor('#1a1a1a')
        
        except Exception as e:
            ax.text(0.5, 0.5, f'Error: {str(e)}', ha='center', va='center', 
                   transform=ax.transAxes, color='white', fontsize=8)
            ax.set_facecolor('#1a1a1a')
    
    def plot_missing_data_analysis(self, ax):
        """Plot missing data analysis"""
        try:
            repr_bias = self.bias_analysis_results['bias_metrics'].get('representation_bias', {})
            missing_analysis = repr_bias.get('missing_data_analysis', {})
            
            if missing_analysis:
                attributes = list(missing_analysis.keys())
                missing_percentages = [data['missing_percentage'] for data in missing_analysis.values()]
                colors = ['#FF6B6B' if data['bias_concern'] else '#4ECDC4' 
                         for data in missing_analysis.values()]
                
                bars = ax.bar(attributes, missing_percentages, color=colors, alpha=0.7)
                ax.set_title('Missing Data by Protected Attribute', fontsize=10, color='white')
                ax.set_ylabel('Missing Data %', color='white')
                ax.tick_params(colors='white')
                ax.axhline(y=5, color='red', linestyle='--', alpha=0.7, label='Concern Threshold (5%)')
                ax.legend()
                
                # Add value labels
                for bar, value in zip(bars, missing_percentages):
                    height = bar.get_height()
                    ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                           f'{value:.1f}%', ha='center', va='bottom', color='white', fontsize=8)
            else:
                ax.text(0.5, 0.5, 'No missing data analysis', ha='center', va='center', 
                       transform=ax.transAxes, color='white')
            
            ax.set_facecolor('#1a1a1a')
        
        except Exception as e:
            ax.text(0.5, 0.5, f'Error: {str(e)}', ha='center', va='center', 
                   transform=ax.transAxes, color='white', fontsize=8)
            ax.set_facecolor('#1a1a1a')
    
    def plot_feature_correlations(self, ax):
        """Plot feature correlations with protected attributes"""
        try:
            repr_bias = self.bias_analysis_results['bias_metrics'].get('representation_bias', {})
            feature_corr = repr_bias.get('feature_correlations', {})
            
            if feature_corr:
                # Collect all correlations
                all_correlations = []
                feature_names = []
                
                for attr, data in feature_corr.items():
                    correlations = data.get('correlations', {})
                    for feature, corr in correlations.items():
                        all_correlations.append(abs(corr))  # Use absolute correlation
                        feature_names.append(f"{attr}-{feature}")
                
                if all_correlations:
                    # Show top correlations
                    top_n = min(10, len(all_correlations))
                    sorted_indices = np.argsort(all_correlations)[-top_n:]
                    
                    top_correlations = [all_correlations[i] for i in sorted_indices]
                    top_features = [feature_names[i] for i in sorted_indices]
                    
                    colors = ['#FF6B6B' if corr > 0.5 else '#4ECDC4' for corr in top_correlations]
                    
                    bars = ax.barh(range(len(top_features)), top_correlations, color=colors, alpha=0.7)
                    ax.set_yticks(range(len(top_features)))
                    ax.set_yticklabels(top_features, fontsize=8)
                    ax.set_title('Feature Correlations with Protected Attributes', fontsize=10, color='white')
                    ax.set_xlabel('Absolute Correlation', color='white')
                    ax.tick_params(colors='white')
                    ax.axvline(x=0.5, color='red', linestyle='--', alpha=0.7, label='High Correlation (0.5)')
                    ax.legend()
                else:
                    ax.text(0.5, 0.5, 'No significant correlations', ha='center', va='center', 
                           transform=ax.transAxes, color='white')
            else:
                ax.text(0.5, 0.5, 'No correlation analysis', ha='center', va='center', 
                       transform=ax.transAxes, color='white')
            
            ax.set_facecolor('#1a1a1a')
        
        except Exception as e:
            ax.text(0.5, 0.5, f'Error: {str(e)}', ha='center', va='center', 
                   transform=ax.transAxes, color='white', fontsize=8)
            ax.set_facecolor('#1a1a1a')


# Tool is loaded via ToolFrame class