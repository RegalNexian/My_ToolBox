# ml_utils.py - Machine Learning utilities for AI/ML development tools
import numpy as np
import pandas as pd
import json
import pickle
import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.backends.backend_tkagg import FigureCanvasTk
import seaborn as sns
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
import warnings
warnings.filterwarnings('ignore')

class MLUtils:
    """Machine Learning utilities for model analysis and visualization"""
    
    def __init__(self):
        self.supported_frameworks = ['sklearn', 'tensorflow', 'pytorch', 'xgboost', 'lightgbm']
        
    def detect_model_framework(self, model) -> str:
        """Detect which ML framework the model belongs to"""
        model_type = str(type(model))
        
        if 'sklearn' in model_type:
            return 'sklearn'
        elif 'tensorflow' in model_type or 'keras' in model_type:
            return 'tensorflow'
        elif 'torch' in model_type:
            return 'pytorch'
        elif 'xgboost' in model_type:
            return 'xgboost'
        elif 'lightgbm' in model_type:
            return 'lightgbm'
        else:
            return 'unknown'
    
    def calculate_classification_metrics(self, y_true, y_pred, y_prob=None) -> Dict:
        """Calculate comprehensive classification metrics"""
        metrics = {}
        
        try:
            metrics['accuracy'] = accuracy_score(y_true, y_pred)
            metrics['precision'] = precision_score(y_true, y_pred, average='weighted', zero_division=0)
            metrics['recall'] = recall_score(y_true, y_pred, average='weighted', zero_division=0)
            metrics['f1_score'] = f1_score(y_true, y_pred, average='weighted', zero_division=0)
            
            if y_prob is not None:
                try:
                    if len(np.unique(y_true)) == 2:  # Binary classification
                        metrics['auc_roc'] = roc_auc_score(y_true, y_prob)
                    else:  # Multi-class
                        metrics['auc_roc'] = roc_auc_score(y_true, y_prob, multi_class='ovr', average='weighted')
                except Exception:
                    metrics['auc_roc'] = None
            
            # Class distribution
            unique, counts = np.unique(y_true, return_counts=True)
            metrics['class_distribution'] = dict(zip(unique.astype(str), counts.tolist()))
            
        except Exception as e:
            metrics['error'] = str(e)
        
        return metrics
    
    def calculate_regression_metrics(self, y_true, y_pred) -> Dict:
        """Calculate comprehensive regression metrics"""
        metrics = {}
        
        try:
            metrics['mse'] = mean_squared_error(y_true, y_pred)
            metrics['rmse'] = np.sqrt(metrics['mse'])
            metrics['mae'] = mean_absolute_error(y_true, y_pred)
            metrics['r2_score'] = r2_score(y_true, y_pred)
            
            # Additional metrics
            metrics['mean_residual'] = np.mean(y_true - y_pred)
            metrics['std_residual'] = np.std(y_true - y_pred)
            
            # Percentage errors
            mape = np.mean(np.abs((y_true - y_pred) / y_true)) * 100
            metrics['mape'] = mape if not np.isnan(mape) and not np.isinf(mape) else None
            
        except Exception as e:
            metrics['error'] = str(e)
        
        return metrics
    
    def detect_model_drift(self, baseline_metrics: Dict, current_metrics: Dict, 
                          threshold: float = 0.05) -> Dict:
        """Detect model performance drift"""
        drift_analysis = {
            'drift_detected': False,
            'drift_metrics': {},
            'severity': 'none',
            'recommendations': []
        }
        
        try:
            # Compare key metrics
            key_metrics = ['accuracy', 'f1_score', 'r2_score', 'auc_roc']
            
            for metric in key_metrics:
                if metric in baseline_metrics and metric in current_metrics:
                    baseline_val = baseline_metrics[metric]
                    current_val = current_metrics[metric]
                    
                    if baseline_val is not None and current_val is not None:
                        drift_pct = abs(baseline_val - current_val) / baseline_val
                        drift_analysis['drift_metrics'][metric] = {
                            'baseline': baseline_val,
                            'current': current_val,
                            'drift_percentage': drift_pct * 100,
                            'drift_detected': drift_pct > threshold
                        }
                        
                        if drift_pct > threshold:
                            drift_analysis['drift_detected'] = True
            
            # Determine severity
            if drift_analysis['drift_detected']:
                max_drift = max([m['drift_percentage'] for m in drift_analysis['drift_metrics'].values() 
                               if m['drift_detected']])
                
                if max_drift > 20:
                    drift_analysis['severity'] = 'critical'
                    drift_analysis['recommendations'].append('Immediate model retraining required')
                elif max_drift > 10:
                    drift_analysis['severity'] = 'high'
                    drift_analysis['recommendations'].append('Schedule model retraining soon')
                else:
                    drift_analysis['severity'] = 'moderate'
                    drift_analysis['recommendations'].append('Monitor closely and consider retraining')
        
        except Exception as e:
            drift_analysis['error'] = str(e)
        
        return drift_analysis
    
    def create_performance_visualization(self, metrics_history: List[Dict], 
                                       metric_name: str = 'accuracy') -> plt.Figure:
        """Create performance trend visualization"""
        fig, ax = plt.subplots(figsize=(10, 6))
        
        try:
            # Extract timestamps and metric values
            timestamps = []
            values = []
            
            for entry in metrics_history:
                if 'timestamp' in entry and metric_name in entry.get('metrics', {}):
                    timestamps.append(pd.to_datetime(entry['timestamp']))
                    values.append(entry['metrics'][metric_name])
            
            if timestamps and values:
                ax.plot(timestamps, values, marker='o', linewidth=2, markersize=6)
                ax.set_title(f'{metric_name.title()} Over Time', fontsize=14, fontweight='bold')
                ax.set_xlabel('Time', fontsize=12)
                ax.set_ylabel(metric_name.title(), fontsize=12)
                ax.grid(True, alpha=0.3)
                
                # Format x-axis
                ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))
                ax.xaxis.set_major_locator(mdates.HourLocator(interval=6))
                plt.xticks(rotation=45)
                
                # Add trend line
                if len(values) > 1:
                    z = np.polyfit(range(len(values)), values, 1)
                    p = np.poly1d(z)
                    ax.plot(timestamps, p(range(len(values))), "--", alpha=0.7, color='red')
            else:
                ax.text(0.5, 0.5, 'No data available', ha='center', va='center', 
                       transform=ax.transAxes, fontsize=14)
        
        except Exception as e:
            ax.text(0.5, 0.5, f'Error creating visualization: {str(e)}', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=12)
        
        plt.tight_layout()
        return fig
    
    def create_metrics_comparison_chart(self, metrics_data: List[Dict]) -> plt.Figure:
        """Create side-by-side metrics comparison"""
        fig, axes = plt.subplots(2, 2, figsize=(12, 10))
        axes = axes.flatten()
        
        try:
            # Common metrics to compare
            metrics_to_plot = ['accuracy', 'precision', 'recall', 'f1_score']
            
            for i, metric in enumerate(metrics_to_plot):
                ax = axes[i]
                
                # Extract metric values
                values = []
                labels = []
                
                for j, data in enumerate(metrics_data):
                    if metric in data.get('metrics', {}):
                        values.append(data['metrics'][metric])
                        labels.append(f"Model {j+1}")
                
                if values:
                    bars = ax.bar(labels, values, alpha=0.7)
                    ax.set_title(f'{metric.title()} Comparison', fontweight='bold')
                    ax.set_ylabel(metric.title())
                    
                    # Add value labels on bars
                    for bar, value in zip(bars, values):
                        height = bar.get_height()
                        ax.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                               f'{value:.3f}', ha='center', va='bottom')
                else:
                    ax.text(0.5, 0.5, f'No {metric} data', ha='center', va='center', 
                           transform=ax.transAxes)
        
        except Exception as e:
            axes[0].text(0.5, 0.5, f'Error: {str(e)}', ha='center', va='center', 
                        transform=axes[0].transAxes)
        
        plt.tight_layout()
        return fig
    
    def analyze_feature_importance(self, model, feature_names: List[str] = None) -> Dict:
        """Analyze feature importance from trained model"""
        importance_data = {
            'feature_importance': {},
            'method': 'unknown',
            'error': None
        }
        
        try:
            framework = self.detect_model_framework(model)
            
            if framework == 'sklearn':
                if hasattr(model, 'feature_importances_'):
                    importances = model.feature_importances_
                    importance_data['method'] = 'tree_based'
                elif hasattr(model, 'coef_'):
                    importances = np.abs(model.coef_).flatten()
                    importance_data['method'] = 'linear_coefficients'
                else:
                    importance_data['error'] = 'Model does not support feature importance'
                    return importance_data
            
            elif framework in ['xgboost', 'lightgbm']:
                if hasattr(model, 'feature_importances_'):
                    importances = model.feature_importances_
                    importance_data['method'] = 'gradient_boosting'
                else:
                    importance_data['error'] = 'Model does not support feature importance'
                    return importance_data
            
            else:
                importance_data['error'] = f'Feature importance not supported for {framework}'
                return importance_data
            
            # Create feature importance dictionary
            if feature_names is None:
                feature_names = [f'feature_{i}' for i in range(len(importances))]
            
            # Sort by importance
            importance_pairs = list(zip(feature_names, importances))
            importance_pairs.sort(key=lambda x: x[1], reverse=True)
            
            importance_data['feature_importance'] = dict(importance_pairs)
            
        except Exception as e:
            importance_data['error'] = str(e)
        
        return importance_data
    
    def create_feature_importance_plot(self, importance_data: Dict, top_n: int = 10) -> plt.Figure:
        """Create feature importance visualization"""
        fig, ax = plt.subplots(figsize=(10, 6))
        
        try:
            if 'error' in importance_data and importance_data['error']:
                ax.text(0.5, 0.5, f"Error: {importance_data['error']}", 
                       ha='center', va='center', transform=ax.transAxes, fontsize=12)
                return fig
            
            feature_importance = importance_data.get('feature_importance', {})
            
            if not feature_importance:
                ax.text(0.5, 0.5, 'No feature importance data available', 
                       ha='center', va='center', transform=ax.transAxes, fontsize=12)
                return fig
            
            # Get top N features
            items = list(feature_importance.items())[:top_n]
            features, importances = zip(*items)
            
            # Create horizontal bar plot
            y_pos = np.arange(len(features))
            bars = ax.barh(y_pos, importances, alpha=0.7)
            
            ax.set_yticks(y_pos)
            ax.set_yticklabels(features)
            ax.invert_yaxis()  # Top feature at top
            ax.set_xlabel('Importance Score')
            ax.set_title(f'Top {len(features)} Feature Importance', fontweight='bold')
            
            # Add value labels
            for i, (bar, importance) in enumerate(zip(bars, importances)):
                width = bar.get_width()
                ax.text(width + max(importances) * 0.01, bar.get_y() + bar.get_height()/2,
                       f'{importance:.3f}', ha='left', va='center')
        
        except Exception as e:
            ax.text(0.5, 0.5, f'Error creating plot: {str(e)}', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=12)
        
        plt.tight_layout()
        return fig
    
    def save_model_metadata(self, model, model_name: str, metrics: Dict, 
                           model_path: str = None) -> str:
        """Save model with metadata"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if model_path is None:
            model_path = f"models/{model_name}_{timestamp}"
        
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        # Save model
        model_file = f"{model_path}_model.pkl"
        with open(model_file, 'wb') as f:
            pickle.dump(model, f)
        
        # Save metadata
        metadata = {
            'model_name': model_name,
            'timestamp': timestamp,
            'framework': self.detect_model_framework(model),
            'metrics': metrics,
            'model_file': model_file
        }
        
        metadata_file = f"{model_path}_metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        return model_path
    
    def load_model_with_metadata(self, model_path: str) -> Tuple[Any, Dict]:
        """Load model with its metadata"""
        model_file = f"{model_path}_model.pkl"
        metadata_file = f"{model_path}_metadata.json"
        
        # Load model
        with open(model_file, 'rb') as f:
            model = pickle.load(f)
        
        # Load metadata
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        
        return model, metadata
    
    def calculate_data_drift_statistics(self, reference_data: np.ndarray, 
                                      current_data: np.ndarray) -> Dict:
        """Calculate statistical measures for data drift detection"""
        drift_stats = {}
        
        try:
            # Ensure data is 2D
            if reference_data.ndim == 1:
                reference_data = reference_data.reshape(-1, 1)
            if current_data.ndim == 1:
                current_data = current_data.reshape(-1, 1)
            
            n_features = reference_data.shape[1]
            
            for i in range(n_features):
                ref_feature = reference_data[:, i]
                cur_feature = current_data[:, i]
                
                feature_stats = {}
                
                # Statistical tests
                from scipy import stats
                
                # Kolmogorov-Smirnov test
                ks_stat, ks_p_value = stats.ks_2samp(ref_feature, cur_feature)
                feature_stats['ks_statistic'] = ks_stat
                feature_stats['ks_p_value'] = ks_p_value
                feature_stats['ks_drift_detected'] = ks_p_value < 0.05
                
                # Mean and std comparison
                ref_mean, ref_std = np.mean(ref_feature), np.std(ref_feature)
                cur_mean, cur_std = np.mean(cur_feature), np.std(cur_feature)
                
                feature_stats['reference_mean'] = ref_mean
                feature_stats['current_mean'] = cur_mean
                feature_stats['mean_drift_pct'] = abs(cur_mean - ref_mean) / abs(ref_mean) * 100 if ref_mean != 0 else 0
                
                feature_stats['reference_std'] = ref_std
                feature_stats['current_std'] = cur_std
                feature_stats['std_drift_pct'] = abs(cur_std - ref_std) / abs(ref_std) * 100 if ref_std != 0 else 0
                
                drift_stats[f'feature_{i}'] = feature_stats
        
        except Exception as e:
            drift_stats['error'] = str(e)
        
        return drift_stats


# Global ML utilities instance
ml_utils = MLUtils()