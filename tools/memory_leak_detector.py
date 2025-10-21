# memory_leak_detector.py - Memory leak detection and analysis tool
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import psutil
import gc
import tracemalloc
import threading
import time
import os
import sys
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
from base_tool import AdvancedToolFrame
from utils.database import db_manager

TAB_NAME = "Memory Leak Detector"

class ToolFrame(AdvancedToolFrame):
    """Memory leak detection and analysis tool"""
    
    def __init__(self, master):
        tool_config = {
            'name': 'Memory Leak Detector',
            'tool_id': 'memory_leak_detector',
            'category': 'Performance'
        }
        super().__init__(master, tool_config)
        
        self.monitoring_active = False
        self.monitoring_thread = None
        self.memory_data = []
        self.process_data = {}
        self.leak_threshold = 10.0  # MB increase threshold
        self.monitoring_interval = 5  # seconds
        self.target_process = None
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface"""
        self.add_label("🔍 Memory Leak Detector", ("Consolas", 16, "bold"))
        self.add_label("Monitor memory allocation patterns and detect potential leaks")
        
        # Setup advanced UI components
        self.setup_advanced_ui()
        
        # Configuration frame
        config_frame = tk.Frame(self, bg=self.master.cget('bg'))
        config_frame.pack(fill="x", padx=10, pady=5)
        
        # Process selection
        process_frame = tk.Frame(config_frame, bg=self.master.cget('bg'))
        process_frame.pack(fill="x", pady=5)
        
        tk.Label(process_frame, text="Target Process:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.process_var = tk.StringVar()
        self.process_combo = ttk.Combobox(process_frame, textvariable=self.process_var, 
                                         width=40, state="readonly")
        self.process_combo.pack(side="left", padx=5)
        
        refresh_btn = self.add_button("Refresh Processes", self.refresh_processes)
        
        # Monitoring controls
        controls_frame = tk.Frame(config_frame, bg=self.master.cget('bg'))
        controls_frame.pack(fill="x", pady=5)
        
        tk.Label(controls_frame, text="Interval (sec):", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.interval_var = tk.StringVar(value=str(self.monitoring_interval))
        interval_entry = tk.Entry(controls_frame, textvariable=self.interval_var, width=10)
        interval_entry.pack(side="left", padx=5)
        
        tk.Label(controls_frame, text="Threshold (MB):", 
                bg=self.master.cget('bg'), fg="white").pack(side="left", padx=(20, 0))
        
        self.threshold_var = tk.StringVar(value=str(self.leak_threshold))
        threshold_entry = tk.Entry(controls_frame, textvariable=self.threshold_var, width=10)
        threshold_entry.pack(side="left", padx=5)
        
        # Action buttons
        button_frame = tk.Frame(self, bg=self.master.cget('bg'))
        button_frame.pack(fill="x", padx=10, pady=10)
        
        self.start_btn = self.add_button("Start Monitoring", self.start_monitoring)
        self.stop_btn = self.add_button("Stop Monitoring", self.stop_monitoring)
        self.analyze_btn = self.add_button("Analyze Current Process", self.analyze_current_process)
        self.python_trace_btn = self.add_button("Python Memory Trace", self.start_python_trace)
        
        self.stop_btn.config(state="disabled")
        
        # Status label
        self.status_label = tk.Label(self, text="Status: Ready", 
                                   bg=self.master.cget('bg'), fg="white")
        self.status_label.pack(pady=5)
        
        # Initialize process list
        self.refresh_processes()
        
    def refresh_processes(self):
        """Refresh the list of running processes"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                try:
                    proc_info = proc.info
                    memory_mb = proc_info['memory_info'].rss / 1024 / 1024
                    processes.append(f"{proc_info['pid']} - {proc_info['name']} ({memory_mb:.1f} MB)")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Sort by memory usage (descending)
            processes.sort(key=lambda x: float(x.split('(')[1].split(' MB')[0]), reverse=True)
            
            self.process_combo['values'] = processes
            if processes:
                self.process_combo.current(0)
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh processes: {str(e)}")
    
    def start_monitoring(self):
        """Start memory monitoring"""
        try:
            # Validate inputs
            self.monitoring_interval = float(self.interval_var.get())
            self.leak_threshold = float(self.threshold_var.get())
            
            if not self.process_var.get():
                messagebox.showwarning("Warning", "Please select a process to monitor")
                return
            
            # Extract PID from selection
            pid_str = self.process_var.get().split(' - ')[0]
            pid = int(pid_str)
            
            # Verify process exists
            try:
                self.target_process = psutil.Process(pid)
                self.target_process.memory_info()  # Test access
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                messagebox.showerror("Error", f"Cannot access process {pid}: {str(e)}")
                return
            
            # Clear previous data
            self.memory_data = []
            self.process_data = {}
            
            # Start monitoring thread
            self.monitoring_active = True
            self.monitoring_thread = threading.Thread(target=self.monitor_memory, daemon=True)
            self.monitoring_thread.start()
            
            # Update UI
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.status_label.config(text=f"Status: Monitoring PID {pid}")
            
            self.update_progress(10, "Monitoring started")
            
        except ValueError as e:
            messagebox.showerror("Error", "Invalid interval or threshold value")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start monitoring: {str(e)}")
    
    def stop_monitoring(self):
        """Stop memory monitoring"""
        self.monitoring_active = False
        
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=2)
        
        # Update UI
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_label.config(text="Status: Monitoring stopped")
        
        # Analyze collected data
        if self.memory_data:
            self.analyze_memory_data()
        
        self.update_progress(100, "Monitoring complete")
    
    def monitor_memory(self):
        """Memory monitoring loop (runs in separate thread)"""
        start_time = time.time()
        
        while self.monitoring_active:
            try:
                if not self.target_process or not self.target_process.is_running():
                    break
                
                # Collect memory information
                memory_info = self.target_process.memory_info()
                memory_percent = self.target_process.memory_percent()
                
                # Get additional process info
                try:
                    cpu_percent = self.target_process.cpu_percent()
                    num_threads = self.target_process.num_threads()
                    open_files = len(self.target_process.open_files())
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    cpu_percent = 0
                    num_threads = 0
                    open_files = 0
                
                timestamp = time.time()
                
                data_point = {
                    'timestamp': timestamp,
                    'elapsed_time': timestamp - start_time,
                    'rss': memory_info.rss / 1024 / 1024,  # MB
                    'vms': memory_info.vms / 1024 / 1024,  # MB
                    'memory_percent': memory_percent,
                    'cpu_percent': cpu_percent,
                    'num_threads': num_threads,
                    'open_files': open_files
                }
                
                self.memory_data.append(data_point)
                
                # Update progress periodically
                if len(self.memory_data) % 10 == 0:
                    progress = min(90, len(self.memory_data) * 2)
                    self.update_progress(progress, f"Collected {len(self.memory_data)} data points")
                
                time.sleep(self.monitoring_interval)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            except Exception as e:
                print(f"Monitoring error: {e}")
                break
    
    def analyze_memory_data(self):
        """Analyze collected memory data for leaks"""
        if not self.memory_data:
            messagebox.showwarning("Warning", "No memory data to analyze")
            return
        
        try:
            analysis_results = self.detect_memory_leaks()
            self.display_analysis_results(analysis_results)
            
            # Save results
            analysis_id = f"memory_leak_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.save_analysis_result(
                analysis_id=analysis_id,
                input_data={
                    'process_pid': self.target_process.pid if self.target_process else 'unknown',
                    'monitoring_duration': len(self.memory_data) * self.monitoring_interval,
                    'data_points': len(self.memory_data)
                },
                results_summary=analysis_results['summary'],
                detailed_findings=analysis_results['detailed_findings'],
                recommendations=analysis_results['recommendations'],
                metrics=analysis_results['metrics']
            )
            
            # Set results for export
            self.set_results_data(analysis_results)
            
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")
    
    def detect_memory_leaks(self) -> Dict:
        """Detect memory leaks in the collected data"""
        if len(self.memory_data) < 3:
            return {
                'summary': {'leak_detected': False, 'reason': 'Insufficient data'},
                'detailed_findings': [],
                'recommendations': [],
                'metrics': {}
            }
        
        # Extract memory usage over time
        timestamps = [d['elapsed_time'] for d in self.memory_data]
        rss_values = [d['rss'] for d in self.memory_data]
        vms_values = [d['vms'] for d in self.memory_data]
        
        # Calculate trends
        rss_trend = np.polyfit(timestamps, rss_values, 1)[0]  # slope
        vms_trend = np.polyfit(timestamps, vms_values, 1)[0]
        
        # Calculate statistics
        initial_rss = rss_values[0]
        final_rss = rss_values[-1]
        max_rss = max(rss_values)
        min_rss = min(rss_values)
        
        rss_increase = final_rss - initial_rss
        rss_volatility = np.std(rss_values)
        
        # Leak detection logic
        leak_detected = False
        leak_severity = "none"
        leak_reasons = []
        
        # Check for consistent upward trend
        if rss_trend > 0.1:  # MB per second
            leak_detected = True
            leak_reasons.append(f"Consistent memory growth: {rss_trend:.2f} MB/sec")
        
        # Check for significant total increase
        if rss_increase > self.leak_threshold:
            leak_detected = True
            leak_reasons.append(f"Total memory increase: {rss_increase:.2f} MB")
        
        # Check for high volatility (possible fragmentation)
        if rss_volatility > initial_rss * 0.1:
            leak_reasons.append(f"High memory volatility: {rss_volatility:.2f} MB")
        
        # Determine severity
        if leak_detected:
            if rss_increase > self.leak_threshold * 3 or rss_trend > 1.0:
                leak_severity = "critical"
            elif rss_increase > self.leak_threshold * 2 or rss_trend > 0.5:
                leak_severity = "high"
            else:
                leak_severity = "moderate"
        
        # Generate recommendations
        recommendations = []
        if leak_detected:
            recommendations.extend([
                "Review memory allocation patterns in the application",
                "Check for unclosed resources (files, connections, etc.)",
                "Use memory profiling tools for detailed analysis",
                "Consider implementing garbage collection optimization"
            ])
            
            if rss_trend > 0.5:
                recommendations.append("Immediate investigation required - rapid memory growth detected")
            
            if rss_volatility > initial_rss * 0.2:
                recommendations.append("Check for memory fragmentation issues")
        else:
            recommendations.append("No significant memory leaks detected")
        
        # Detailed findings
        detailed_findings = [
            f"Monitoring duration: {timestamps[-1]:.1f} seconds",
            f"Initial RSS memory: {initial_rss:.2f} MB",
            f"Final RSS memory: {final_rss:.2f} MB",
            f"Maximum RSS memory: {max_rss:.2f} MB",
            f"Memory growth rate: {rss_trend:.4f} MB/sec",
            f"Memory volatility: {rss_volatility:.2f} MB",
            f"Total memory increase: {rss_increase:.2f} MB"
        ]
        
        if leak_detected:
            detailed_findings.extend(leak_reasons)
        
        return {
            'summary': {
                'leak_detected': leak_detected,
                'severity': leak_severity,
                'total_increase_mb': rss_increase,
                'growth_rate_mb_per_sec': rss_trend,
                'monitoring_duration_sec': timestamps[-1]
            },
            'detailed_findings': detailed_findings,
            'recommendations': recommendations,
            'metrics': {
                'initial_rss_mb': initial_rss,
                'final_rss_mb': final_rss,
                'max_rss_mb': max_rss,
                'min_rss_mb': min_rss,
                'rss_trend_mb_per_sec': rss_trend,
                'vms_trend_mb_per_sec': vms_trend,
                'rss_volatility_mb': rss_volatility,
                'data_points': len(self.memory_data)
            }
        }
    
    def display_analysis_results(self, results: Dict):
        """Display analysis results in the UI"""
        # Update summary tab
        summary = results['summary']
        summary_text = f"""Memory Leak Analysis Results
{'='*50}

Leak Detected: {'YES' if summary['leak_detected'] else 'NO'}
Severity: {summary.get('severity', 'N/A').upper()}
Total Memory Increase: {summary.get('total_increase_mb', 0):.2f} MB
Growth Rate: {summary.get('growth_rate_mb_per_sec', 0):.4f} MB/sec
Monitoring Duration: {summary.get('monitoring_duration_sec', 0):.1f} seconds
"""
        
        self.update_results_tab("Summary", summary_text)
        
        # Update details tab
        details_text = "Detailed Findings:\n" + "\n".join([f"• {finding}" for finding in results['detailed_findings']])
        self.update_results_tab("Details", details_text)
        
        # Update analysis tab with recommendations
        recommendations_text = "Recommendations:\n" + "\n".join([f"• {rec}" for rec in results['recommendations']])
        self.update_results_tab("Analysis", recommendations_text)
        
        # Create and display visualization
        self.create_memory_visualization()
    
    def create_memory_visualization(self):
        """Create memory usage visualization"""
        if not self.memory_data:
            return
        
        try:
            fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))
            
            timestamps = [d['elapsed_time'] / 60 for d in self.memory_data]  # Convert to minutes
            rss_values = [d['rss'] for d in self.memory_data]
            vms_values = [d['vms'] for d in self.memory_data]
            cpu_values = [d['cpu_percent'] for d in self.memory_data]
            
            # Memory usage plot
            ax1.plot(timestamps, rss_values, 'b-', label='RSS Memory', linewidth=2)
            ax1.plot(timestamps, vms_values, 'r--', label='Virtual Memory', alpha=0.7)
            ax1.set_xlabel('Time (minutes)')
            ax1.set_ylabel('Memory Usage (MB)')
            ax1.set_title('Memory Usage Over Time')
            ax1.legend()
            ax1.grid(True, alpha=0.3)
            
            # Add trend line for RSS
            if len(timestamps) > 1:
                z = np.polyfit(timestamps, rss_values, 1)
                p = np.poly1d(z)
                ax1.plot(timestamps, p(timestamps), "g--", alpha=0.8, label=f'Trend (slope: {z[0]:.2f} MB/min)')
                ax1.legend()
            
            # CPU usage plot
            ax2.plot(timestamps, cpu_values, 'orange', label='CPU Usage (%)', linewidth=2)
            ax2.set_xlabel('Time (minutes)')
            ax2.set_ylabel('CPU Usage (%)')
            ax2.set_title('CPU Usage Over Time')
            ax2.legend()
            ax2.grid(True, alpha=0.3)
            
            plt.tight_layout()
            
            # Convert to text representation for raw data tab
            raw_data_text = "Timestamp (min), RSS (MB), VMS (MB), CPU (%)\n"
            for i, data in enumerate(self.memory_data):
                raw_data_text += f"{data['elapsed_time']/60:.2f}, {data['rss']:.2f}, {data['vms']:.2f}, {data['cpu_percent']:.1f}\n"
            
            self.update_results_tab("Raw Data", raw_data_text)
            
        except Exception as e:
            print(f"Visualization error: {e}")
    
    def analyze_current_process(self):
        """Analyze the current Python process"""
        try:
            current_process = psutil.Process()
            
            # Get memory info
            memory_info = current_process.memory_info()
            memory_percent = current_process.memory_percent()
            
            # Get object counts
            gc.collect()  # Force garbage collection
            object_counts = {}
            for obj in gc.get_objects():
                obj_type = type(obj).__name__
                object_counts[obj_type] = object_counts.get(obj_type, 0) + 1
            
            # Sort by count
            sorted_objects = sorted(object_counts.items(), key=lambda x: x[1], reverse=True)
            
            # Create analysis
            analysis_text = f"""Current Process Memory Analysis
{'='*50}

Process ID: {current_process.pid}
RSS Memory: {memory_info.rss / 1024 / 1024:.2f} MB
Virtual Memory: {memory_info.vms / 1024 / 1024:.2f} MB
Memory Percentage: {memory_percent:.2f}%

Top Python Objects:
"""
            
            for obj_type, count in sorted_objects[:20]:
                analysis_text += f"{obj_type}: {count:,}\n"
            
            # Display in results
            self.update_results_tab("Summary", analysis_text)
            
            # Get garbage collection stats
            gc_stats = gc.get_stats()
            gc_text = f"Garbage Collection Statistics:\n"
            for i, stats in enumerate(gc_stats):
                gc_text += f"Generation {i}: {stats}\n"
            
            self.update_results_tab("Details", gc_text)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to analyze current process: {str(e)}")
    
    def start_python_trace(self):
        """Start Python memory tracing using tracemalloc"""
        try:
            if not tracemalloc.is_tracing():
                tracemalloc.start()
                messagebox.showinfo("Tracing Started", 
                                  "Python memory tracing started. Run your code and then click 'Analyze Current Process' to see detailed memory allocation.")
            else:
                # Get current trace
                snapshot = tracemalloc.take_snapshot()
                top_stats = snapshot.statistics('lineno')
                
                trace_text = "Top Memory Allocations:\n"
                trace_text += "=" * 50 + "\n"
                
                for index, stat in enumerate(top_stats[:20], 1):
                    trace_text += f"{index}. {stat.traceback.format()[-1]}\n"
                    trace_text += f"   Size: {stat.size / 1024:.1f} KB, Count: {stat.count}\n\n"
                
                self.update_results_tab("Analysis", trace_text)
                
        except Exception as e:
            messagebox.showerror("Error", f"Memory tracing failed: {str(e)}")


def create_memory_leak_detector(parent):
    """Factory function to create the Memory Leak Detector tool"""
    return MemoryLeakDetector(parent)