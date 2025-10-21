# performance_bottleneck_analyzer.py - Performance bottleneck identification and analysis tool
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import cProfile
import pstats
import io
import sys
import os
import threading
import time
import psutil
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
from base_tool import AdvancedToolFrame
from utils.database import db_manager

TAB_NAME = "Performance Bottleneck Analyzer"

class ToolFrame(AdvancedToolFrame):
    """Performance bottleneck identification and analysis tool"""
    
    def __init__(self, master):
        tool_config = {
            'name': 'Performance Bottleneck Analyzer',
            'tool_id': 'performance_bottleneck_analyzer',
            'category': 'Performance'
        }
        super().__init__(master, tool_config)
        
        self.profiler = None
        self.profiling_active = False
        self.monitoring_thread = None
        self.system_metrics = []
        self.profile_results = None
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface"""
        self.add_label("⚡ Performance Bottleneck Analyzer", ("Consolas", 16, "bold"))
        self.add_label("Identify CPU and I/O bottlenecks with flame graphs and optimization suggestions")
        
        # Setup advanced UI components
        self.setup_advanced_ui()
        
        # Analysis mode selection
        mode_frame = tk.Frame(self, bg=self.master.cget('bg'))
        mode_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(mode_frame, text="Analysis Mode:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.analysis_mode = tk.StringVar(value="code_profiling")
        mode_combo = ttk.Combobox(mode_frame, textvariable=self.analysis_mode, 
                                 values=["code_profiling", "system_monitoring", "script_analysis"], 
                                 state="readonly", width=20)
        mode_combo.pack(side="left", padx=5)
        
        # Code profiling section
        self.create_code_profiling_section()
        
        # System monitoring section
        self.create_system_monitoring_section()
        
        # Script analysis section
        self.create_script_analysis_section()
        
        # Action buttons
        button_frame = tk.Frame(self, bg=self.master.cget('bg'))
        button_frame.pack(fill="x", padx=10, pady=10)
        
        self.start_btn = self.add_button("Start Analysis", self.start_analysis)
        self.stop_btn = self.add_button("Stop Analysis", self.stop_analysis)
        self.generate_report_btn = self.add_button("Generate Report", self.generate_performance_report)
        
        self.stop_btn.config(state="disabled")
        
        # Status label
        self.status_label = tk.Label(self, text="Status: Ready", 
                                   bg=self.master.cget('bg'), fg="white")
        self.status_label.pack(pady=5)
    
    def create_code_profiling_section(self):
        """Create code profiling controls"""
        profiling_frame = tk.LabelFrame(self, text="Code Profiling", 
                                       bg=self.master.cget('bg'), fg="white")
        profiling_frame.pack(fill="x", padx=10, pady=5)
        
        # Code input
        tk.Label(profiling_frame, text="Python Code to Profile:", 
                bg=self.master.cget('bg'), fg="white").pack(anchor="w")
        
        self.code_text = tk.Text(profiling_frame, height=8, width=70, 
                                bg="#111111", fg="white", insertbackground="white")
        self.code_text.pack(fill="x", padx=5, pady=5)
        
        # Default example code
        example_code = '''# Example: Performance test code
import time
import random

def slow_function():
    time.sleep(0.1)
    return sum(random.random() for _ in range(1000))

def fast_function():
    return sum(range(1000))

def main():
    results = []
    for i in range(10):
        if i % 2 == 0:
            results.append(slow_function())
        else:
            results.append(fast_function())
    return results

if __name__ == "__main__":
    main()
'''
        self.code_text.insert("1.0", example_code)
        
        # Profiling options
        options_frame = tk.Frame(profiling_frame, bg=self.master.cget('bg'))
        options_frame.pack(fill="x", padx=5, pady=5)
        
        self.sort_by_var = tk.StringVar(value="cumulative")
        tk.Label(options_frame, text="Sort by:", bg=self.master.cget('bg'), fg="white").pack(side="left")
        sort_combo = ttk.Combobox(options_frame, textvariable=self.sort_by_var,
                                 values=["cumulative", "time", "calls", "name"], 
                                 state="readonly", width=15)
        sort_combo.pack(side="left", padx=5)
        
        self.max_lines_var = tk.StringVar(value="20")
        tk.Label(options_frame, text="Max lines:", bg=self.master.cget('bg'), fg="white").pack(side="left", padx=(20, 0))
        lines_entry = tk.Entry(options_frame, textvariable=self.max_lines_var, width=10)
        lines_entry.pack(side="left", padx=5)
    
    def create_system_monitoring_section(self):
        """Create system monitoring controls"""
        monitoring_frame = tk.LabelFrame(self, text="System Monitoring", 
                                        bg=self.master.cget('bg'), fg="white")
        monitoring_frame.pack(fill="x", padx=10, pady=5)
        
        # Monitoring options
        options_frame = tk.Frame(monitoring_frame, bg=self.master.cget('bg'))
        options_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(options_frame, text="Duration (sec):", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        self.duration_var = tk.StringVar(value="60")
        duration_entry = tk.Entry(options_frame, textvariable=self.duration_var, width=10)
        duration_entry.pack(side="left", padx=5)
        
        tk.Label(options_frame, text="Interval (sec):", 
                bg=self.master.cget('bg'), fg="white").pack(side="left", padx=(20, 0))
        self.interval_var = tk.StringVar(value="1")
        interval_entry = tk.Entry(options_frame, textvariable=self.interval_var, width=10)
        interval_entry.pack(side="left", padx=5)
        
        # Metrics selection
        metrics_frame = tk.Frame(monitoring_frame, bg=self.master.cget('bg'))
        metrics_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(metrics_frame, text="Monitor:", bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.monitor_cpu = tk.BooleanVar(value=True)
        self.monitor_memory = tk.BooleanVar(value=True)
        self.monitor_disk = tk.BooleanVar(value=True)
        self.monitor_network = tk.BooleanVar(value=True)
        
        tk.Checkbutton(metrics_frame, text="CPU", variable=self.monitor_cpu, 
                      bg=self.master.cget('bg'), fg="white", selectcolor="#333333").pack(side="left", padx=5)
        tk.Checkbutton(metrics_frame, text="Memory", variable=self.monitor_memory, 
                      bg=self.master.cget('bg'), fg="white", selectcolor="#333333").pack(side="left", padx=5)
        tk.Checkbutton(metrics_frame, text="Disk I/O", variable=self.monitor_disk, 
                      bg=self.master.cget('bg'), fg="white", selectcolor="#333333").pack(side="left", padx=5)
        tk.Checkbutton(metrics_frame, text="Network", variable=self.monitor_network, 
                      bg=self.master.cget('bg'), fg="white", selectcolor="#333333").pack(side="left", padx=5)
    
    def create_script_analysis_section(self):
        """Create script analysis controls"""
        script_frame = tk.LabelFrame(self, text="Script Analysis", 
                                    bg=self.master.cget('bg'), fg="white")
        script_frame.pack(fill="x", padx=10, pady=5)
        
        # File selection
        file_frame = tk.Frame(script_frame, bg=self.master.cget('bg'))
        file_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(file_frame, text="Python Script:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.script_path_var = tk.StringVar()
        script_entry = tk.Entry(file_frame, textvariable=self.script_path_var, width=50)
        script_entry.pack(side="left", padx=5, fill="x", expand=True)
        
        browse_btn = tk.Button(file_frame, text="Browse", command=self.browse_script)
        browse_btn.pack(side="right", padx=5)
        
        # Script arguments
        args_frame = tk.Frame(script_frame, bg=self.master.cget('bg'))
        args_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(args_frame, text="Arguments:", 
                bg=self.master.cget('bg'), fg="white").pack(side="left")
        
        self.script_args_var = tk.StringVar()
        args_entry = tk.Entry(args_frame, textvariable=self.script_args_var, width=50)
        args_entry.pack(side="left", padx=5, fill="x", expand=True)
    
    def browse_script(self):
        """Browse for Python script file"""
        filename = filedialog.askopenfilename(
            title="Select Python Script",
            filetypes=[("Python files", "*.py"), ("All files", "*.*")]
        )
        if filename:
            self.script_path_var.set(filename)
    
    def start_analysis(self):
        """Start performance analysis based on selected mode"""
        mode = self.analysis_mode.get()
        
        try:
            if mode == "code_profiling":
                self.start_code_profiling()
            elif mode == "system_monitoring":
                self.start_system_monitoring()
            elif mode == "script_analysis":
                self.start_script_analysis()
            
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start analysis: {str(e)}")
    
    def stop_analysis(self):
        """Stop current analysis"""
        self.profiling_active = False
        
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=2)
        
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_label.config(text="Status: Analysis stopped")
        
        self.update_progress(100, "Analysis complete")
    
    def start_code_profiling(self):
        """Start profiling the provided code"""
        code = self.code_text.get("1.0", tk.END).strip()
        if not code:
            messagebox.showwarning("Warning", "Please enter code to profile")
            return
        
        self.update_progress(10, "Starting code profiling")
        self.status_label.config(text="Status: Profiling code")
        
        # Run profiling in separate thread
        self.profiling_active = True
        self.monitoring_thread = threading.Thread(target=self.profile_code, args=(code,), daemon=True)
        self.monitoring_thread.start()
    
    def profile_code(self, code: str):
        """Profile the provided code"""
        try:
            # Create profiler
            profiler = cProfile.Profile()
            
            # Prepare code execution environment
            exec_globals = {}
            exec_locals = {}
            
            self.update_progress(30, "Executing code with profiler")
            
            # Profile the code
            profiler.enable()
            exec(code, exec_globals, exec_locals)
            profiler.disable()
            
            self.update_progress(70, "Analyzing profile results")
            
            # Get profile statistics
            stats_stream = io.StringIO()
            stats = pstats.Stats(profiler, stream=stats_stream)
            
            sort_by = self.sort_by_var.get()
            max_lines = int(self.max_lines_var.get())
            
            stats.sort_stats(sort_by)
            stats.print_stats(max_lines)
            
            # Store results
            self.profile_results = {
                'stats_text': stats_stream.getvalue(),
                'stats_object': stats,
                'sort_by': sort_by,
                'max_lines': max_lines
            }
            
            self.update_progress(90, "Generating analysis")
            
            # Analyze results
            self.analyze_profile_results()
            
        except Exception as e:
            self.update_progress(0, f"Error: {str(e)}")
            print(f"Profiling error: {e}")
        finally:
            self.profiling_active = False
    
    def analyze_profile_results(self):
        """Analyze profiling results and identify bottlenecks"""
        if not self.profile_results:
            return
        
        try:
            stats = self.profile_results['stats_object']
            
            # Get function statistics
            function_stats = []
            for func, (cc, nc, tt, ct, callers) in stats.stats.items():
                filename, line_num, func_name = func
                function_stats.append({
                    'function': f"{filename}:{line_num}({func_name})",
                    'calls': nc,
                    'total_time': tt,
                    'cumulative_time': ct,
                    'per_call_time': tt / nc if nc > 0 else 0,
                    'per_call_cumulative': ct / nc if nc > 0 else 0
                })
            
            # Sort by cumulative time to find bottlenecks
            function_stats.sort(key=lambda x: x['cumulative_time'], reverse=True)
            
            # Identify bottlenecks
            bottlenecks = []
            total_time = sum(f['total_time'] for f in function_stats)
            
            for func_stat in function_stats[:10]:  # Top 10 functions
                time_percentage = (func_stat['cumulative_time'] / total_time * 100) if total_time > 0 else 0
                
                if time_percentage > 5:  # Functions taking more than 5% of total time
                    bottlenecks.append({
                        'function': func_stat['function'],
                        'time_percentage': time_percentage,
                        'cumulative_time': func_stat['cumulative_time'],
                        'calls': func_stat['calls'],
                        'per_call_time': func_stat['per_call_cumulative']
                    })
            
            # Generate recommendations
            recommendations = self.generate_code_recommendations(bottlenecks, function_stats)
            
            # Display results
            self.display_profiling_results(bottlenecks, recommendations, function_stats)
            
        except Exception as e:
            print(f"Analysis error: {e}")
    
    def generate_code_recommendations(self, bottlenecks: List[Dict], all_stats: List[Dict]) -> List[str]:
        """Generate optimization recommendations based on profiling results"""
        recommendations = []
        
        if not bottlenecks:
            recommendations.append("No significant bottlenecks detected. Code performance appears optimal.")
            return recommendations
        
        for bottleneck in bottlenecks:
            func_name = bottleneck['function']
            time_pct = bottleneck['time_percentage']
            calls = bottleneck['calls']
            per_call = bottleneck['per_call_time']
            
            if time_pct > 20:
                recommendations.append(f"CRITICAL: {func_name} consumes {time_pct:.1f}% of execution time - immediate optimization required")
            elif time_pct > 10:
                recommendations.append(f"HIGH: {func_name} consumes {time_pct:.1f}% of execution time - consider optimization")
            
            if calls > 1000:
                recommendations.append(f"Consider reducing call frequency for {func_name} ({calls:,} calls)")
            
            if per_call > 0.01:  # 10ms per call
                recommendations.append(f"Optimize individual call performance for {func_name} ({per_call*1000:.1f}ms per call)")
        
        # General recommendations
        if len(bottlenecks) > 5:
            recommendations.append("Multiple performance bottlenecks detected - consider algorithmic improvements")
        
        # Check for I/O operations
        io_functions = [f for f in all_stats if any(keyword in f['function'].lower() 
                       for keyword in ['read', 'write', 'open', 'close', 'request', 'sleep'])]
        if io_functions:
            recommendations.append("I/O operations detected - consider asynchronous processing or caching")
        
        return recommendations
    
    def display_profiling_results(self, bottlenecks: List[Dict], recommendations: List[str], all_stats: List[Dict]):
        """Display profiling analysis results"""
        # Summary tab
        summary_text = f"""Performance Profiling Results
{'='*50}

Total Functions Analyzed: {len(all_stats)}
Bottlenecks Identified: {len(bottlenecks)}

Top Performance Issues:
"""
        
        for i, bottleneck in enumerate(bottlenecks[:5], 1):
            summary_text += f"{i}. {bottleneck['function']}\n"
            summary_text += f"   Time: {bottleneck['time_percentage']:.1f}% ({bottleneck['cumulative_time']:.4f}s)\n"
            summary_text += f"   Calls: {bottleneck['calls']:,}\n\n"
        
        self.update_results_tab("Summary", summary_text)
        
        # Details tab - Full profiling output
        self.update_results_tab("Details", self.profile_results['stats_text'])
        
        # Analysis tab - Recommendations
        analysis_text = "Performance Optimization Recommendations:\n\n"
        for i, rec in enumerate(recommendations, 1):
            analysis_text += f"{i}. {rec}\n\n"
        
        self.update_results_tab("Analysis", analysis_text)
        
        # Raw data tab - Function statistics
        raw_data_text = "Function,Calls,Total Time,Cumulative Time,Per Call Time\n"
        for stat in all_stats[:50]:  # Top 50 functions
            raw_data_text += f"{stat['function']},{stat['calls']},{stat['total_time']:.6f},{stat['cumulative_time']:.6f},{stat['per_call_cumulative']:.6f}\n"
        
        self.update_results_tab("Raw Data", raw_data_text)
        
        # Create visualization
        self.create_profiling_visualization(bottlenecks)
    
    def create_profiling_visualization(self, bottlenecks: List[Dict]):
        """Create visualization for profiling results"""
        if not bottlenecks:
            return
        
        try:
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 6))
            
            # Time percentage pie chart
            functions = [b['function'].split('(')[-1].replace(')', '') for b in bottlenecks[:8]]
            percentages = [b['time_percentage'] for b in bottlenecks[:8]]
            
            ax1.pie(percentages, labels=functions, autopct='%1.1f%%', startangle=90)
            ax1.set_title('Time Distribution by Function')
            
            # Calls vs Time scatter plot
            calls = [b['calls'] for b in bottlenecks[:10]]
            times = [b['cumulative_time'] for b in bottlenecks[:10]]
            
            ax2.scatter(calls, times, alpha=0.7, s=100)
            ax2.set_xlabel('Number of Calls')
            ax2.set_ylabel('Cumulative Time (seconds)')
            ax2.set_title('Calls vs Execution Time')
            ax2.set_xscale('log')
            
            # Add function labels
            for i, (call, time, func) in enumerate(zip(calls, times, functions)):
                if i < 5:  # Label top 5 only
                    ax2.annotate(func[:15], (call, time), xytext=(5, 5), 
                               textcoords='offset points', fontsize=8)
            
            plt.tight_layout()
            
        except Exception as e:
            print(f"Visualization error: {e}")
    
    def start_system_monitoring(self):
        """Start system performance monitoring"""
        try:
            duration = float(self.duration_var.get())
            interval = float(self.interval_var.get())
            
            self.system_metrics = []
            self.profiling_active = True
            
            self.update_progress(10, "Starting system monitoring")
            self.status_label.config(text=f"Status: Monitoring system for {duration}s")
            
            # Start monitoring thread
            self.monitoring_thread = threading.Thread(
                target=self.monitor_system_performance, 
                args=(duration, interval), 
                daemon=True
            )
            self.monitoring_thread.start()
            
        except ValueError:
            messagebox.showerror("Error", "Invalid duration or interval value")
    
    def monitor_system_performance(self, duration: float, interval: float):
        """Monitor system performance metrics"""
        start_time = time.time()
        
        try:
            while self.profiling_active and (time.time() - start_time) < duration:
                timestamp = time.time()
                elapsed = timestamp - start_time
                
                metrics = {'timestamp': timestamp, 'elapsed': elapsed}
                
                # CPU metrics
                if self.monitor_cpu.get():
                    metrics['cpu_percent'] = psutil.cpu_percent(interval=0.1)
                    metrics['cpu_count'] = psutil.cpu_count()
                    cpu_times = psutil.cpu_times()
                    metrics['cpu_user'] = cpu_times.user
                    metrics['cpu_system'] = cpu_times.system
                
                # Memory metrics
                if self.monitor_memory.get():
                    memory = psutil.virtual_memory()
                    metrics['memory_percent'] = memory.percent
                    metrics['memory_available'] = memory.available / 1024 / 1024  # MB
                    metrics['memory_used'] = memory.used / 1024 / 1024  # MB
                
                # Disk I/O metrics
                if self.monitor_disk.get():
                    disk_io = psutil.disk_io_counters()
                    if disk_io:
                        metrics['disk_read_bytes'] = disk_io.read_bytes
                        metrics['disk_write_bytes'] = disk_io.write_bytes
                        metrics['disk_read_count'] = disk_io.read_count
                        metrics['disk_write_count'] = disk_io.write_count
                
                # Network metrics
                if self.monitor_network.get():
                    net_io = psutil.net_io_counters()
                    if net_io:
                        metrics['net_bytes_sent'] = net_io.bytes_sent
                        metrics['net_bytes_recv'] = net_io.bytes_recv
                        metrics['net_packets_sent'] = net_io.packets_sent
                        metrics['net_packets_recv'] = net_io.packets_recv
                
                self.system_metrics.append(metrics)
                
                # Update progress
                progress = min(90, (elapsed / duration) * 100)
                self.update_progress(progress, f"Monitoring... {elapsed:.1f}s")
                
                time.sleep(interval)
            
            # Analyze collected metrics
            if self.system_metrics:
                self.analyze_system_metrics()
            
        except Exception as e:
            print(f"Monitoring error: {e}")
        finally:
            self.profiling_active = False
    
    def analyze_system_metrics(self):
        """Analyze collected system metrics for bottlenecks"""
        if not self.system_metrics:
            return
        
        try:
            # Calculate statistics
            analysis = {
                'duration': self.system_metrics[-1]['elapsed'],
                'data_points': len(self.system_metrics),
                'bottlenecks': [],
                'recommendations': []
            }
            
            # Analyze CPU usage
            if 'cpu_percent' in self.system_metrics[0]:
                cpu_values = [m['cpu_percent'] for m in self.system_metrics]
                cpu_avg = np.mean(cpu_values)
                cpu_max = np.max(cpu_values)
                cpu_std = np.std(cpu_values)
                
                analysis['cpu_avg'] = cpu_avg
                analysis['cpu_max'] = cpu_max
                analysis['cpu_volatility'] = cpu_std
                
                if cpu_avg > 80:
                    analysis['bottlenecks'].append(f"High average CPU usage: {cpu_avg:.1f}%")
                    analysis['recommendations'].append("Consider CPU optimization or load balancing")
                
                if cpu_max > 95:
                    analysis['bottlenecks'].append(f"CPU spikes detected: {cpu_max:.1f}%")
                    analysis['recommendations'].append("Investigate CPU-intensive operations")
            
            # Analyze memory usage
            if 'memory_percent' in self.system_metrics[0]:
                memory_values = [m['memory_percent'] for m in self.system_metrics]
                memory_avg = np.mean(memory_values)
                memory_max = np.max(memory_values)
                
                analysis['memory_avg'] = memory_avg
                analysis['memory_max'] = memory_max
                
                if memory_avg > 85:
                    analysis['bottlenecks'].append(f"High memory usage: {memory_avg:.1f}%")
                    analysis['recommendations'].append("Consider memory optimization or adding RAM")
                
                if memory_max > 95:
                    analysis['bottlenecks'].append(f"Memory pressure detected: {memory_max:.1f}%")
                    analysis['recommendations'].append("Check for memory leaks or excessive allocation")
            
            # Analyze disk I/O
            if 'disk_read_bytes' in self.system_metrics[0]:
                read_rates = []
                write_rates = []
                
                for i in range(1, len(self.system_metrics)):
                    prev = self.system_metrics[i-1]
                    curr = self.system_metrics[i]
                    time_diff = curr['elapsed'] - prev['elapsed']
                    
                    if time_diff > 0:
                        read_rate = (curr['disk_read_bytes'] - prev['disk_read_bytes']) / time_diff / 1024 / 1024  # MB/s
                        write_rate = (curr['disk_write_bytes'] - prev['disk_write_bytes']) / time_diff / 1024 / 1024  # MB/s
                        
                        read_rates.append(read_rate)
                        write_rates.append(write_rate)
                
                if read_rates:
                    avg_read_rate = np.mean(read_rates)
                    max_read_rate = np.max(read_rates)
                    avg_write_rate = np.mean(write_rates)
                    max_write_rate = np.max(write_rates)
                    
                    analysis['disk_read_avg_mb_s'] = avg_read_rate
                    analysis['disk_read_max_mb_s'] = max_read_rate
                    analysis['disk_write_avg_mb_s'] = avg_write_rate
                    analysis['disk_write_max_mb_s'] = max_write_rate
                    
                    if max_read_rate > 100:  # 100 MB/s
                        analysis['bottlenecks'].append(f"High disk read activity: {max_read_rate:.1f} MB/s")
                        analysis['recommendations'].append("Consider SSD upgrade or I/O optimization")
                    
                    if max_write_rate > 100:
                        analysis['bottlenecks'].append(f"High disk write activity: {max_write_rate:.1f} MB/s")
                        analysis['recommendations'].append("Consider write caching or batch operations")
            
            # Display results
            self.display_system_analysis(analysis)
            
        except Exception as e:
            print(f"System analysis error: {e}")
    
    def display_system_analysis(self, analysis: Dict):
        """Display system performance analysis results"""
        # Summary tab
        summary_text = f"""System Performance Analysis
{'='*50}

Monitoring Duration: {analysis['duration']:.1f} seconds
Data Points Collected: {analysis['data_points']}

Performance Metrics:
"""
        
        if 'cpu_avg' in analysis:
            summary_text += f"CPU Usage - Avg: {analysis['cpu_avg']:.1f}%, Max: {analysis['cpu_max']:.1f}%\n"
        
        if 'memory_avg' in analysis:
            summary_text += f"Memory Usage - Avg: {analysis['memory_avg']:.1f}%, Max: {analysis['memory_max']:.1f}%\n"
        
        if 'disk_read_avg_mb_s' in analysis:
            summary_text += f"Disk Read - Avg: {analysis['disk_read_avg_mb_s']:.1f} MB/s, Max: {analysis['disk_read_max_mb_s']:.1f} MB/s\n"
            summary_text += f"Disk Write - Avg: {analysis['disk_write_avg_mb_s']:.1f} MB/s, Max: {analysis['disk_write_max_mb_s']:.1f} MB/s\n"
        
        summary_text += f"\nBottlenecks Detected: {len(analysis['bottlenecks'])}\n"
        for bottleneck in analysis['bottlenecks']:
            summary_text += f"• {bottleneck}\n"
        
        self.update_results_tab("Summary", summary_text)
        
        # Recommendations
        recommendations_text = "Performance Optimization Recommendations:\n\n"
        for i, rec in enumerate(analysis['recommendations'], 1):
            recommendations_text += f"{i}. {rec}\n\n"
        
        if not analysis['recommendations']:
            recommendations_text += "No significant performance issues detected. System performance appears optimal."
        
        self.update_results_tab("Analysis", recommendations_text)
        
        # Create system metrics visualization
        self.create_system_visualization()
    
    def create_system_visualization(self):
        """Create system performance visualization"""
        if not self.system_metrics:
            return
        
        try:
            fig, axes = plt.subplots(2, 2, figsize=(12, 10))
            axes = axes.flatten()
            
            timestamps = [m['elapsed'] / 60 for m in self.system_metrics]  # Convert to minutes
            
            # CPU usage plot
            if 'cpu_percent' in self.system_metrics[0]:
                cpu_values = [m['cpu_percent'] for m in self.system_metrics]
                axes[0].plot(timestamps, cpu_values, 'b-', linewidth=2)
                axes[0].set_title('CPU Usage Over Time')
                axes[0].set_ylabel('CPU Usage (%)')
                axes[0].grid(True, alpha=0.3)
            
            # Memory usage plot
            if 'memory_percent' in self.system_metrics[0]:
                memory_values = [m['memory_percent'] for m in self.system_metrics]
                axes[1].plot(timestamps, memory_values, 'r-', linewidth=2)
                axes[1].set_title('Memory Usage Over Time')
                axes[1].set_ylabel('Memory Usage (%)')
                axes[1].grid(True, alpha=0.3)
            
            # Disk I/O plot
            if 'disk_read_bytes' in self.system_metrics[0]:
                read_rates = []
                write_rates = []
                
                for i in range(1, len(self.system_metrics)):
                    prev = self.system_metrics[i-1]
                    curr = self.system_metrics[i]
                    time_diff = curr['elapsed'] - prev['elapsed']
                    
                    if time_diff > 0:
                        read_rate = (curr['disk_read_bytes'] - prev['disk_read_bytes']) / time_diff / 1024 / 1024
                        write_rate = (curr['disk_write_bytes'] - prev['disk_write_bytes']) / time_diff / 1024 / 1024
                        read_rates.append(read_rate)
                        write_rates.append(write_rate)
                
                if read_rates:
                    axes[2].plot(timestamps[1:], read_rates, 'g-', label='Read', linewidth=2)
                    axes[2].plot(timestamps[1:], write_rates, 'orange', label='Write', linewidth=2)
                    axes[2].set_title('Disk I/O Over Time')
                    axes[2].set_ylabel('I/O Rate (MB/s)')
                    axes[2].legend()
                    axes[2].grid(True, alpha=0.3)
            
            # Set common x-axis label
            for ax in axes:
                ax.set_xlabel('Time (minutes)')
            
            plt.tight_layout()
            
        except Exception as e:
            print(f"System visualization error: {e}")
    
    def start_script_analysis(self):
        """Start analysis of external Python script"""
        script_path = self.script_path_var.get().strip()
        if not script_path or not os.path.exists(script_path):
            messagebox.showwarning("Warning", "Please select a valid Python script")
            return
        
        self.update_progress(10, "Starting script analysis")
        self.status_label.config(text="Status: Analyzing script")
        
        # Run analysis in separate thread
        self.profiling_active = True
        self.monitoring_thread = threading.Thread(
            target=self.analyze_external_script, 
            args=(script_path,), 
            daemon=True
        )
        self.monitoring_thread.start()
    
    def analyze_external_script(self, script_path: str):
        """Analyze external Python script performance"""
        try:
            script_args = self.script_args_var.get().strip().split() if self.script_args_var.get().strip() else []
            
            # Build command
            cmd = [sys.executable, "-m", "cProfile", "-s", "cumulative", script_path] + script_args
            
            self.update_progress(30, "Running script with profiler")
            
            # Run script with profiler
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            self.update_progress(70, "Analyzing results")
            
            if result.returncode == 0:
                # Parse profiler output
                profile_output = result.stderr if result.stderr else result.stdout
                
                # Display results
                self.display_script_analysis(script_path, profile_output, result.stdout)
            else:
                error_msg = f"Script execution failed:\n{result.stderr}"
                self.update_results_tab("Summary", error_msg)
            
        except subprocess.TimeoutExpired:
            self.update_results_tab("Summary", "Script execution timed out (5 minutes)")
        except Exception as e:
            self.update_results_tab("Summary", f"Analysis error: {str(e)}")
        finally:
            self.profiling_active = False
    
    def display_script_analysis(self, script_path: str, profile_output: str, script_output: str):
        """Display external script analysis results"""
        # Summary tab
        summary_text = f"""Script Performance Analysis
{'='*50}

Script: {script_path}
Analysis Method: cProfile

{profile_output[:2000]}...
"""
        
        self.update_results_tab("Summary", summary_text)
        
        # Details tab - Full profiler output
        self.update_results_tab("Details", profile_output)
        
        # Script output
        if script_output:
            self.update_results_tab("Raw Data", f"Script Output:\n{script_output}")
    
    def generate_performance_report(self):
        """Generate comprehensive performance report"""
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'analysis_mode': self.analysis_mode.get(),
                'summary': {},
                'recommendations': [],
                'metrics': {}
            }
            
            # Add mode-specific data
            if self.analysis_mode.get() == "code_profiling" and self.profile_results:
                report['summary']['type'] = 'Code Profiling'
                report['summary']['functions_analyzed'] = len(self.profile_results['stats_object'].stats)
                
            elif self.analysis_mode.get() == "system_monitoring" and self.system_metrics:
                report['summary']['type'] = 'System Monitoring'
                report['summary']['duration'] = self.system_metrics[-1]['elapsed']
                report['summary']['data_points'] = len(self.system_metrics)
            
            # Save report
            analysis_id = f"performance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.save_analysis_result(
                analysis_id=analysis_id,
                input_data={'analysis_mode': self.analysis_mode.get()},
                results_summary=report['summary'],
                recommendations=report['recommendations'],
                metrics=report['metrics']
            )
            
            messagebox.showinfo("Report Generated", f"Performance report saved with ID: {analysis_id}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {str(e)}")


def create_performance_bottleneck_analyzer(parent):
    """Factory function to create the Performance Bottleneck Analyzer tool"""
    return PerformanceBottleneckAnalyzer(parent)