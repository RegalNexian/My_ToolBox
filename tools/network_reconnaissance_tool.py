# tools/network_reconnaissance_tool.py - Network Reconnaissance Tool
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import threading
import json
import time
import socket
import ipaddress
import re
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from base_tool import SecurityToolFrame
from theme import BG_COLOR, TEXT_COLOR, style_button
from utils import ensure_results_subfolder, get_save_path

TAB_NAME = "Network Reconnaissance Tool"

class NetworkReconTool(SecurityToolFrame):
    """Network reconnaissance tool with ethical validation and nmap integration"""
    
    def __init__(self, master):
        super().__init__(master, {
            'name': 'Network Reconnaissance Tool',
            'tool_id': 'network_reconnaissance_tool',
            'category': 'Security'
        })
        
        ensure_results_subfolder("Network_Reconnaissance")
        
        # Initialize variables
        self.scan_results = {}
        self.scan_thread = None
        self.is_scanning = False
        

        
        # Build UI
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface"""
        # Main container with scrollable frame
        main_frame = tk.Frame(self, bg=BG_COLOR)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Left panel for controls
        left_panel = tk.Frame(main_frame, bg=BG_COLOR, width=400)
        left_panel.pack(side="left", fill="y", padx=(0, 10))
        left_panel.pack_propagate(False)
        
        # Title
        title_label = tk.Label(left_panel, text="🔍 Network Reconnaissance", 
                              bg=BG_COLOR, fg=TEXT_COLOR, 
                              font=("Consolas", 14, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Ethical notice section
        ethical_frame = tk.LabelFrame(left_panel, text="Ethical Use Notice", 
                                    bg=BG_COLOR, fg=TEXT_COLOR)
        ethical_frame.pack(fill="x", pady=10)
        
        ethical_text = tk.Label(ethical_frame, 
                              text="⚠️ Use responsibly and only on systems you own or have explicit permission to test.",
                              bg=BG_COLOR, fg="#FFD700", wraplength=350, justify="left")
        ethical_text.pack(pady=5)
        
        # Target input section
        target_frame = tk.LabelFrame(left_panel, text="Target Configuration", 
                                   bg=BG_COLOR, fg=TEXT_COLOR)
        target_frame.pack(fill="x", pady=10)
        
        tk.Label(target_frame, text="Target (IP/Network/Hostname):", 
                bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        self.target_entry = tk.Entry(target_frame, bg="#111111", fg=TEXT_COLOR,
                                   insertbackground=TEXT_COLOR)
        self.target_entry.pack(fill="x", pady=2)
        
        # Scan configuration
        config_frame = tk.LabelFrame(left_panel, text="Scan Configuration", 
                                   bg=BG_COLOR, fg=TEXT_COLOR)
        config_frame.pack(fill="x", pady=10)
        
        # Scan type selection
        tk.Label(config_frame, text="Scan Type:", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        self.scan_type = tk.StringVar(value="stealth")
        scan_types = [
            ("Stealth SYN Scan (-sS)", "stealth"),
            ("TCP Connect Scan (-sT)", "connect"), 
            ("UDP Scan (-sU)", "udp"),
            ("Ping Sweep (-sn)", "ping"),
            ("Service Detection (-sV)", "service"),
            ("OS Detection (-O)", "os")
        ]
        
        for text, value in scan_types:
            rb = tk.Radiobutton(config_frame, text=text, variable=self.scan_type, 
                              value=value, bg=BG_COLOR, fg=TEXT_COLOR,
                              selectcolor=BG_COLOR)
            rb.pack(anchor="w")
        
        # Port specification
        tk.Label(config_frame, text="Ports:", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w", pady=(10,0))
        self.ports_entry = tk.Entry(config_frame, bg="#111111", fg=TEXT_COLOR, 
                                  insertbackground=TEXT_COLOR)
        self.ports_entry.pack(fill="x", pady=2)
        self.ports_entry.insert(0, "1-1000")
        
        # Timing template
        tk.Label(config_frame, text="Timing:", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w", pady=(10,0))
        self.timing = tk.StringVar(value="T3")
        timing_frame = tk.Frame(config_frame, bg=BG_COLOR)
        timing_frame.pack(fill="x")
        
        timings = [("Paranoid (T0)", "T0"), ("Sneaky (T1)", "T1"), 
                  ("Polite (T2)", "T2"), ("Normal (T3)", "T3"),
                  ("Aggressive (T4)", "T4"), ("Insane (T5)", "T5")]
        
        for i, (text, value) in enumerate(timings):
            rb = tk.Radiobutton(timing_frame, text=text, variable=self.timing,
                              value=value, bg=BG_COLOR, fg=TEXT_COLOR,
                              selectcolor=BG_COLOR)
            if i < 3:
                rb.pack(side="left")
            else:
                if i == 3:
                    timing_frame2 = tk.Frame(config_frame, bg=BG_COLOR)
                    timing_frame2.pack(fill="x")
                rb.pack(side="left")
                rb.master = timing_frame2
        
        # Advanced options
        advanced_frame = tk.LabelFrame(left_panel, text="Advanced Options", 
                                     bg=BG_COLOR, fg=TEXT_COLOR)
        advanced_frame.pack(fill="x", pady=10)
        
        self.fragment_packets = tk.BooleanVar()
        tk.Checkbutton(advanced_frame, text="Fragment packets (-f)", 
                      variable=self.fragment_packets, bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR).pack(anchor="w")
        
        self.decoy_scan = tk.BooleanVar()
        tk.Checkbutton(advanced_frame, text="Use decoy addresses (-D)", 
                      variable=self.decoy_scan, bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR).pack(anchor="w")
        
        self.randomize_hosts = tk.BooleanVar()
        tk.Checkbutton(advanced_frame, text="Randomize host order (--randomize-hosts)", 
                      variable=self.randomize_hosts, bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR).pack(anchor="w")
        
        # Rate limiting
        tk.Label(advanced_frame, text="Max rate (packets/sec):", 
                bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w", pady=(10,0))
        self.max_rate_entry = tk.Entry(advanced_frame, bg="#111111", fg=TEXT_COLOR,
                                     insertbackground=TEXT_COLOR)
        self.max_rate_entry.pack(fill="x", pady=2)
        self.max_rate_entry.insert(0, "100")
        
        # Control buttons
        button_frame = tk.Frame(left_panel, bg=BG_COLOR)
        button_frame.pack(fill="x", pady=20)
        
        self.scan_button = tk.Button(button_frame, text="Start Reconnaissance", 
                                   command=self.start_scan)
        style_button(self.scan_button)
        self.scan_button.pack(fill="x", pady=2)
        
        self.stop_button = tk.Button(button_frame, text="Stop Scan", 
                                   command=self.stop_scan, state="disabled")
        style_button(self.stop_button)
        self.stop_button.pack(fill="x", pady=2)
        
        # Export buttons
        export_frame = tk.Frame(left_panel, bg=BG_COLOR)
        export_frame.pack(fill="x", pady=10)
        
        tk.Label(export_frame, text="Export Results:", bg=BG_COLOR, fg=TEXT_COLOR,
                font=("Consolas", 10, "bold")).pack(anchor="w")
        
        export_btn_frame = tk.Frame(export_frame, bg=BG_COLOR)
        export_btn_frame.pack(fill="x", pady=5)
        
        json_btn = tk.Button(export_btn_frame, text="JSON", command=self.export_json)
        style_button(json_btn)
        json_btn.pack(side="left", padx=(0, 5))
        
        xml_btn = tk.Button(export_btn_frame, text="XML", command=self.export_xml)
        style_button(xml_btn)
        xml_btn.pack(side="left", padx=5)
        
        txt_btn = tk.Button(export_btn_frame, text="TXT", command=self.export_txt)
        style_button(txt_btn)
        txt_btn.pack(side="left", padx=5)
        
        # Right panel for results
        right_panel = tk.Frame(main_frame, bg=BG_COLOR)
        right_panel.pack(side="right", fill="both", expand=True)
        
        # Progress bar
        self.add_progress_bar("Reconnaissance Progress")
        
        # Results viewer with tabs
        self.add_results_viewer(["Summary", "Detailed Results", "Network Map", "Raw Output"])
        
        # Status label
        self.status_label = tk.Label(right_panel, text="Ready", 
                                   bg=BG_COLOR, fg=TEXT_COLOR)
        self.status_label.pack(pady=5)
    
    def check_nmap_availability(self) -> bool:
        """Check if nmap is available on the system"""
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def build_nmap_command(self, target: str) -> List[str]:
        """Build nmap command based on selected options"""
        cmd = ['nmap']
        
        # Add scan type
        scan_type = self.scan_type.get()
        if scan_type == "stealth":
            cmd.append('-sS')
        elif scan_type == "connect":
            cmd.append('-sT')
        elif scan_type == "udp":
            cmd.append('-sU')
        elif scan_type == "ping":
            cmd.append('-sn')
        elif scan_type == "service":
            cmd.extend(['-sV', '-sC'])
        elif scan_type == "os":
            cmd.append('-O')
        
        # Add timing
        cmd.append(f'-{self.timing.get()}')
        
        # Add ports if not ping sweep
        if scan_type != "ping":
            ports = self.ports_entry.get().strip()
            if ports:
                cmd.extend(['-p', ports])
        
        # Add advanced options
        if self.fragment_packets.get():
            cmd.append('-f')
        
        if self.decoy_scan.get():
            cmd.extend(['-D', 'RND:10'])
        
        if self.randomize_hosts.get():
            cmd.append('--randomize-hosts')
        
        # Add rate limiting
        max_rate = self.max_rate_entry.get().strip()
        if max_rate and max_rate.isdigit():
            cmd.extend(['--max-rate', max_rate])
        
        # Output format
        cmd.extend(['-oX', '-'])  # XML output to stdout
        
        # Add target
        cmd.append(target)
        
        return cmd
    
    def start_scan(self):
        """Start the network reconnaissance scan"""
        if self.is_scanning:
            messagebox.showwarning("Scan in Progress", "A scan is already running.")
            return
        
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Invalid Target", "Please enter a target.")
            return
        
        # Check nmap availability
        if not self.check_nmap_availability():
            messagebox.showerror("Nmap Not Found", 
                               "Nmap is not installed or not in PATH. Please install nmap to use this tool.")
            return
        
        # Validate target format
        try:
            # Try to parse as network
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            # Try as hostname
            try:
                socket.gethostbyname(target)
            except socket.gaierror:
                messagebox.showerror("Invalid Target", 
                                   "Target must be a valid IP address, network, or hostname.")
                return
        
        # Start scan in separate thread
        self.is_scanning = True
        self.scan_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.update_progress(0, "Starting scan...")
        
        self.scan_thread = threading.Thread(target=self.run_scan, args=(target,))
        self.scan_thread.daemon = True
        self.scan_thread.start()
        

    
    def run_scan(self, target: str):
        """Run the actual nmap scan"""
        try:
            # Build command
            cmd = self.build_nmap_command(target)
            
            self.update_progress(10, "Building scan command...")
            

            
            self.update_progress(20, "Executing nmap scan...")
            
            # Execute nmap
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, text=True)
            
            stdout, stderr = process.communicate()
            
            if process.returncode == 0:
                self.update_progress(80, "Processing results...")
                self.process_scan_results(stdout, target)
                self.update_progress(100, "Scan completed successfully")
                self.status_label.config(text="Scan completed successfully")
            else:
                error_msg = stderr or "Unknown error occurred"
                self.update_progress(0, f"Scan failed: {error_msg}")
                self.status_label.config(text=f"Scan failed: {error_msg}")
                messagebox.showerror("Scan Failed", f"Nmap scan failed:\n{error_msg}")
            
        except Exception as e:
            self.update_progress(0, f"Error: {str(e)}")
            self.status_label.config(text=f"Error: {str(e)}")
            messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{str(e)}")
        
        finally:
            self.is_scanning = False
            self.scan_button.config(state="normal")
            self.stop_button.config(state="disabled")

    
    def process_scan_results(self, xml_output: str, target: str):
        """Process nmap XML output and update results"""
        try:
            # Parse XML output (simplified parsing)
            hosts_found = []
            open_ports = {}
            services = {}
            
            # Extract basic information using regex (simplified approach)
            # In a production tool, you'd use proper XML parsing
            
            # Find hosts
            host_pattern = r'<host.*?<address addr="([^"]+)"'
            hosts = re.findall(host_pattern, xml_output, re.DOTALL)
            
            # Find open ports
            port_pattern = r'<port protocol="([^"]+)" portid="([^"]+)">.*?<state state="open"'
            ports = re.findall(port_pattern, xml_output, re.DOTALL)
            
            # Find services
            service_pattern = r'<service name="([^"]*)".*?product="([^"]*)".*?version="([^"]*)"'
            service_info = re.findall(service_pattern, xml_output, re.DOTALL)
            
            # Store results
            self.scan_results = {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'hosts_found': hosts,
                'open_ports': ports,
                'services': service_info,
                'raw_output': xml_output
            }
            
            # Update UI tabs
            self.update_summary_tab()
            self.update_detailed_tab()
            self.update_network_map_tab()
            self.update_raw_output_tab()
            
            # Set results data for export
            self.set_results_data(self.scan_results)
            
        except Exception as e:
            messagebox.showerror("Processing Error", 
                               f"Error processing scan results:\n{str(e)}")
    
    def update_summary_tab(self):
        """Update the summary tab with scan overview"""
        if not self.scan_results:
            return
        
        summary = f"""Network Reconnaissance Summary
Target: {self.scan_results['target']}
Scan Time: {self.scan_results['timestamp']}
Hosts Found: {len(self.scan_results['hosts_found'])}
Open Ports: {len(self.scan_results['open_ports'])}
Services Detected: {len(self.scan_results['services'])}

Discovered Hosts:
"""
        for host in self.scan_results['hosts_found']:
            summary += f"  • {host}\n"
        
        summary += "\nOpen Ports Summary:\n"
        port_summary = {}
        for protocol, port in self.scan_results['open_ports']:
            key = f"{port}/{protocol}"
            port_summary[key] = port_summary.get(key, 0) + 1
        
        for port, count in sorted(port_summary.items()):
            summary += f"  • {port} ({count} host{'s' if count > 1 else ''})\n"
        
        self.update_results_tab("Summary", summary)
    
    def update_detailed_tab(self):
        """Update the detailed results tab"""
        if not self.scan_results:
            return
        
        detailed = f"""Detailed Reconnaissance Results
{'='*50}

Target: {self.scan_results['target']}
Scan Timestamp: {self.scan_results['timestamp']}

Host Discovery:
"""
        for i, host in enumerate(self.scan_results['hosts_found'], 1):
            detailed += f"{i}. {host}\n"
        
        detailed += f"\nPort Scan Results:\n"
        for protocol, port in self.scan_results['open_ports']:
            detailed += f"  {port}/{protocol} - OPEN\n"
        
        detailed += f"\nService Detection:\n"
        for name, product, version in self.scan_results['services']:
            detailed += f"  Service: {name}\n"
            if product:
                detailed += f"    Product: {product}\n"
            if version:
                detailed += f"    Version: {version}\n"
            detailed += "\n"
        
        self.update_results_tab("Detailed Results", detailed)
    
    def update_network_map_tab(self):
        """Update the network map tab with topology information"""
        if not self.scan_results:
            return
        
        network_map = f"""Network Topology Map
{'='*30}

Target Network: {self.scan_results['target']}

Network Layout:
"""
        
        # Group hosts by subnet if multiple hosts found
        hosts = self.scan_results['hosts_found']
        if len(hosts) > 1:
            try:
                # Try to determine network structure
                subnets = {}
                for host in hosts:
                    try:
                        ip = ipaddress.ip_address(host)
                        network = ipaddress.ip_network(f"{ip}/24", strict=False)
                        subnet_key = str(network.network_address)
                        if subnet_key not in subnets:
                            subnets[subnet_key] = []
                        subnets[subnet_key].append(host)
                    except ValueError:
                        # Handle hostnames
                        if 'other' not in subnets:
                            subnets['other'] = []
                        subnets['other'].append(host)
                
                for subnet, subnet_hosts in subnets.items():
                    network_map += f"\nSubnet {subnet}:\n"
                    for host in subnet_hosts:
                        network_map += f"  └─ {host}\n"
                        
                        # Add port information for this host
                        host_ports = [f"{port}/{protocol}" for protocol, port in self.scan_results['open_ports']]
                        if host_ports:
                            network_map += f"     Ports: {', '.join(host_ports[:5])}"
                            if len(host_ports) > 5:
                                network_map += f" (+{len(host_ports)-5} more)"
                            network_map += "\n"
                        
            except Exception:
                # Fallback to simple list
                for host in hosts:
                    network_map += f"  • {host}\n"
        else:
            network_map += f"Single host target: {hosts[0] if hosts else 'No hosts found'}\n"
        
        self.update_results_tab("Network Map", network_map)
    
    def update_raw_output_tab(self):
        """Update the raw output tab with nmap XML"""
        if not self.scan_results:
            return
        
        raw_output = f"""Raw Nmap XML Output
{'='*25}

{self.scan_results['raw_output']}
"""
        self.update_results_tab("Raw Output", raw_output)
    
    def stop_scan(self):
        """Stop the current scan"""
        if self.scan_thread and self.scan_thread.is_alive():
            # Note: This is a simplified stop - in production you'd need proper process management
            self.is_scanning = False
            self.scan_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.update_progress(0, "Scan stopped by user")
            self.status_label.config(text="Scan stopped")
            messagebox.showinfo("Scan Stopped", "Scan has been stopped.")
    
    def export_json(self):
        """Export results as JSON"""
        if not self.scan_results:
            messagebox.showwarning("No Results", "No scan results to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            title="Export Reconnaissance Results as JSON"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.scan_results, f, indent=2)
                messagebox.showinfo("Export Successful", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export results:\n{str(e)}")
    
    def export_xml(self):
        """Export raw XML results"""
        if not self.scan_results or 'raw_output' not in self.scan_results:
            messagebox.showwarning("No Results", "No raw XML output to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".xml",
            filetypes=[("XML files", "*.xml")],
            title="Export Raw Nmap XML"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.scan_results['raw_output'])
                messagebox.showinfo("Export Successful", f"XML exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export XML:\n{str(e)}")
    
    def export_txt(self):
        """Export results as formatted text"""
        if not self.scan_results:
            messagebox.showwarning("No Results", "No scan results to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            title="Export Reconnaissance Results as Text"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(f"Network Reconnaissance Report\n")
                    f.write(f"{'='*40}\n\n")
                    f.write(f"Target: {self.scan_results['target']}\n")
                    f.write(f"Scan Time: {self.scan_results['timestamp']}\n\n")
                    
                    f.write(f"Hosts Found ({len(self.scan_results['hosts_found'])}):\n")
                    for host in self.scan_results['hosts_found']:
                        f.write(f"  • {host}\n")
                    
                    f.write(f"\nOpen Ports ({len(self.scan_results['open_ports'])}):\n")
                    for protocol, port in self.scan_results['open_ports']:
                        f.write(f"  • {port}/{protocol}\n")
                    
                    f.write(f"\nServices Detected ({len(self.scan_results['services'])}):\n")
                    for name, product, version in self.scan_results['services']:
                        f.write(f"  • {name}")
                        if product:
                            f.write(f" - {product}")
                        if version:
                            f.write(f" ({version})")
                        f.write("\n")
                
                messagebox.showinfo("Export Successful", f"Report exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export report:\n{str(e)}")


# Create the ToolFrame class that the main application expects
class ToolFrame(NetworkReconTool):
    """Wrapper class for main application compatibility"""
    pass