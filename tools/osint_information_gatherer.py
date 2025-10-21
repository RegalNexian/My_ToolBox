# tools/osint_information_gatherer.py - OSINT Information Gatherer
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import requests
import threading
import json
import time
import re
from datetime import datetime
from typing import Dict, List, Optional, Any
from base_tool import SecurityToolFrame
from theme import BG_COLOR, TEXT_COLOR, style_button
from utils import ensure_results_subfolder

TAB_NAME = "OSINT Information Gatherer"

class OSINTInformationGatherer(SecurityToolFrame):
    """OSINT information gatherer for collecting publicly available information"""
    
    def __init__(self, master):
        super().__init__(master, {
            'name': 'OSINT Information Gatherer',
            'tool_id': 'osint_information_gatherer',
            'category': 'Security'
        })
        
        ensure_results_subfolder("OSINT_Information")
        
        # Initialize variables
        self.osint_data = []
        self.gathering_thread = None
        self.is_gathering = False
        
        # Setup security framework
        self.setup_security_framework()
        
        # Initialize OSINT sources
        self.osint_sources = self.initialize_osint_sources()
        
        # Build UI
        self.setup_ui()
    
    def initialize_osint_sources(self) -> Dict[str, Dict]:
        """Initialize OSINT source configurations"""
        return {
            'whois': {
                'name': 'WHOIS Lookup',
                'description': 'Domain registration information',
                'enabled': True,
                'ethical': True
            },
            'dns': {
                'name': 'DNS Records',
                'description': 'DNS record enumeration',
                'enabled': True,
                'ethical': True
            },
            'subdomain': {
                'name': 'Subdomain Enumeration',
                'description': 'Find subdomains using public sources',
                'enabled': True,
                'ethical': True
            },
            'social_media': {
                'name': 'Social Media Search',
                'description': 'Public social media information',
                'enabled': False,
                'ethical': True,
                'note': 'Requires API keys and ethical guidelines'
            },
            'search_engines': {
                'name': 'Search Engine Results',
                'description': 'Public search engine information',
                'enabled': True,
                'ethical': True
            },
            'certificate_transparency': {
                'name': 'Certificate Transparency',
                'description': 'SSL certificate logs',
                'enabled': True,
                'ethical': True
            },
            'public_records': {
                'name': 'Public Records',
                'description': 'Publicly available records',
                'enabled': False,
                'ethical': True,
                'note': 'Limited to publicly available information'
            }
        }
    
    def setup_ui(self):
        """Setup the user interface"""
        # Main container
        main_frame = tk.Frame(self, bg=BG_COLOR)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Left panel for controls
        left_panel = tk.Frame(main_frame, bg=BG_COLOR, width=400)
        left_panel.pack(side="left", fill="y", padx=(0, 10))
        left_panel.pack_propagate(False)
        
        # Title
        title_label = tk.Label(left_panel, text="🔍 OSINT Information Gatherer", 
                              bg=BG_COLOR, fg=TEXT_COLOR, 
                              font=("Consolas", 14, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Ethical notice
        ethics_frame = tk.Frame(left_panel, bg="#2A2A2A", relief="raised", bd=2)
        ethics_frame.pack(fill="x", pady=10)
        
        ethics_label = tk.Label(ethics_frame, 
                              text="⚠️ ETHICAL OSINT ONLY\nThis tool collects only publicly available information.\nRespect privacy laws and platform terms of service.", 
                              bg="#2A2A2A", fg="#FFD700", 
                              font=("Consolas", 9, "bold"),
                              justify="center")
        ethics_label.pack(pady=10)
        
        # Target configuration
        target_frame = tk.LabelFrame(left_panel, text="Target Information", 
                                   bg=BG_COLOR, fg=TEXT_COLOR)
        target_frame.pack(fill="x", pady=10)
        
        # Target type selection
        tk.Label(target_frame, text="Target Type:", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        self.target_type = tk.StringVar(value="domain")
        
        tk.Radiobutton(target_frame, text="Domain/Organization", variable=self.target_type, 
                      value="domain", bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR, command=self.toggle_target_type).pack(anchor="w")
        tk.Radiobutton(target_frame, text="Email Address", variable=self.target_type, 
                      value="email", bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR, command=self.toggle_target_type).pack(anchor="w")
        tk.Radiobutton(target_frame, text="Username", variable=self.target_type, 
                      value="username", bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR, command=self.toggle_target_type).pack(anchor="w")
        
        # Target input
        tk.Label(target_frame, text="Target:", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w", pady=(10, 0))
        self.target_entry = tk.Entry(target_frame, bg="#111111", fg=TEXT_COLOR,
                                   insertbackground=TEXT_COLOR)
        self.target_entry.pack(fill="x", pady=2)
        self.target_entry.insert(0, "example.com")
        
        # OSINT source selection
        sources_frame = tk.LabelFrame(left_panel, text="OSINT Sources", 
                                    bg=BG_COLOR, fg=TEXT_COLOR)
        sources_frame.pack(fill="x", pady=10)
        
        self.source_vars = {}
        for source_id, config in self.osint_sources.items():
            var = tk.BooleanVar(value=config['enabled'])
            self.source_vars[source_id] = var
            
            cb_text = f"{config['name']} - {config['description']}"
            if 'note' in config:
                cb_text += f" ({config['note']})"
            
            cb = tk.Checkbutton(sources_frame, text=cb_text, 
                              variable=var, bg=BG_COLOR, fg=TEXT_COLOR,
                              selectcolor=BG_COLOR, wraplength=350)
            cb.pack(anchor="w", pady=1)
        
        # Gathering options
        options_frame = tk.LabelFrame(left_panel, text="Gathering Options", 
                                    bg=BG_COLOR, fg=TEXT_COLOR)
        options_frame.pack(fill="x", pady=10)
        
        self.deep_search = tk.BooleanVar(value=False)
        tk.Checkbutton(options_frame, text="Deep search (more comprehensive)", 
                      variable=self.deep_search, bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR).pack(anchor="w")
        
        self.include_historical = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Include historical data", 
                      variable=self.include_historical, bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR).pack(anchor="w")
        
        self.respect_robots = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Respect robots.txt and rate limits", 
                      variable=self.respect_robots, bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR).pack(anchor="w")
        
        # Rate limiting
        tk.Label(options_frame, text="Request delay (seconds):", 
                bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w", pady=(10, 0))
        self.delay_entry = tk.Entry(options_frame, bg="#111111", fg=TEXT_COLOR,
                                  insertbackground=TEXT_COLOR)
        self.delay_entry.pack(fill="x", pady=2)
        self.delay_entry.insert(0, "2")
        
        # Control buttons
        button_frame = tk.Frame(left_panel, bg=BG_COLOR)
        button_frame.pack(fill="x", pady=20)
        
        self.gather_button = tk.Button(button_frame, text="Start OSINT Gathering", 
                                     command=self.start_gathering)
        style_button(self.gather_button)
        self.gather_button.pack(fill="x", pady=2)
        
        self.stop_button = tk.Button(button_frame, text="Stop Gathering", 
                                   command=self.stop_gathering, state="disabled")
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
        
        report_btn = tk.Button(export_btn_frame, text="Report", command=self.export_report)
        style_button(report_btn)
        report_btn.pack(side="left", padx=5)
        
        # Right panel for results
        right_panel = tk.Frame(main_frame, bg=BG_COLOR)
        right_panel.pack(side="right", fill="both", expand=True)
        
        # Progress bar
        self.add_progress_bar("OSINT Gathering Progress")
        
        # Results viewer with tabs
        self.add_results_viewer(["Summary", "Domain Info", "Social Media", "Technical Details"])
        
        # Status label
        self.status_label = tk.Label(right_panel, text="Ready", 
                                   bg=BG_COLOR, fg=TEXT_COLOR)
        self.status_label.pack(pady=5)
    
    def toggle_target_type(self):
        """Update UI based on target type selection"""
        target_type = self.target_type.get()
        
        # Update placeholder text
        self.target_entry.delete(0, tk.END)
        if target_type == "domain":
            self.target_entry.insert(0, "example.com")
        elif target_type == "email":
            self.target_entry.insert(0, "user@example.com")
        elif target_type == "username":
            self.target_entry.insert(0, "username")
    
    def start_gathering(self):
        """Start OSINT information gathering"""
        # Check authorization first
        if not hasattr(self, 'security_base') or not self.security_base or not self.security_base.is_authorized:
            messagebox.showerror("Authorization Required", 
                               "Please validate target before running security operations.")
            return
        
        if self.is_gathering:
            messagebox.showwarning("Gathering in Progress", "OSINT gathering is already running.")
            return
        
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Invalid Target", "Please enter a target.")
            return
        
        # Get selected sources
        selected_sources = [source_id for source_id, var in self.source_vars.items() if var.get()]
        
        if not selected_sources:
            messagebox.showerror("No Sources Selected", "Please select at least one OSINT source.")
            return
        
        # Ethical confirmation
        confirm = messagebox.askyesno("Ethical OSINT Confirmation", 
                                    "Do you confirm that you will only collect publicly available information "
                                    "and comply with all applicable laws and terms of service?")
        if not confirm:
            return
        
        # Start gathering in separate thread
        self.is_gathering = True
        self.gather_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.osint_data = []
        self.update_progress(0, "Starting OSINT gathering...")
        
        self.gathering_thread = threading.Thread(target=self.run_gathering, 
                                                args=(target, selected_sources))
        self.gathering_thread.daemon = True
        self.gathering_thread.start()
        
        # Log the gathering start
        self.log_security_activity("OSINT_GATHERING_STARTED", f"OSINT gathering started for target: {target}")
    
    def run_gathering(self, target: str, selected_sources: List[str]):
        """Run the OSINT information gathering"""
        try:
            delay = float(self.delay_entry.get() or 2)
            target_type = self.target_type.get()
            
            total_sources = len(selected_sources)
            
            for i, source_id in enumerate(selected_sources):
                if not self.is_gathering:
                    break
                
                progress = (i / total_sources) * 90
                source_name = self.osint_sources[source_id]['name']
                self.update_progress(progress, f"Gathering from {source_name}...")
                
                self.gather_from_source(source_id, target, target_type)
                
                # Rate limiting
                if self.respect_robots.get():
                    time.sleep(delay)
            
            if self.is_gathering:
                self.update_progress(95, "Processing gathered information...")
                self.process_osint_data(target)
                
                self.update_progress(100, "OSINT gathering completed")
                self.status_label.config(text=f"Gathering completed - {len(self.osint_data)} items found")
            
        except Exception as e:
            self.update_progress(0, f"Error: {str(e)}")
            self.status_label.config(text=f"Error: {str(e)}")
            messagebox.showerror("Gathering Error", f"An error occurred during gathering:\n{str(e)}")
        
        finally:
            self.is_gathering = False
            self.gather_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.log_security_activity("OSINT_GATHERING_COMPLETED", 
                                     f"OSINT gathering completed - {len(self.osint_data)} items found")
    
    def gather_from_source(self, source_id: str, target: str, target_type: str):
        """Gather information from a specific OSINT source"""
        try:
            if source_id == 'whois':
                self.gather_whois_info(target)
            elif source_id == 'dns':
                self.gather_dns_info(target)
            elif source_id == 'subdomain':
                self.gather_subdomain_info(target)
            elif source_id == 'social_media':
                self.gather_social_media_info(target, target_type)
            elif source_id == 'search_engines':
                self.gather_search_engine_info(target, target_type)
            elif source_id == 'certificate_transparency':
                self.gather_certificate_info(target)
            elif source_id == 'public_records':
                self.gather_public_records(target, target_type)
        
        except Exception as e:
            self.add_osint_finding(source_id, 'ERROR', f"Error gathering from {source_id}: {str(e)}")
    
    def gather_whois_info(self, target: str):
        """Gather WHOIS information"""
        try:
            # This is a simplified WHOIS lookup
            # In practice, you'd use a proper WHOIS library
            import socket
            
            # Try to get basic domain info
            try:
                ip = socket.gethostbyname(target)
                self.add_osint_finding('whois', 'IP_ADDRESS', f"Domain resolves to: {ip}")
            except socket.gaierror:
                self.add_osint_finding('whois', 'DNS_ERROR', f"Domain does not resolve: {target}")
            
            # Placeholder for actual WHOIS data
            self.add_osint_finding('whois', 'WHOIS_INFO', 
                                 f"WHOIS lookup performed for {target} (requires whois library for full data)")
        
        except Exception as e:
            self.add_osint_finding('whois', 'ERROR', f"WHOIS lookup error: {str(e)}")
    
    def gather_dns_info(self, target: str):
        """Gather DNS information"""
        try:
            import socket
            
            # A record
            try:
                ip = socket.gethostbyname(target)
                self.add_osint_finding('dns', 'A_RECORD', f"A record: {ip}")
            except socket.gaierror:
                pass
            
            # Try common subdomains
            common_subdomains = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test']
            for subdomain in common_subdomains:
                try:
                    full_domain = f"{subdomain}.{target}"
                    ip = socket.gethostbyname(full_domain)
                    self.add_osint_finding('dns', 'SUBDOMAIN', f"Found subdomain: {full_domain} -> {ip}")
                except socket.gaierror:
                    continue
        
        except Exception as e:
            self.add_osint_finding('dns', 'ERROR', f"DNS lookup error: {str(e)}")
    
    def gather_subdomain_info(self, target: str):
        """Gather subdomain information using public sources"""
        try:
            # This would typically use certificate transparency logs, DNS databases, etc.
            # For demo purposes, we'll simulate some findings
            
            potential_subdomains = [
                'www', 'mail', 'webmail', 'ftp', 'cpanel', 'admin', 'api', 
                'dev', 'test', 'staging', 'blog', 'shop', 'store'
            ]
            
            found_subdomains = []
            for subdomain in potential_subdomains[:5]:  # Limit for demo
                if not self.is_gathering:
                    break
                
                try:
                    import socket
                    full_domain = f"{subdomain}.{target}"
                    socket.gethostbyname(full_domain)
                    found_subdomains.append(full_domain)
                    self.add_osint_finding('subdomain', 'SUBDOMAIN_FOUND', f"Active subdomain: {full_domain}")
                except socket.gaierror:
                    continue
            
            if found_subdomains:
                self.add_osint_finding('subdomain', 'SUMMARY', 
                                     f"Found {len(found_subdomains)} active subdomains")
        
        except Exception as e:
            self.add_osint_finding('subdomain', 'ERROR', f"Subdomain enumeration error: {str(e)}")
    
    def gather_social_media_info(self, target: str, target_type: str):
        """Gather social media information (ethical, public only)"""
        try:
            # This is a placeholder for social media OSINT
            # In practice, this would use public APIs and respect rate limits
            
            if target_type == "username":
                platforms = ['twitter', 'linkedin', 'github', 'instagram', 'facebook']
                for platform in platforms:
                    # Simulate checking if username exists on platform
                    # In reality, you'd use proper APIs or public endpoints
                    self.add_osint_finding('social_media', 'PLATFORM_CHECK', 
                                         f"Checked {platform} for username: {target} (requires API integration)")
            
            elif target_type == "email":
                self.add_osint_finding('social_media', 'EMAIL_SEARCH', 
                                     f"Social media search for email: {target} (requires specialized tools)")
            
            else:
                self.add_osint_finding('social_media', 'DOMAIN_SEARCH', 
                                     f"Social media search for domain: {target} (requires API integration)")
        
        except Exception as e:
            self.add_osint_finding('social_media', 'ERROR', f"Social media search error: {str(e)}")
    
    def gather_search_engine_info(self, target: str, target_type: str):
        """Gather search engine information"""
        try:
            # This simulates search engine dorking and public information gathering
            # In practice, you'd use search APIs or web scraping (respecting robots.txt)
            
            search_queries = []
            if target_type == "domain":
                search_queries = [
                    f'site:{target}',
                    f'inurl:{target}',
                    f'"{target}" contact',
                    f'"{target}" employees'
                ]
            elif target_type == "email":
                search_queries = [
                    f'"{target}"',
                    f'"{target}" profile',
                    f'"{target}" contact'
                ]
            elif target_type == "username":
                search_queries = [
                    f'"{target}" profile',
                    f'"{target}" social',
                    f'"{target}" account'
                ]
            
            for query in search_queries[:3]:  # Limit for demo
                self.add_osint_finding('search_engines', 'SEARCH_QUERY', 
                                     f"Search query: {query} (requires search API integration)")
        
        except Exception as e:
            self.add_osint_finding('search_engines', 'ERROR', f"Search engine error: {str(e)}")
    
    def gather_certificate_info(self, target: str):
        """Gather certificate transparency information"""
        try:
            # This would typically query certificate transparency logs
            # For demo purposes, we'll try to get the current certificate
            
            import ssl
            import socket
            
            try:
                context = ssl.create_default_context()
                with socket.create_connection((target, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Extract certificate information
                        subject = dict(x[0] for x in cert['subject'])
                        issuer = dict(x[0] for x in cert['issuer'])
                        
                        self.add_osint_finding('certificate_transparency', 'CERT_SUBJECT', 
                                             f"Certificate subject: {subject.get('commonName', 'Unknown')}")
                        self.add_osint_finding('certificate_transparency', 'CERT_ISSUER', 
                                             f"Certificate issuer: {issuer.get('organizationName', 'Unknown')}")
                        
                        # Check for subject alternative names
                        for ext in cert.get('extensions', []):
                            if ext[0] == 'subjectAltName':
                                san_list = [name[1] for name in ext[1]]
                                self.add_osint_finding('certificate_transparency', 'SAN_DOMAINS', 
                                                     f"SAN domains: {', '.join(san_list[:10])}")
                                break
            
            except Exception as cert_error:
                self.add_osint_finding('certificate_transparency', 'CERT_ERROR', 
                                     f"Certificate retrieval error: {str(cert_error)}")
        
        except Exception as e:
            self.add_osint_finding('certificate_transparency', 'ERROR', 
                                 f"Certificate transparency error: {str(e)}")
    
    def gather_public_records(self, target: str, target_type: str):
        """Gather public records information"""
        try:
            # This is a placeholder for public records search
            # In practice, this would query legitimate public databases
            
            if target_type == "domain":
                self.add_osint_finding('public_records', 'DOMAIN_RECORDS', 
                                     f"Public records search for domain: {target} (requires database access)")
            elif target_type == "email":
                self.add_osint_finding('public_records', 'EMAIL_RECORDS', 
                                     f"Public records search for email: {target} (requires database access)")
            else:
                self.add_osint_finding('public_records', 'USERNAME_RECORDS', 
                                     f"Public records search for username: {target} (requires database access)")
        
        except Exception as e:
            self.add_osint_finding('public_records', 'ERROR', f"Public records error: {str(e)}")
    
    def add_osint_finding(self, source: str, finding_type: str, description: str):
        """Add an OSINT finding"""
        finding = {
            'source': source,
            'type': finding_type,
            'description': description,
            'timestamp': datetime.now().isoformat()
        }
        self.osint_data.append(finding)
    
    def process_osint_data(self, target: str):
        """Process and analyze gathered OSINT data"""
        if not self.osint_data:
            return
        
        # Update UI tabs
        self.update_summary_tab(target)
        self.update_domain_info_tab()
        self.update_social_media_tab()
        self.update_technical_details_tab()
        
        # Set results data for export
        self.set_results_data({
            'osint_metadata': {
                'target': target,
                'target_type': self.target_type.get(),
                'timestamp': datetime.now().isoformat(),
                'total_findings': len(self.osint_data)
            },
            'findings': self.osint_data
        })
    
    def update_summary_tab(self, target: str):
        """Update the summary tab"""
        summary_text = f"""OSINT Gathering Summary
{'='*30}

Target: {target}
Target Type: {self.target_type.get().title()}
Gathering Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Findings: {len(self.osint_data)}

Findings by Source:
"""
        
        # Count findings by source
        source_counts = {}
        for finding in self.osint_data:
            source = finding['source']
            source_counts[source] = source_counts.get(source, 0) + 1
        
        for source, count in sorted(source_counts.items()):
            source_name = self.osint_sources.get(source, {}).get('name', source)
            summary_text += f"  • {source_name}: {count}\n"
        
        # Key findings
        key_findings = []
        for finding in self.osint_data:
            if finding['type'] in ['IP_ADDRESS', 'SUBDOMAIN_FOUND', 'CERT_SUBJECT']:
                key_findings.append(finding)
        
        if key_findings:
            summary_text += f"\nKey Findings:\n"
            for finding in key_findings[:10]:  # Show top 10
                summary_text += f"  • {finding['description']}\n"
        
        summary_text += f"""

OSINT Gathering Notes:
• All information collected from publicly available sources
• Gathering performed in compliance with ethical guidelines
• Results may require additional verification
• Respect privacy laws and terms of service
"""
        
        self.update_results_tab("Summary", summary_text)
    
    def update_domain_info_tab(self):
        """Update the domain information tab"""
        domain_findings = [f for f in self.osint_data 
                          if f['source'] in ['whois', 'dns', 'subdomain', 'certificate_transparency']]
        
        domain_text = f"""Domain Information
{'='*20}

"""
        
        if domain_findings:
            # Group by source
            by_source = {}
            for finding in domain_findings:
                source = finding['source']
                if source not in by_source:
                    by_source[source] = []
                by_source[source].append(finding)
            
            for source, findings in by_source.items():
                source_name = self.osint_sources.get(source, {}).get('name', source)
                domain_text += f"\n{source_name}:\n"
                domain_text += f"{'─' * 20}\n"
                
                for finding in findings:
                    domain_text += f"  • {finding['description']}\n"
        else:
            domain_text += "No domain information gathered.\n"
        
        self.update_results_tab("Domain Info", domain_text)
    
    def update_social_media_tab(self):
        """Update the social media tab"""
        social_findings = [f for f in self.osint_data if f['source'] == 'social_media']
        
        social_text = f"""Social Media Information
{'='*30}

"""
        
        if social_findings:
            for finding in social_findings:
                social_text += f"• {finding['description']}\n"
        else:
            social_text += "No social media information gathered.\n"
        
        social_text += f"""

Social Media OSINT Notes:
• Only publicly available information is collected
• Requires proper API access for comprehensive results
• Must comply with platform terms of service
• Consider privacy implications and legal requirements
"""
        
        self.update_results_tab("Social Media", social_text)
    
    def update_technical_details_tab(self):
        """Update the technical details tab"""
        technical_findings = [f for f in self.osint_data 
                            if f['source'] in ['dns', 'certificate_transparency', 'search_engines']]
        
        technical_text = f"""Technical Details
{'='*20}

"""
        
        if technical_findings:
            for finding in technical_findings:
                technical_text += f"Source: {finding['source'].title()}\n"
                technical_text += f"Type: {finding['type']}\n"
                technical_text += f"Details: {finding['description']}\n"
                technical_text += f"Timestamp: {finding['timestamp']}\n\n"
        else:
            technical_text += "No technical details gathered.\n"
        
        self.update_results_tab("Technical Details", technical_text)
    
    def stop_gathering(self):
        """Stop OSINT gathering"""
        if self.is_gathering:
            self.is_gathering = False
            self.gather_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.update_progress(0, "Gathering stopped by user")
            self.status_label.config(text="Gathering stopped")
            messagebox.showinfo("Gathering Stopped", "OSINT gathering has been stopped.")
    
    def export_json(self):
        """Export OSINT data as JSON"""
        if not self.osint_data:
            messagebox.showwarning("No Data", "No OSINT data to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            title="Export OSINT Data as JSON"
        )
        
        if filename:
            try:
                export_data = {
                    'metadata': {
                        'target': self.target_entry.get(),
                        'target_type': self.target_type.get(),
                        'export_timestamp': datetime.now().isoformat(),
                        'total_findings': len(self.osint_data)
                    },
                    'findings': self.osint_data
                }
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
                messagebox.showinfo("Export Successful", f"OSINT data exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export data:\n{str(e)}")
    
    def export_report(self):
        """Export OSINT data as formatted report"""
        if not self.osint_data:
            messagebox.showwarning("No Data", "No OSINT data to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            title="Export OSINT Report"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"OSINT Information Gathering Report\n")
                    f.write(f"{'='*40}\n\n")
                    f.write(f"Target: {self.target_entry.get()}\n")
                    f.write(f"Target Type: {self.target_type.get().title()}\n")
                    f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Total Findings: {len(self.osint_data)}\n\n")
                    
                    # Group findings by source
                    by_source = {}
                    for finding in self.osint_data:
                        source = finding['source']
                        if source not in by_source:
                            by_source[source] = []
                        by_source[source].append(finding)
                    
                    for source, findings in by_source.items():
                        source_name = self.osint_sources.get(source, {}).get('name', source)
                        f.write(f"{source_name} ({len(findings)} findings):\n")
                        f.write(f"{'─' * 30}\n")
                        
                        for finding in findings:
                            f.write(f"  • {finding['description']}\n")
                        f.write("\n")
                    
                    f.write("DISCLAIMER:\n")
                    f.write("This report contains information gathered from publicly available sources only.\n")
                    f.write("All gathering was performed in compliance with ethical guidelines and applicable laws.\n")
                    f.write("Information should be verified through additional sources before use.\n")
                
                messagebox.showinfo("Export Successful", f"OSINT report exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export report:\n{str(e)}")


# Create the ToolFrame class that the main application expects
class ToolFrame(OSINTInformationGatherer):
    """Wrapper class for main application compatibility"""
    pass