# tools/threat_intelligence_aggregator.py - Threat Intelligence Aggregator
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import requests
import threading
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from base_tool import SecurityToolFrame
from theme import BG_COLOR, TEXT_COLOR, style_button
from utils import ensure_results_subfolder

TAB_NAME = "Threat Intelligence Aggregator"

class ThreatIntelligenceAggregator(SecurityToolFrame):
    """Threat intelligence aggregator for collecting and analyzing security threats"""
    
    def __init__(self, master):
        super().__init__(master, {
            'name': 'Threat Intelligence Aggregator',
            'tool_id': 'threat_intelligence_aggregator',
            'category': 'Security'
        })
        
        ensure_results_subfolder("Threat_Intelligence")
        
        # Initialize variables
        self.threat_data = []
        self.collection_thread = None
        self.is_collecting = False
        

        
        # Initialize threat feeds
        self.threat_feeds = self.initialize_threat_feeds()
        
        # Build UI
        self.setup_ui()
    
    def initialize_threat_feeds(self) -> Dict[str, Dict]:
        """Initialize threat intelligence feed configurations"""
        return {
            'abuse_ch': {
                'name': 'Abuse.ch',
                'url': 'https://urlhaus-api.abuse.ch/v1/urls/recent/',
                'type': 'malware_urls',
                'enabled': True,
                'description': 'Recent malware URLs'
            },
            'malware_bazaar': {
                'name': 'MalwareBazaar',
                'url': 'https://mb-api.abuse.ch/api/v1/',
                'type': 'malware_samples',
                'enabled': True,
                'description': 'Malware samples database'
            },
            'threatfox': {
                'name': 'ThreatFox',
                'url': 'https://threatfox-api.abuse.ch/api/v1/',
                'type': 'iocs',
                'enabled': True,
                'description': 'Indicators of Compromise'
            },
            'custom_feed': {
                'name': 'Custom Feed',
                'url': '',
                'type': 'custom',
                'enabled': False,
                'description': 'Custom threat intelligence feed'
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
        title_label = tk.Label(left_panel, text="🛡️ Threat Intelligence Aggregator", 
                              bg=BG_COLOR, fg=TEXT_COLOR, 
                              font=("Consolas", 14, "bold"))
        title_label.pack(pady=(0, 10))
        
        # Ethical notice
        ethical_notice = tk.Label(left_panel, 
                                text="⚠️ Use responsibly and only on systems you own or have permission to test",
                                bg=BG_COLOR, fg="#FFA500", 
                                font=("Consolas", 9),
                                wraplength=380)
        ethical_notice.pack(pady=(0, 20))
        
        # Feed selection
        feeds_frame = tk.LabelFrame(left_panel, text="Threat Intelligence Feeds", 
                                  bg=BG_COLOR, fg=TEXT_COLOR)
        feeds_frame.pack(fill="x", pady=10)
        
        self.feed_vars = {}
        for feed_id, config in self.threat_feeds.items():
            var = tk.BooleanVar(value=config['enabled'])
            self.feed_vars[feed_id] = var
            
            cb = tk.Checkbutton(feeds_frame, text=f"{config['name']} - {config['description']}", 
                              variable=var, bg=BG_COLOR, fg=TEXT_COLOR,
                              selectcolor=BG_COLOR, wraplength=350)
            cb.pack(anchor="w", pady=2)
        
        # Custom feed configuration
        custom_frame = tk.LabelFrame(left_panel, text="Custom Feed Configuration", 
                                   bg=BG_COLOR, fg=TEXT_COLOR)
        custom_frame.pack(fill="x", pady=10)
        
        tk.Label(custom_frame, text="Custom Feed URL:", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        self.custom_url_entry = tk.Entry(custom_frame, bg="#111111", fg=TEXT_COLOR,
                                       insertbackground=TEXT_COLOR)
        self.custom_url_entry.pack(fill="x", pady=2)
        
        tk.Label(custom_frame, text="API Key (if required):", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        self.api_key_entry = tk.Entry(custom_frame, bg="#111111", fg=TEXT_COLOR,
                                    insertbackground=TEXT_COLOR, show="*")
        self.api_key_entry.pack(fill="x", pady=2)
        
        # Collection options
        options_frame = tk.LabelFrame(left_panel, text="Collection Options", 
                                    bg=BG_COLOR, fg=TEXT_COLOR)
        options_frame.pack(fill="x", pady=10)
        
        tk.Label(options_frame, text="Collection Interval (minutes):", 
                bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        self.interval_entry = tk.Entry(options_frame, bg="#111111", fg=TEXT_COLOR,
                                     insertbackground=TEXT_COLOR)
        self.interval_entry.pack(fill="x", pady=2)
        self.interval_entry.insert(0, "60")
        
        self.auto_correlate = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Auto-correlate with local infrastructure", 
                      variable=self.auto_correlate, bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR).pack(anchor="w")
        
        self.filter_duplicates = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Filter duplicate indicators", 
                      variable=self.filter_duplicates, bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR).pack(anchor="w")
        
        # IOC search
        search_frame = tk.LabelFrame(left_panel, text="IOC Search", 
                                   bg=BG_COLOR, fg=TEXT_COLOR)
        search_frame.pack(fill="x", pady=10)
        
        tk.Label(search_frame, text="Search IOC:", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        
        search_input_frame = tk.Frame(search_frame, bg=BG_COLOR)
        search_input_frame.pack(fill="x", pady=5)
        
        self.search_entry = tk.Entry(search_input_frame, bg="#111111", fg=TEXT_COLOR,
                                   insertbackground=TEXT_COLOR)
        self.search_entry.pack(side="left", fill="x", expand=True)
        
        search_btn = tk.Button(search_input_frame, text="Search", command=self.search_ioc)
        style_button(search_btn)
        search_btn.pack(side="right", padx=(5, 0))
        
        # Control buttons
        button_frame = tk.Frame(left_panel, bg=BG_COLOR)
        button_frame.pack(fill="x", pady=20)
        
        self.collect_button = tk.Button(button_frame, text="Start Collection", 
                                      command=self.start_collection)
        style_button(self.collect_button)
        self.collect_button.pack(fill="x", pady=2)
        
        self.stop_button = tk.Button(button_frame, text="Stop Collection", 
                                   command=self.stop_collection, state="disabled")
        style_button(self.stop_button)
        self.stop_button.pack(fill="x", pady=2)
        
        # Export buttons
        export_frame = tk.Frame(left_panel, bg=BG_COLOR)
        export_frame.pack(fill="x", pady=10)
        
        tk.Label(export_frame, text="Export Data:", bg=BG_COLOR, fg=TEXT_COLOR,
                font=("Consolas", 10, "bold")).pack(anchor="w")
        
        export_btn_frame = tk.Frame(export_frame, bg=BG_COLOR)
        export_btn_frame.pack(fill="x", pady=5)
        
        json_btn = tk.Button(export_btn_frame, text="JSON", command=self.export_json)
        style_button(json_btn)
        json_btn.pack(side="left", padx=(0, 5))
        
        csv_btn = tk.Button(export_btn_frame, text="CSV", command=self.export_csv)
        style_button(csv_btn)
        csv_btn.pack(side="left", padx=5)
        
        # Right panel for results
        right_panel = tk.Frame(main_frame, bg=BG_COLOR)
        right_panel.pack(side="right", fill="both", expand=True)
        
        # Progress bar
        self.add_progress_bar("Threat Intelligence Collection")
        
        # Results viewer with tabs
        self.add_results_viewer(["Dashboard", "IOCs", "Threats", "Correlations"])
        
        # Status label
        self.status_label = tk.Label(right_panel, text="Ready", 
                                   bg=BG_COLOR, fg=TEXT_COLOR)
        self.status_label.pack(pady=5)
    
    def start_collection(self):
        """Start threat intelligence collection"""
        if self.is_collecting:
            messagebox.showwarning("Collection in Progress", "Collection is already running.")
            return
        
        # Get selected feeds
        selected_feeds = [feed_id for feed_id, var in self.feed_vars.items() if var.get()]
        
        if not selected_feeds:
            messagebox.showerror("No Feeds Selected", "Please select at least one threat intelligence feed.")
            return
        
        # Start collection in separate thread
        self.is_collecting = True
        self.collect_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.threat_data = []
        self.update_progress(0, "Starting threat intelligence collection...")
        
        self.collection_thread = threading.Thread(target=self.run_collection, args=(selected_feeds,))
        self.collection_thread.daemon = True
        self.collection_thread.start()
        

    
    def run_collection(self, selected_feeds: List[str]):
        """Run the threat intelligence collection"""
        try:
            interval = int(self.interval_entry.get() or 60) * 60  # Convert to seconds
            
            while self.is_collecting:
                self.update_progress(10, "Collecting from feeds...")
                
                for i, feed_id in enumerate(selected_feeds):
                    if not self.is_collecting:
                        break
                    
                    progress = 10 + (i / len(selected_feeds)) * 70
                    feed_name = self.threat_feeds[feed_id]['name']
                    self.update_progress(progress, f"Collecting from {feed_name}...")
                    
                    self.collect_from_feed(feed_id)
                    time.sleep(2)  # Rate limiting
                
                if self.is_collecting:
                    self.update_progress(80, "Processing collected data...")
                    self.process_threat_data()
                    
                    self.update_progress(100, f"Collection complete - {len(self.threat_data)} indicators")
                    self.status_label.config(text=f"Collection complete - {len(self.threat_data)} indicators")
                    
                    # Wait for next collection cycle
                    for _ in range(interval):
                        if not self.is_collecting:
                            break
                        time.sleep(1)
            
        except Exception as e:
            self.update_progress(0, f"Error: {str(e)}")
            self.status_label.config(text=f"Error: {str(e)}")
            messagebox.showerror("Collection Error", f"An error occurred during collection:\n{str(e)}")
        
        finally:
            self.is_collecting = False
            self.collect_button.config(state="normal")
            self.stop_button.config(state="disabled")

    
    def collect_from_feed(self, feed_id: str):
        """Collect data from a specific threat intelligence feed"""
        config = self.threat_feeds[feed_id]
        
        try:
            if feed_id == 'abuse_ch':
                self.collect_from_abuse_ch()
            elif feed_id == 'malware_bazaar':
                self.collect_from_malware_bazaar()
            elif feed_id == 'threatfox':
                self.collect_from_threatfox()
            elif feed_id == 'custom_feed':
                self.collect_from_custom_feed()
        
        except Exception as e:
            print(f"Error collecting from {config['name']}: {e}")
    
    def collect_from_abuse_ch(self):
        """Collect from Abuse.ch URLhaus"""
        try:
            response = requests.get('https://urlhaus-api.abuse.ch/v1/urls/recent/', timeout=30)
            if response.status_code == 200:
                data = response.json()
                
                for url_info in data.get('urls', [])[:50]:  # Limit to 50 recent URLs
                    threat_item = {
                        'source': 'Abuse.ch URLhaus',
                        'type': 'malicious_url',
                        'indicator': url_info.get('url', ''),
                        'threat_type': url_info.get('threat', ''),
                        'tags': url_info.get('tags', []),
                        'date_added': url_info.get('date_added', ''),
                        'confidence': 'high',
                        'description': f"Malicious URL reported to URLhaus"
                    }
                    self.threat_data.append(threat_item)
        
        except Exception as e:
            print(f"Error collecting from Abuse.ch: {e}")
    
    def collect_from_malware_bazaar(self):
        """Collect from MalwareBazaar"""
        try:
            # Get recent samples
            payload = {'query': 'get_recent', 'selector': 'time'}
            response = requests.post('https://mb-api.abuse.ch/api/v1/', 
                                   data=payload, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for sample in data.get('data', [])[:25]:  # Limit to 25 recent samples
                    threat_item = {
                        'source': 'MalwareBazaar',
                        'type': 'malware_hash',
                        'indicator': sample.get('sha256_hash', ''),
                        'threat_type': sample.get('signature', ''),
                        'tags': sample.get('tags', []),
                        'date_added': sample.get('first_seen', ''),
                        'confidence': 'high',
                        'description': f"Malware sample: {sample.get('file_name', 'Unknown')}"
                    }
                    self.threat_data.append(threat_item)
        
        except Exception as e:
            print(f"Error collecting from MalwareBazaar: {e}")
    
    def collect_from_threatfox(self):
        """Collect from ThreatFox"""
        try:
            # Get recent IOCs
            payload = {'query': 'get_iocs', 'days': 1}
            response = requests.post('https://threatfox-api.abuse.ch/api/v1/', 
                                   data=json.dumps(payload), 
                                   headers={'Content-Type': 'application/json'},
                                   timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for ioc in data.get('data', [])[:50]:  # Limit to 50 recent IOCs
                    threat_item = {
                        'source': 'ThreatFox',
                        'type': ioc.get('ioc_type', ''),
                        'indicator': ioc.get('ioc', ''),
                        'threat_type': ioc.get('threat_type', ''),
                        'tags': ioc.get('tags', []),
                        'date_added': ioc.get('first_seen', ''),
                        'confidence': ioc.get('confidence_level', 'medium'),
                        'description': f"IOC from ThreatFox: {ioc.get('malware', 'Unknown')}"
                    }
                    self.threat_data.append(threat_item)
        
        except Exception as e:
            print(f"Error collecting from ThreatFox: {e}")
    
    def collect_from_custom_feed(self):
        """Collect from custom threat intelligence feed"""
        custom_url = self.custom_url_entry.get().strip()
        if not custom_url:
            return
        
        try:
            headers = {}
            api_key = self.api_key_entry.get().strip()
            if api_key:
                headers['Authorization'] = f'Bearer {api_key}'
            
            response = requests.get(custom_url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                
                # This is a generic parser - would need customization for specific feeds
                if isinstance(data, list):
                    for item in data[:50]:  # Limit to 50 items
                        threat_item = {
                            'source': 'Custom Feed',
                            'type': item.get('type', 'unknown'),
                            'indicator': item.get('indicator', ''),
                            'threat_type': item.get('threat_type', ''),
                            'tags': item.get('tags', []),
                            'date_added': item.get('date', datetime.now().isoformat()),
                            'confidence': item.get('confidence', 'medium'),
                            'description': item.get('description', 'Custom feed indicator')
                        }
                        self.threat_data.append(threat_item)
        
        except Exception as e:
            print(f"Error collecting from custom feed: {e}")
    
    def process_threat_data(self):
        """Process and analyze collected threat data"""
        if not self.threat_data:
            return
        
        # Filter duplicates if enabled
        if self.filter_duplicates.get():
            seen_indicators = set()
            filtered_data = []
            for item in self.threat_data:
                indicator = item['indicator']
                if indicator not in seen_indicators:
                    seen_indicators.add(indicator)
                    filtered_data.append(item)
            self.threat_data = filtered_data
        
        # Auto-correlate with local infrastructure if enabled
        if self.auto_correlate.get():
            self.correlate_with_infrastructure()
        
        # Update UI tabs
        self.update_dashboard_tab()
        self.update_iocs_tab()
        self.update_threats_tab()
        self.update_correlations_tab()
        
        # Set results data for export
        self.set_results_data({
            'collection_metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_indicators': len(self.threat_data),
                'sources': list(set(item['source'] for item in self.threat_data))
            },
            'threat_intelligence': self.threat_data
        })
    
    def correlate_with_infrastructure(self):
        """Correlate threat intelligence with local infrastructure"""
        # This is a simplified correlation - in practice, you'd have actual infrastructure data
        local_ips = ['192.168.1.0/24', '10.0.0.0/8']  # Example local networks
        
        for item in self.threat_data:
            indicator = item['indicator']
            
            # Check if indicator matches local infrastructure patterns
            if any(pattern in indicator for pattern in local_ips):
                item['correlation'] = 'potential_local_match'
                item['risk_level'] = 'high'
            else:
                item['correlation'] = 'no_match'
                item['risk_level'] = 'medium'
    
    def search_ioc(self):
        """Search for a specific IOC in collected data"""
        search_term = self.search_entry.get().strip().lower()
        if not search_term:
            messagebox.showwarning("No Search Term", "Please enter an IOC to search for.")
            return
        
        matches = []
        for item in self.threat_data:
            if (search_term in item['indicator'].lower() or 
                search_term in item.get('description', '').lower() or
                search_term in str(item.get('tags', [])).lower()):
                matches.append(item)
        
        if matches:
            # Display search results
            result_text = f"Search Results for '{search_term}':\n\n"
            for match in matches[:10]:  # Show top 10 matches
                result_text += f"Indicator: {match['indicator']}\n"
                result_text += f"Type: {match['type']}\n"
                result_text += f"Source: {match['source']}\n"
                result_text += f"Description: {match['description']}\n\n"
            
            self.update_results_tab("IOCs", result_text)
            messagebox.showinfo("Search Results", f"Found {len(matches)} matches for '{search_term}'")
        else:
            messagebox.showinfo("Search Results", f"No matches found for '{search_term}'")
    
    def update_dashboard_tab(self):
        """Update the dashboard tab"""
        if not self.threat_data:
            self.update_results_tab("Dashboard", "No threat intelligence data collected yet.")
            return
        
        # Generate statistics
        total_indicators = len(self.threat_data)
        sources = {}
        types = {}
        threat_types = {}
        
        for item in self.threat_data:
            # Count by source
            source = item['source']
            sources[source] = sources.get(source, 0) + 1
            
            # Count by type
            ioc_type = item['type']
            types[ioc_type] = types.get(ioc_type, 0) + 1
            
            # Count by threat type
            threat_type = item.get('threat_type', 'Unknown')
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        dashboard_text = f"""Threat Intelligence Dashboard
{'='*35}

Collection Summary:
• Total Indicators: {total_indicators}
• Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
• Active Sources: {len(sources)}

Indicators by Source:
"""
        
        for source, count in sorted(sources.items(), key=lambda x: x[1], reverse=True):
            dashboard_text += f"  • {source}: {count}\n"
        
        dashboard_text += "\nIndicators by Type:\n"
        for ioc_type, count in sorted(types.items(), key=lambda x: x[1], reverse=True):
            dashboard_text += f"  • {ioc_type}: {count}\n"
        
        dashboard_text += "\nTop Threat Types:\n"
        for threat_type, count in sorted(threat_types.items(), key=lambda x: x[1], reverse=True)[:10]:
            dashboard_text += f"  • {threat_type}: {count}\n"
        
        # Recent high-confidence indicators
        high_conf_indicators = [item for item in self.threat_data 
                               if item.get('confidence', '').lower() == 'high'][:5]
        
        if high_conf_indicators:
            dashboard_text += "\nRecent High-Confidence Indicators:\n"
            for item in high_conf_indicators:
                dashboard_text += f"  • {item['indicator']} ({item['type']})\n"
        
        self.update_results_tab("Dashboard", dashboard_text)
    
    def update_iocs_tab(self):
        """Update the IOCs tab"""
        if not self.threat_data:
            self.update_results_tab("IOCs", "No IOCs collected yet.")
            return
        
        iocs_text = f"""Indicators of Compromise (IOCs)
{'='*35}

Total IOCs: {len(self.threat_data)}

Recent IOCs:
"""
        
        # Show recent IOCs
        for item in self.threat_data[:20]:  # Show top 20
            iocs_text += f"\nIndicator: {item['indicator']}\n"
            iocs_text += f"  Type: {item['type']}\n"
            iocs_text += f"  Source: {item['source']}\n"
            iocs_text += f"  Confidence: {item.get('confidence', 'Unknown')}\n"
            iocs_text += f"  Date: {item.get('date_added', 'Unknown')}\n"
            if item.get('tags'):
                iocs_text += f"  Tags: {', '.join(item['tags'])}\n"
        
        if len(self.threat_data) > 20:
            iocs_text += f"\n... and {len(self.threat_data) - 20} more IOCs\n"
        
        self.update_results_tab("IOCs", iocs_text)
    
    def update_threats_tab(self):
        """Update the threats tab"""
        if not self.threat_data:
            self.update_results_tab("Threats", "No threat data collected yet.")
            return
        
        # Group by threat type
        threats_by_type = {}
        for item in self.threat_data:
            threat_type = item.get('threat_type', 'Unknown')
            if threat_type not in threats_by_type:
                threats_by_type[threat_type] = []
            threats_by_type[threat_type].append(item)
        
        threats_text = f"""Threat Analysis
{'='*20}

Threat Categories: {len(threats_by_type)}

"""
        
        for threat_type, items in sorted(threats_by_type.items(), 
                                       key=lambda x: len(x[1]), reverse=True):
            threats_text += f"\n{threat_type} ({len(items)} indicators):\n"
            threats_text += f"{'─' * 40}\n"
            
            # Show top indicators for this threat type
            for item in items[:5]:
                threats_text += f"  • {item['indicator']} ({item['source']})\n"
            
            if len(items) > 5:
                threats_text += f"  ... and {len(items) - 5} more\n"
        
        self.update_results_tab("Threats", threats_text)
    
    def update_correlations_tab(self):
        """Update the correlations tab"""
        if not self.threat_data:
            self.update_results_tab("Correlations", "No correlation data available.")
            return
        
        correlations_text = f"""Threat Correlations
{'='*25}

"""
        
        # Check for correlations
        correlated_items = [item for item in self.threat_data 
                          if item.get('correlation') == 'potential_local_match']
        
        if correlated_items:
            correlations_text += f"⚠️  POTENTIAL LOCAL MATCHES ({len(correlated_items)}):\n\n"
            for item in correlated_items:
                correlations_text += f"• {item['indicator']}\n"
                correlations_text += f"  Type: {item['type']}\n"
                correlations_text += f"  Risk Level: {item.get('risk_level', 'Unknown')}\n"
                correlations_text += f"  Description: {item['description']}\n\n"
        else:
            correlations_text += "✅ No direct correlations with local infrastructure detected.\n\n"
        
        # Pattern analysis
        correlations_text += "Pattern Analysis:\n"
        
        # Common domains/IPs
        domains = [item['indicator'] for item in self.threat_data 
                  if item['type'] in ['domain', 'url', 'malicious_url']]
        if domains:
            correlations_text += f"• {len(domains)} malicious domains/URLs identified\n"
        
        # Hash patterns
        hashes = [item['indicator'] for item in self.threat_data 
                 if item['type'] in ['md5_hash', 'sha1_hash', 'sha256_hash', 'malware_hash']]
        if hashes:
            correlations_text += f"• {len(hashes)} malware hashes collected\n"
        
        # IP addresses
        ips = [item['indicator'] for item in self.threat_data 
              if item['type'] in ['ip', 'ip_address']]
        if ips:
            correlations_text += f"• {len(ips)} malicious IP addresses identified\n"
        
        self.update_results_tab("Correlations", correlations_text)
    
    def stop_collection(self):
        """Stop threat intelligence collection"""
        if self.is_collecting:
            self.is_collecting = False
            self.collect_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.update_progress(0, "Collection stopped by user")
            self.status_label.config(text="Collection stopped")
            messagebox.showinfo("Collection Stopped", "Threat intelligence collection has been stopped.")
    
    def export_json(self):
        """Export threat intelligence as JSON"""
        if not self.threat_data:
            messagebox.showwarning("No Data", "No threat intelligence data to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            title="Export Threat Intelligence as JSON"
        )
        
        if filename:
            try:
                export_data = {
                    'metadata': {
                        'export_timestamp': datetime.now().isoformat(),
                        'total_indicators': len(self.threat_data),
                        'sources': list(set(item['source'] for item in self.threat_data))
                    },
                    'threat_intelligence': self.threat_data
                }
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
                messagebox.showinfo("Export Successful", f"Threat intelligence exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export data:\n{str(e)}")
    
    def export_csv(self):
        """Export threat intelligence as CSV"""
        if not self.threat_data:
            messagebox.showwarning("No Data", "No threat intelligence data to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Export Threat Intelligence as CSV"
        )
        
        if filename:
            try:
                import csv
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    
                    # Write header
                    writer.writerow(['Indicator', 'Type', 'Source', 'Threat Type', 
                                   'Confidence', 'Date Added', 'Description', 'Tags'])
                    
                    # Write data
                    for item in self.threat_data:
                        writer.writerow([
                            item['indicator'],
                            item['type'],
                            item['source'],
                            item.get('threat_type', ''),
                            item.get('confidence', ''),
                            item.get('date_added', ''),
                            item['description'],
                            ', '.join(item.get('tags', []))
                        ])
                
                messagebox.showinfo("Export Successful", f"Threat intelligence exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export data:\n{str(e)}")


# Create the ToolFrame class that the main application expects
class ToolFrame(ThreatIntelligenceAggregator):
    """Wrapper class for main application compatibility"""
    pass