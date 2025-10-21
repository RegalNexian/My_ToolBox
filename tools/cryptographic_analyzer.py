# tools/cryptographic_analyzer.py - Cryptographic Analyzer Tool
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import hashlib
import ssl
import socket
import threading
import json
import os
import re
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from base_tool import SecurityToolFrame
from theme import BG_COLOR, TEXT_COLOR, style_button
from utils import ensure_results_subfolder

TAB_NAME = "Cryptographic Analyzer"

class CryptographicAnalyzer(SecurityToolFrame):
    """Cryptographic analyzer for evaluating crypto implementations and configurations"""
    
    def __init__(self, master):
        super().__init__(master, {
            'name': 'Cryptographic Analyzer',
            'tool_id': 'cryptographic_analyzer',
            'category': 'Security'
        })
        
        ensure_results_subfolder("Cryptographic_Analyzer")
        
        # Initialize variables
        self.analysis_results = []
        self.analysis_thread = None
        self.is_analyzing = False
        
        # Setup security framework
        self.setup_security_framework()
        
        # Initialize crypto standards
        self.crypto_standards = self.initialize_crypto_standards()
        
        # Build UI
        self.setup_ui()
    
    def initialize_crypto_standards(self) -> Dict[str, Dict]:
        """Initialize cryptographic standards and recommendations"""
        return {
            'symmetric_algorithms': {
                'secure': ['AES-256', 'AES-192', 'AES-128', 'ChaCha20'],
                'weak': ['DES', '3DES', 'RC4', 'Blowfish'],
                'deprecated': ['MD5', 'SHA1']
            },
            'asymmetric_algorithms': {
                'secure': ['RSA-4096', 'RSA-3072', 'RSA-2048', 'ECDSA-P256', 'ECDSA-P384', 'Ed25519'],
                'weak': ['RSA-1024', 'DSA-1024'],
                'deprecated': ['RSA-512', 'DSA-512']
            },
            'hash_algorithms': {
                'secure': ['SHA-256', 'SHA-384', 'SHA-512', 'SHA-3', 'BLAKE2'],
                'weak': ['SHA-1'],
                'deprecated': ['MD5', 'MD4', 'MD2']
            },
            'key_sizes': {
                'RSA': {'minimum': 2048, 'recommended': 3072, 'secure': 4096},
                'DSA': {'minimum': 2048, 'recommended': 3072, 'secure': 4096},
                'ECDSA': {'minimum': 256, 'recommended': 384, 'secure': 521},
                'AES': {'minimum': 128, 'recommended': 256, 'secure': 256}
            },
            'ssl_tls_versions': {
                'secure': ['TLSv1.3', 'TLSv1.2'],
                'weak': ['TLSv1.1', 'TLSv1.0'],
                'deprecated': ['SSLv3', 'SSLv2']
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
        title_label = tk.Label(left_panel, text="🔐 Cryptographic Analyzer", 
                              bg=BG_COLOR, fg=TEXT_COLOR, 
                              font=("Consolas", 14, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Analysis type selection
        type_frame = tk.LabelFrame(left_panel, text="Analysis Type", 
                                 bg=BG_COLOR, fg=TEXT_COLOR)
        type_frame.pack(fill="x", pady=10)
        
        self.analysis_type = tk.StringVar(value="code")
        
        tk.Radiobutton(type_frame, text="Code Analysis", variable=self.analysis_type, 
                      value="code", bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR, command=self.toggle_analysis_type).pack(anchor="w")
        tk.Radiobutton(type_frame, text="SSL/TLS Certificate Analysis", variable=self.analysis_type, 
                      value="ssl", bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR, command=self.toggle_analysis_type).pack(anchor="w")
        tk.Radiobutton(type_frame, text="File Hash Analysis", variable=self.analysis_type, 
                      value="hash", bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR, command=self.toggle_analysis_type).pack(anchor="w")
        tk.Radiobutton(type_frame, text="Entropy Analysis", variable=self.analysis_type, 
                      value="entropy", bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR, command=self.toggle_analysis_type).pack(anchor="w")
        
        # Code analysis frame
        self.code_frame = tk.LabelFrame(left_panel, text="Code Analysis", 
                                      bg=BG_COLOR, fg=TEXT_COLOR)
        self.code_frame.pack(fill="x", pady=10)
        
        tk.Label(self.code_frame, text="Directory/File to analyze:", 
                bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        
        code_input_frame = tk.Frame(self.code_frame, bg=BG_COLOR)
        code_input_frame.pack(fill="x", pady=5)
        
        self.code_path_entry = tk.Entry(code_input_frame, bg="#111111", fg=TEXT_COLOR, 
                                      insertbackground=TEXT_COLOR)
        self.code_path_entry.pack(side="left", fill="x", expand=True)
        
        browse_code_btn = tk.Button(code_input_frame, text="Browse", 
                                  command=self.browse_code_path)
        style_button(browse_code_btn)
        browse_code_btn.pack(side="right", padx=(5, 0))
        
        # File patterns
        tk.Label(self.code_frame, text="File patterns:", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        self.code_patterns_entry = tk.Entry(self.code_frame, bg="#111111", fg=TEXT_COLOR,
                                          insertbackground=TEXT_COLOR)
        self.code_patterns_entry.pack(fill="x", pady=2)
        self.code_patterns_entry.insert(0, "*.py,*.js,*.java,*.c,*.cpp,*.cs")
        
        # SSL analysis frame
        self.ssl_frame = tk.LabelFrame(left_panel, text="SSL/TLS Analysis", 
                                     bg=BG_COLOR, fg=TEXT_COLOR)
        
        tk.Label(self.ssl_frame, text="Hostname:", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        self.hostname_entry = tk.Entry(self.ssl_frame, bg="#111111", fg=TEXT_COLOR,
                                     insertbackground=TEXT_COLOR)
        self.hostname_entry.pack(fill="x", pady=2)
        self.hostname_entry.insert(0, "google.com")
        
        tk.Label(self.ssl_frame, text="Port:", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        self.port_entry = tk.Entry(self.ssl_frame, bg="#111111", fg=TEXT_COLOR,
                                 insertbackground=TEXT_COLOR)
        self.port_entry.pack(fill="x", pady=2)
        self.port_entry.insert(0, "443")
        
        # Hash analysis frame
        self.hash_frame = tk.LabelFrame(left_panel, text="Hash Analysis", 
                                      bg=BG_COLOR, fg=TEXT_COLOR)
        
        tk.Label(self.hash_frame, text="File to analyze:", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        
        hash_input_frame = tk.Frame(self.hash_frame, bg=BG_COLOR)
        hash_input_frame.pack(fill="x", pady=5)
        
        self.hash_file_entry = tk.Entry(hash_input_frame, bg="#111111", fg=TEXT_COLOR,
                                      insertbackground=TEXT_COLOR)
        self.hash_file_entry.pack(side="left", fill="x", expand=True)
        
        browse_hash_btn = tk.Button(hash_input_frame, text="Browse", 
                                  command=self.browse_hash_file)
        style_button(browse_hash_btn)
        browse_hash_btn.pack(side="right", padx=(5, 0))
        
        # Entropy analysis frame
        self.entropy_frame = tk.LabelFrame(left_panel, text="Entropy Analysis", 
                                         bg=BG_COLOR, fg=TEXT_COLOR)
        
        tk.Label(self.entropy_frame, text="Text/Data to analyze:", 
                bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        self.entropy_text = tk.Text(self.entropy_frame, height=4, bg="#111111", 
                                  fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
        self.entropy_text.pack(fill="x", pady=2)
        
        # Analysis options
        options_frame = tk.LabelFrame(left_panel, text="Analysis Options", 
                                    bg=BG_COLOR, fg=TEXT_COLOR)
        options_frame.pack(fill="x", pady=10)
        
        self.check_weak_algorithms = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Check for weak algorithms", 
                      variable=self.check_weak_algorithms, bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR).pack(anchor="w")
        
        self.check_key_sizes = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Analyze key sizes", 
                      variable=self.check_key_sizes, bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR).pack(anchor="w")
        
        self.check_implementations = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Check implementation patterns", 
                      variable=self.check_implementations, bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR).pack(anchor="w")
        
        self.check_certificates = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Validate certificates", 
                      variable=self.check_certificates, bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR).pack(anchor="w")
        
        # Control buttons
        button_frame = tk.Frame(left_panel, bg=BG_COLOR)
        button_frame.pack(fill="x", pady=20)
        
        self.analyze_button = tk.Button(button_frame, text="Start Analysis", 
                                      command=self.start_analysis)
        style_button(self.analyze_button)
        self.analyze_button.pack(fill="x", pady=2)
        
        self.stop_button = tk.Button(button_frame, text="Stop Analysis", 
                                   command=self.stop_analysis, state="disabled")
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
        
        pdf_btn = tk.Button(export_btn_frame, text="PDF", command=self.export_pdf)
        style_button(pdf_btn)
        pdf_btn.pack(side="left", padx=5)
        
        # Right panel for results
        right_panel = tk.Frame(main_frame, bg=BG_COLOR)
        right_panel.pack(side="right", fill="both", expand=True)
        
        # Progress bar
        self.add_progress_bar("Cryptographic Analysis Progress")
        
        # Results viewer with tabs
        self.add_results_viewer(["Summary", "Weak Algorithms", "Key Analysis", "Recommendations"])
        
        # Status label
        self.status_label = tk.Label(right_panel, text="Ready", 
                                   bg=BG_COLOR, fg=TEXT_COLOR)
        self.status_label.pack(pady=5)
        
        # Initialize UI state
        self.toggle_analysis_type()
    
    def toggle_analysis_type(self):
        """Toggle visibility of analysis type frames"""
        # Hide all frames first
        self.code_frame.pack_forget()
        self.ssl_frame.pack_forget()
        self.hash_frame.pack_forget()
        self.entropy_frame.pack_forget()
        
        # Show the selected frame
        analysis_type = self.analysis_type.get()
        if analysis_type == "code":
            self.code_frame.pack(fill="x", pady=10)
        elif analysis_type == "ssl":
            self.ssl_frame.pack(fill="x", pady=10)
        elif analysis_type == "hash":
            self.hash_frame.pack(fill="x", pady=10)
        elif analysis_type == "entropy":
            self.entropy_frame.pack(fill="x", pady=10)
    
    def browse_code_path(self):
        """Browse for code directory or file"""
        path = filedialog.askdirectory(title="Select Directory to Analyze")
        if not path:
            path = filedialog.askopenfilename(title="Select File to Analyze")
        
        if path:
            self.code_path_entry.delete(0, tk.END)
            self.code_path_entry.insert(0, path)
    
    def browse_hash_file(self):
        """Browse for file to hash"""
        filename = filedialog.askopenfilename(title="Select File for Hash Analysis")
        if filename:
            self.hash_file_entry.delete(0, tk.END)
            self.hash_file_entry.insert(0, filename)
    
    def start_analysis(self):
        """Start the cryptographic analysis"""
        if self.is_analyzing:
            messagebox.showwarning("Analysis in Progress", "An analysis is already running.")
            return
        
        analysis_type = self.analysis_type.get()
        
        # Validate inputs based on analysis type
        if analysis_type == "code":
            path = self.code_path_entry.get().strip()
            if not path or not os.path.exists(path):
                messagebox.showerror("Invalid Path", "Please select a valid file or directory.")
                return
        elif analysis_type == "ssl":
            hostname = self.hostname_entry.get().strip()
            port = self.port_entry.get().strip()
            if not hostname:
                messagebox.showerror("Invalid Hostname", "Please enter a hostname.")
                return
            try:
                port = int(port)
            except ValueError:
                messagebox.showerror("Invalid Port", "Please enter a valid port number.")
                return
        elif analysis_type == "hash":
            filename = self.hash_file_entry.get().strip()
            if not filename or not os.path.exists(filename):
                messagebox.showerror("Invalid File", "Please select a valid file.")
                return
        elif analysis_type == "entropy":
            text = self.entropy_text.get("1.0", tk.END).strip()
            if not text:
                messagebox.showerror("No Data", "Please enter text or data to analyze.")
                return
        
        # Start analysis in separate thread
        self.is_analyzing = True
        self.analyze_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.analysis_results = []
        self.update_progress(0, "Starting analysis...")
        
        self.analysis_thread = threading.Thread(target=self.run_analysis, args=(analysis_type,))
        self.analysis_thread.daemon = True
        self.analysis_thread.start()
        
        # Log the analysis start
        self.log_security_activity("CRYPTO_ANALYSIS_STARTED", f"Cryptographic analysis started: {analysis_type}")
    
    def run_analysis(self, analysis_type: str):
        """Run the actual cryptographic analysis"""
        try:
            if analysis_type == "code":
                self.analyze_code()
            elif analysis_type == "ssl":
                self.analyze_ssl_certificate()
            elif analysis_type == "hash":
                self.analyze_file_hashes()
            elif analysis_type == "entropy":
                self.analyze_entropy()
            
            if self.is_analyzing:
                self.update_progress(100, "Analysis completed")
                self.process_analysis_results()
                self.status_label.config(text=f"Analysis completed - {len(self.analysis_results)} issues found")
            
        except Exception as e:
            self.update_progress(0, f"Error: {str(e)}")
            self.status_label.config(text=f"Error: {str(e)}")
            messagebox.showerror("Analysis Error", f"An error occurred during analysis:\n{str(e)}")
        
        finally:
            self.is_analyzing = False
            self.analyze_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.log_security_activity("CRYPTO_ANALYSIS_COMPLETED", 
                                     f"Cryptographic analysis completed - {len(self.analysis_results)} issues found")
    
    def analyze_code(self):
        """Analyze code for cryptographic issues"""
        path = self.code_path_entry.get().strip()
        patterns = [p.strip() for p in self.code_patterns_entry.get().split(',') if p.strip()]
        
        self.update_progress(10, "Scanning files...")
        
        files_to_analyze = []
        if os.path.isfile(path):
            files_to_analyze = [path]
        else:
            files_to_analyze = self.find_files_to_analyze(path, patterns)
        
        total_files = len(files_to_analyze)
        if total_files == 0:
            self.update_progress(100, "No files found to analyze")
            return
        
        self.update_progress(20, f"Found {total_files} files to analyze")
        
        for i, file_path in enumerate(files_to_analyze):
            if not self.is_analyzing:
                break
            
            progress = 20 + (i / total_files) * 70
            self.update_progress(progress, f"Analyzing {os.path.basename(file_path)}...")
            
            self.analyze_code_file(file_path)
    
    def find_files_to_analyze(self, directory: str, patterns: List[str]) -> List[str]:
        """Find files matching the specified patterns"""
        import fnmatch
        
        files_to_analyze = []
        for root, dirs, files in os.walk(directory):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', 'node_modules', '.venv']]
            
            for file in files:
                if any(fnmatch.fnmatch(file, pattern) for pattern in patterns):
                    files_to_analyze.append(os.path.join(root, file))
        
        return files_to_analyze
    
    def analyze_code_file(self, file_path: str):
        """Analyze a single code file for cryptographic issues"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check for weak algorithms
            if self.check_weak_algorithms.get():
                self.check_weak_crypto_algorithms(file_path, content)
            
            # Check for implementation issues
            if self.check_implementations.get():
                self.check_crypto_implementation_issues(file_path, content)
            
            # Check for hardcoded keys/secrets
            self.check_hardcoded_crypto_material(file_path, content)
            
        except Exception as e:
            self.add_finding(file_path, 'ERROR', f"Error analyzing file: {str(e)}", 'LOW')
    
    def check_weak_crypto_algorithms(self, file_path: str, content: str):
        """Check for weak cryptographic algorithms"""
        weak_patterns = {
            'MD5': [r'md5\s*\(', r'hashlib\.md5', r'MD5\s*\(', r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']'],
            'SHA1': [r'sha1\s*\(', r'hashlib\.sha1', r'SHA1\s*\(', r'MessageDigest\.getInstance\s*\(\s*["\']SHA-1["\']'],
            'DES': [r'DES\s*\(', r'Cipher\.getInstance\s*\(\s*["\']DES["\']'],
            '3DES': [r'3DES\s*\(', r'TripleDES', r'Cipher\.getInstance\s*\(\s*["\']DESede["\']'],
            'RC4': [r'RC4\s*\(', r'Cipher\.getInstance\s*\(\s*["\']RC4["\']'],
            'Blowfish': [r'Blowfish\s*\(', r'Cipher\.getInstance\s*\(\s*["\']Blowfish["\']']
        }
        
        for algorithm, patterns in weak_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    severity = 'CRITICAL' if algorithm in ['MD5', 'DES', 'RC4'] else 'HIGH'
                    self.add_finding(
                        file_path, 
                        'WEAK_ALGORITHM', 
                        f"Weak cryptographic algorithm: {algorithm} at line {line_num}",
                        severity
                    )
    
    def check_crypto_implementation_issues(self, file_path: str, content: str):
        """Check for common cryptographic implementation issues"""
        issues = {
            'ECB_MODE': {
                'patterns': [r'ECB', r'ELECTRONIC_CODEBOOK'],
                'description': 'ECB mode usage detected',
                'severity': 'HIGH'
            },
            'WEAK_RANDOM': {
                'patterns': [r'Math\.random\s*\(', r'Random\s*\(', r'rand\s*\('],
                'description': 'Weak random number generation',
                'severity': 'MEDIUM'
            },
            'HARDCODED_IV': {
                'patterns': [r'iv\s*=\s*["\'][^"\']{16,}["\']', r'IV\s*=\s*["\'][^"\']{16,}["\']'],
                'description': 'Hardcoded initialization vector',
                'severity': 'HIGH'
            },
            'WEAK_KEY_SIZE': {
                'patterns': [r'keysize\s*=\s*512', r'1024.*bit', r'RSA.*1024'],
                'description': 'Weak key size detected',
                'severity': 'MEDIUM'
            }
        }
        
        for issue_type, config in issues.items():
            for pattern in config['patterns']:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    self.add_finding(
                        file_path,
                        issue_type,
                        f"{config['description']} at line {line_num}",
                        config['severity']
                    )
    
    def check_hardcoded_crypto_material(self, file_path: str, content: str):
        """Check for hardcoded cryptographic material"""
        patterns = {
            'PRIVATE_KEY': r'-----BEGIN.*PRIVATE KEY-----',
            'CERTIFICATE': r'-----BEGIN CERTIFICATE-----',
            'LONG_HEX_STRING': r'["\'][a-fA-F0-9]{32,}["\']',  # Potential keys
            'BASE64_KEY': r'["\'][A-Za-z0-9+/]{40,}={0,2}["\']'  # Potential base64 encoded keys
        }
        
        for key_type, pattern in patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                severity = 'CRITICAL' if 'KEY' in key_type else 'HIGH'
                self.add_finding(
                    file_path,
                    'HARDCODED_CRYPTO',
                    f"Hardcoded cryptographic material ({key_type}) at line {line_num}",
                    severity
                )
    
    def analyze_ssl_certificate(self):
        """Analyze SSL/TLS certificate"""
        hostname = self.hostname_entry.get().strip()
        port = int(self.port_entry.get().strip())
        
        self.update_progress(20, "Connecting to server...")
        
        try:
            # Get certificate
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cert_der = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()
            
            self.update_progress(50, "Analyzing certificate...")
            
            # Analyze certificate details
            self.analyze_certificate_details(hostname, cert, cipher, version)
            
            self.update_progress(80, "Checking certificate chain...")
            
            # Analyze certificate chain
            self.analyze_certificate_chain(hostname, port)
            
        except Exception as e:
            self.add_finding(hostname, 'CONNECTION_ERROR', f"Failed to connect: {str(e)}", 'HIGH')
    
    def analyze_certificate_details(self, hostname: str, cert: Dict, cipher: Tuple, version: str):
        """Analyze SSL certificate details"""
        # Check certificate expiration
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_until_expiry = (not_after - datetime.now()).days
        
        if days_until_expiry < 0:
            self.add_finding(hostname, 'CERT_EXPIRED', 'Certificate has expired', 'CRITICAL')
        elif days_until_expiry < 30:
            self.add_finding(hostname, 'CERT_EXPIRING', f'Certificate expires in {days_until_expiry} days', 'HIGH')
        elif days_until_expiry < 90:
            self.add_finding(hostname, 'CERT_EXPIRING', f'Certificate expires in {days_until_expiry} days', 'MEDIUM')
        
        # Check key algorithm and size
        public_key = cert.get('subjectPublicKeyInfo', {})
        if 'algorithm' in str(public_key):
            # This is a simplified check - in practice, you'd parse the ASN.1 structure
            if 'rsa' in str(public_key).lower():
                # Try to extract key size (simplified)
                if '1024' in str(public_key):
                    self.add_finding(hostname, 'WEAK_KEY_SIZE', 'RSA key size 1024 bits is weak', 'HIGH')
        
        # Check signature algorithm
        sig_algorithm = cert.get('signatureAlgorithm', '')
        if 'sha1' in sig_algorithm.lower():
            self.add_finding(hostname, 'WEAK_SIGNATURE', 'Certificate uses SHA-1 signature', 'MEDIUM')
        elif 'md5' in sig_algorithm.lower():
            self.add_finding(hostname, 'WEAK_SIGNATURE', 'Certificate uses MD5 signature', 'CRITICAL')
        
        # Check SSL/TLS version
        if version in self.crypto_standards['ssl_tls_versions']['deprecated']:
            self.add_finding(hostname, 'DEPRECATED_TLS', f'Using deprecated TLS version: {version}', 'CRITICAL')
        elif version in self.crypto_standards['ssl_tls_versions']['weak']:
            self.add_finding(hostname, 'WEAK_TLS', f'Using weak TLS version: {version}', 'HIGH')
        
        # Check cipher suite
        if cipher:
            cipher_name = cipher[0]
            if 'RC4' in cipher_name:
                self.add_finding(hostname, 'WEAK_CIPHER', f'Weak cipher suite: {cipher_name}', 'HIGH')
            elif 'DES' in cipher_name:
                self.add_finding(hostname, 'WEAK_CIPHER', f'Weak cipher suite: {cipher_name}', 'CRITICAL')
        
        # Check subject alternative names
        san_list = []
        for ext in cert.get('extensions', []):
            if ext[0] == 'subjectAltName':
                san_list = [name[1] for name in ext[1]]
                break
        
        if hostname not in san_list and not any(hostname.endswith(name.replace('*.', '.')) for name in san_list):
            self.add_finding(hostname, 'HOSTNAME_MISMATCH', 'Hostname not in certificate SAN', 'HIGH')
    
    def analyze_certificate_chain(self, hostname: str, port: int):
        """Analyze certificate chain"""
        try:
            # This is a simplified chain analysis
            # In practice, you'd need to validate the entire chain
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock) as ssock:
                    # Get peer certificate chain
                    cert_chain = ssock.getpeercert_chain()
                    
                    if cert_chain and len(cert_chain) < 2:
                        self.add_finding(hostname, 'INCOMPLETE_CHAIN', 'Certificate chain appears incomplete', 'MEDIUM')
        
        except Exception as e:
            self.add_finding(hostname, 'CHAIN_ERROR', f'Error analyzing certificate chain: {str(e)}', 'LOW')
    
    def analyze_file_hashes(self):
        """Analyze file hashes"""
        filename = self.hash_file_entry.get().strip()
        
        self.update_progress(20, "Computing hashes...")
        
        try:
            # Compute multiple hashes
            hashes = self.compute_file_hashes(filename)
            
            self.update_progress(60, "Analyzing hash algorithms...")
            
            # Analyze hash strength
            for algorithm, hash_value in hashes.items():
                if algorithm.upper() in self.crypto_standards['hash_algorithms']['deprecated']:
                    self.add_finding(filename, 'DEPRECATED_HASH', 
                                   f'{algorithm.upper()} is deprecated for security purposes', 'HIGH')
                elif algorithm.upper() in self.crypto_standards['hash_algorithms']['weak']:
                    self.add_finding(filename, 'WEAK_HASH', 
                                   f'{algorithm.upper()} is considered weak', 'MEDIUM')
            
            # Store hash results
            self.hash_results = hashes
            
        except Exception as e:
            self.add_finding(filename, 'HASH_ERROR', f'Error computing hashes: {str(e)}', 'LOW')
    
    def compute_file_hashes(self, filename: str) -> Dict[str, str]:
        """Compute multiple hashes for a file"""
        hashes = {}
        
        # Initialize hash objects
        hash_objects = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'sha512': hashlib.sha512()
        }
        
        # Read file and update hashes
        with open(filename, 'rb') as f:
            while chunk := f.read(8192):
                for hash_obj in hash_objects.values():
                    hash_obj.update(chunk)
        
        # Get hex digests
        for name, hash_obj in hash_objects.items():
            hashes[name] = hash_obj.hexdigest()
        
        return hashes
    
    def analyze_entropy(self):
        """Analyze entropy of text/data"""
        text = self.entropy_text.get("1.0", tk.END).strip()
        
        self.update_progress(30, "Computing entropy...")
        
        # Calculate Shannon entropy
        entropy = self.calculate_shannon_entropy(text)
        
        self.update_progress(70, "Analyzing entropy results...")
        
        # Analyze entropy results
        if entropy < 1.0:
            self.add_finding('entropy_analysis', 'LOW_ENTROPY', 
                           f'Very low entropy ({entropy:.2f}) - data may be predictable', 'HIGH')
        elif entropy < 2.0:
            self.add_finding('entropy_analysis', 'LOW_ENTROPY', 
                           f'Low entropy ({entropy:.2f}) - data has limited randomness', 'MEDIUM')
        elif entropy > 7.5:
            self.add_finding('entropy_analysis', 'HIGH_ENTROPY', 
                           f'High entropy ({entropy:.2f}) - data appears random/encrypted', 'LOW')
        
        # Store entropy result
        self.entropy_result = entropy
    
    def calculate_shannon_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Count frequency of each character
        frequency = {}
        for char in data:
            frequency[char] = frequency.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in frequency.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def add_finding(self, location: str, finding_type: str, description: str, severity: str):
        """Add an analysis finding"""
        finding = {
            'location': location,
            'type': finding_type,
            'description': description,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        self.analysis_results.append(finding)
    
    def process_analysis_results(self):
        """Process and display analysis results"""
        if not self.analysis_results:
            self.update_results_tab("Summary", "No cryptographic issues found.")
            self.update_results_tab("Weak Algorithms", "No weak algorithms detected.")
            self.update_results_tab("Key Analysis", "No key-related issues found.")
            self.update_results_tab("Recommendations", "No specific recommendations.")
            return
        
        # Update all tabs
        self.update_summary_tab()
        self.update_weak_algorithms_tab()
        self.update_key_analysis_tab()
        self.update_recommendations_tab()
        
        # Set results data for export
        self.set_results_data({
            'analysis_metadata': {
                'analysis_type': self.analysis_type.get(),
                'timestamp': datetime.now().isoformat(),
                'total_issues': len(self.analysis_results)
            },
            'summary': self.generate_summary_data(),
            'findings': self.analysis_results
        })
    
    def generate_summary_data(self) -> Dict:
        """Generate summary statistics"""
        summary = {
            'total_issues': len(self.analysis_results),
            'by_severity': {},
            'by_type': {}
        }
        
        for result in self.analysis_results:
            # Count by severity
            severity = result['severity']
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # Count by type
            finding_type = result['type']
            summary['by_type'][finding_type] = summary['by_type'].get(finding_type, 0) + 1
        
        return summary
    
    def update_summary_tab(self):
        """Update the summary tab"""
        summary_data = self.generate_summary_data()
        analysis_type = self.analysis_type.get()
        
        summary_text = f"""Cryptographic Analysis Summary
{'='*35}

Analysis Type: {analysis_type.title()}
Analysis Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Issues Found: {summary_data['total_issues']}

Severity Breakdown:
"""
        
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        for severity in severity_order:
            count = summary_data['by_severity'].get(severity, 0)
            if count > 0:
                summary_text += f"  {severity}: {count}\n"
        
        summary_text += "\nIssue Types:\n"
        for issue_type, count in sorted(summary_data['by_type'].items()):
            display_name = issue_type.replace('_', ' ').title()
            summary_text += f"  {display_name}: {count}\n"
        
        # Add specific results based on analysis type
        if analysis_type == "hash" and hasattr(self, 'hash_results'):
            summary_text += f"\nFile Hash Results:\n"
            for algorithm, hash_value in self.hash_results.items():
                summary_text += f"  {algorithm.upper()}: {hash_value}\n"
        
        if analysis_type == "entropy" and hasattr(self, 'entropy_result'):
            summary_text += f"\nEntropy Analysis:\n"
            summary_text += f"  Shannon Entropy: {self.entropy_result:.4f}\n"
            if self.entropy_result < 2.0:
                summary_text += "  Assessment: Low randomness\n"
            elif self.entropy_result > 7.0:
                summary_text += "  Assessment: High randomness\n"
            else:
                summary_text += "  Assessment: Moderate randomness\n"
        
        self.update_results_tab("Summary", summary_text)
    
    def update_weak_algorithms_tab(self):
        """Update the weak algorithms tab"""
        weak_algo_issues = [r for r in self.analysis_results 
                           if 'WEAK' in r['type'] or 'DEPRECATED' in r['type']]
        
        weak_text = f"""Weak Algorithm Analysis
{'='*30}

"""
        
        if weak_algo_issues:
            weak_text += f"Weak/Deprecated Algorithms Found ({len(weak_algo_issues)}):\n\n"
            
            for issue in weak_algo_issues:
                weak_text += f"• {issue['description']}\n"
                weak_text += f"  Location: {issue['location']}\n"
                weak_text += f"  Severity: {issue['severity']}\n"
                weak_text += f"  Type: {issue['type']}\n\n"
        else:
            weak_text += "✅ No weak or deprecated algorithms detected.\n"
        
        weak_text += """
Algorithm Recommendations:

SECURE ALGORITHMS:
• Symmetric: AES-256, ChaCha20
• Asymmetric: RSA-3072+, ECDSA-P256+, Ed25519
• Hashing: SHA-256, SHA-384, SHA-512, BLAKE2

DEPRECATED/WEAK ALGORITHMS TO AVOID:
• Symmetric: DES, 3DES, RC4, Blowfish
• Asymmetric: RSA-1024, DSA-1024
• Hashing: MD5, SHA-1
"""
        
        self.update_results_tab("Weak Algorithms", weak_text)
    
    def update_key_analysis_tab(self):
        """Update the key analysis tab"""
        key_issues = [r for r in self.analysis_results 
                     if 'KEY' in r['type'] or 'CERT' in r['type']]
        
        key_text = f"""Key & Certificate Analysis
{'='*30}

"""
        
        if key_issues:
            key_text += f"Key/Certificate Issues Found ({len(key_issues)}):\n\n"
            
            for issue in key_issues:
                key_text += f"• {issue['description']}\n"
                key_text += f"  Location: {issue['location']}\n"
                key_text += f"  Severity: {issue['severity']}\n\n"
        else:
            key_text += "✅ No key or certificate issues detected.\n"
        
        key_text += """
Key Size Recommendations:

MINIMUM SECURE KEY SIZES:
• RSA: 2048 bits (3072+ recommended)
• DSA: 2048 bits (3072+ recommended)  
• ECDSA: 256 bits (384+ recommended)
• AES: 128 bits (256 recommended)

CERTIFICATE BEST PRACTICES:
• Use SHA-256 or higher for signatures
• Ensure proper hostname validation
• Monitor certificate expiration dates
• Use complete certificate chains
• Implement certificate pinning where appropriate
"""
        
        self.update_results_tab("Key Analysis", key_text)
    
    def update_recommendations_tab(self):
        """Update the recommendations tab"""
        recommendations_text = f"""Cryptographic Recommendations
{'='*35}

Based on the analysis results, here are the recommended actions:

IMMEDIATE ACTIONS:
"""
        
        critical_issues = [r for r in self.analysis_results if r['severity'] == 'CRITICAL']
        high_issues = [r for r in self.analysis_results if r['severity'] == 'HIGH']
        
        if critical_issues:
            recommendations_text += f"\n🚨 Address {len(critical_issues)} CRITICAL issues:\n"
            for issue in critical_issues[:5]:
                recommendations_text += f"  • {issue['description']}\n"
        
        if high_issues:
            recommendations_text += f"\n⚠️  Address {len(high_issues)} HIGH-severity issues:\n"
            for issue in high_issues[:5]:
                recommendations_text += f"  • {issue['description']}\n"
        
        recommendations_text += """

GENERAL CRYPTOGRAPHIC BEST PRACTICES:

1. Algorithm Selection
   • Use modern, well-vetted cryptographic algorithms
   • Avoid deprecated algorithms (MD5, SHA-1, DES, RC4)
   • Regularly review and update cryptographic choices

2. Key Management
   • Use appropriate key sizes for security level required
   • Implement proper key rotation policies
   • Store keys securely (HSMs, key management services)
   • Never hardcode keys in source code

3. Implementation Security
   • Use established cryptographic libraries
   • Avoid implementing crypto primitives yourself
   • Use secure random number generators
   • Implement proper error handling

4. SSL/TLS Configuration
   • Use TLS 1.2 or higher
   • Disable weak cipher suites
   • Implement proper certificate validation
   • Use HSTS and certificate pinning

5. Code Security
   • Regular security code reviews
   • Automated cryptographic scanning
   • Keep cryptographic libraries updated
   • Follow secure coding guidelines

6. Monitoring & Maintenance
   • Monitor certificate expiration dates
   • Regular cryptographic audits
   • Stay informed about cryptographic vulnerabilities
   • Implement crypto-agility for future algorithm changes
"""
        
        self.update_results_tab("Recommendations", recommendations_text)
    
    def stop_analysis(self):
        """Stop the current analysis"""
        if self.is_analyzing:
            self.is_analyzing = False
            self.analyze_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.update_progress(0, "Analysis stopped by user")
            self.status_label.config(text="Analysis stopped")
            messagebox.showinfo("Analysis Stopped", "Analysis has been stopped.")
    
    def export_json(self):
        """Export results as JSON"""
        if not self.analysis_results:
            messagebox.showwarning("No Results", "No analysis results to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            title="Export Cryptographic Analysis Results as JSON"
        )
        
        if filename:
            try:
                export_data = {
                    'analysis_metadata': {
                        'analysis_type': self.analysis_type.get(),
                        'timestamp': datetime.now().isoformat(),
                        'total_issues': len(self.analysis_results)
                    },
                    'summary': self.generate_summary_data(),
                    'findings': self.analysis_results
                }
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
                messagebox.showinfo("Export Successful", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export results:\n{str(e)}")
    
    def export_pdf(self):
        """Export results as PDF (placeholder - would need reportlab)"""
        messagebox.showinfo("PDF Export", 
                          "PDF export functionality would require additional libraries like reportlab. "
                          "Use JSON export for now.")


# Create the ToolFrame class that the main application expects
class ToolFrame(CryptographicAnalyzer):
    """Wrapper class for main application compatibility"""
    pass