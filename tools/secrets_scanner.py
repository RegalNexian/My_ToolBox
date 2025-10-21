# tools/secrets_scanner.py - Secrets Scanner Tool
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import re
import os
import json
import threading
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Set
from base_tool import SecurityToolFrame
from theme import BG_COLOR, TEXT_COLOR, style_button
from utils import ensure_results_subfolder

TAB_NAME = "Secrets Scanner"

class SecretsScanner(SecurityToolFrame):
    """Secrets scanner tool for detecting sensitive information in code repositories"""
    
    def __init__(self, master):
        super().__init__(master, {
            'name': 'Secrets Scanner',
            'tool_id': 'secrets_scanner',
            'category': 'Security'
        })
        
        ensure_results_subfolder("Secrets_Scanner")
        
        # Initialize variables
        self.scan_results = []
        self.scan_thread = None
        self.is_scanning = False
        self.total_files = 0
        self.scanned_files = 0
        
        # Setup security framework
        self.setup_security_framework()
        
        # Secret patterns for detection
        self.secret_patterns = self.initialize_secret_patterns()
        
        # Build UI
        self.setup_ui()
    
    def initialize_secret_patterns(self) -> Dict[str, Dict]:
        """Initialize patterns for detecting various types of secrets"""
        return {
            'api_keys': {
                'patterns': [
                    r'(?i)api[_-]?key[_-]?[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                    r'(?i)apikey[_-]?[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                    r'(?i)key[_-]?[:=]\s*["\']?([a-zA-Z0-9_-]{32,})["\']?'
                ],
                'severity': 'HIGH',
                'description': 'API Key detected'
            },
            'passwords': {
                'patterns': [
                    r'(?i)password[_-]?[:=]\s*["\']([^"\']{8,})["\']',
                    r'(?i)passwd[_-]?[:=]\s*["\']([^"\']{8,})["\']',
                    r'(?i)pwd[_-]?[:=]\s*["\']([^"\']{8,})["\']'
                ],
                'severity': 'HIGH',
                'description': 'Password detected'
            },
            'tokens': {
                'patterns': [
                    r'(?i)token[_-]?[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                    r'(?i)access[_-]?token[_-]?[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                    r'(?i)auth[_-]?token[_-]?[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?'
                ],
                'severity': 'HIGH',
                'description': 'Authentication token detected'
            },
            'aws_keys': {
                'patterns': [
                    r'AKIA[0-9A-Z]{16}',
                    r'(?i)aws[_-]?access[_-]?key[_-]?id[_-]?[:=]\s*["\']?(AKIA[0-9A-Z]{16})["\']?',
                    r'(?i)aws[_-]?secret[_-]?access[_-]?key[_-]?[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?'
                ],
                'severity': 'CRITICAL',
                'description': 'AWS credentials detected'
            },
            'github_tokens': {
                'patterns': [
                    r'ghp_[a-zA-Z0-9]{36}',
                    r'gho_[a-zA-Z0-9]{36}',
                    r'ghu_[a-zA-Z0-9]{36}',
                    r'ghs_[a-zA-Z0-9]{36}'
                ],
                'severity': 'CRITICAL',
                'description': 'GitHub token detected'
            },
            'private_keys': {
                'patterns': [
                    r'-----BEGIN PRIVATE KEY-----',
                    r'-----BEGIN RSA PRIVATE KEY-----',
                    r'-----BEGIN DSA PRIVATE KEY-----',
                    r'-----BEGIN EC PRIVATE KEY-----'
                ],
                'severity': 'CRITICAL',
                'description': 'Private key detected'
            },
            'certificates': {
                'patterns': [
                    r'-----BEGIN CERTIFICATE-----',
                    r'-----BEGIN PUBLIC KEY-----'
                ],
                'severity': 'MEDIUM',
                'description': 'Certificate detected'
            },
            'database_urls': {
                'patterns': [
                    r'(?i)mongodb://[^\s]+',
                    r'(?i)mysql://[^\s]+',
                    r'(?i)postgresql://[^\s]+',
                    r'(?i)redis://[^\s]+'
                ],
                'severity': 'HIGH',
                'description': 'Database connection string detected'
            },
            'jwt_tokens': {
                'patterns': [
                    r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
                ],
                'severity': 'HIGH',
                'description': 'JWT token detected'
            },
            'slack_tokens': {
                'patterns': [
                    r'xox[baprs]-[0-9a-zA-Z-]+'
                ],
                'severity': 'HIGH',
                'description': 'Slack token detected'
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
        title_label = tk.Label(left_panel, text="🔍 Secrets Scanner", 
                              bg=BG_COLOR, fg=TEXT_COLOR, 
                              font=("Consolas", 14, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Target selection
        target_frame = tk.LabelFrame(left_panel, text="Scan Target", 
                                   bg=BG_COLOR, fg=TEXT_COLOR)
        target_frame.pack(fill="x", pady=10)
        
        # Directory selection
        tk.Label(target_frame, text="Directory to scan:", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        
        dir_frame = tk.Frame(target_frame, bg=BG_COLOR)
        dir_frame.pack(fill="x", pady=5)
        
        self.directory_entry = tk.Entry(dir_frame, bg="#111111", fg=TEXT_COLOR, 
                                      insertbackground=TEXT_COLOR)
        self.directory_entry.pack(side="left", fill="x", expand=True)
        
        browse_btn = tk.Button(dir_frame, text="Browse", command=self.browse_directory)
        style_button(browse_btn)
        browse_btn.pack(side="right", padx=(5, 0))
        
        # File patterns
        tk.Label(target_frame, text="File patterns (comma-separated):", 
                bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w", pady=(10, 0))
        self.patterns_entry = tk.Entry(target_frame, bg="#111111", fg=TEXT_COLOR,
                                     insertbackground=TEXT_COLOR)
        self.patterns_entry.pack(fill="x", pady=2)
        self.patterns_entry.insert(0, "*.py,*.js,*.json,*.yaml,*.yml,*.env,*.config")
        
        # Scan options
        options_frame = tk.LabelFrame(left_panel, text="Scan Options", 
                                    bg=BG_COLOR, fg=TEXT_COLOR)
        options_frame.pack(fill="x", pady=10)
        
        self.include_comments = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Scan comments", 
                      variable=self.include_comments, bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR).pack(anchor="w")
        
        self.include_strings = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Scan string literals", 
                      variable=self.include_strings, bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR).pack(anchor="w")
        
        self.case_sensitive = tk.BooleanVar(value=False)
        tk.Checkbutton(options_frame, text="Case sensitive matching", 
                      variable=self.case_sensitive, bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR).pack(anchor="w")
        
        self.exclude_test_files = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Exclude test files", 
                      variable=self.exclude_test_files, bg=BG_COLOR, fg=TEXT_COLOR,
                      selectcolor=BG_COLOR).pack(anchor="w")
        
        # Secret types selection
        types_frame = tk.LabelFrame(left_panel, text="Secret Types to Detect", 
                                  bg=BG_COLOR, fg=TEXT_COLOR)
        types_frame.pack(fill="x", pady=10)
        
        self.secret_type_vars = {}
        for secret_type, config in self.secret_patterns.items():
            var = tk.BooleanVar(value=True)
            self.secret_type_vars[secret_type] = var
            display_name = secret_type.replace('_', ' ').title()
            tk.Checkbutton(types_frame, text=f"{display_name} ({config['severity']})", 
                          variable=var, bg=BG_COLOR, fg=TEXT_COLOR,
                          selectcolor=BG_COLOR).pack(anchor="w")
        
        # Control buttons
        button_frame = tk.Frame(left_panel, bg=BG_COLOR)
        button_frame.pack(fill="x", pady=20)
        
        self.scan_button = tk.Button(button_frame, text="Start Scan", 
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
        
        csv_btn = tk.Button(export_btn_frame, text="CSV", command=self.export_csv)
        style_button(csv_btn)
        csv_btn.pack(side="left", padx=5)
        
        # Right panel for results
        right_panel = tk.Frame(main_frame, bg=BG_COLOR)
        right_panel.pack(side="right", fill="both", expand=True)
        
        # Progress bar
        self.add_progress_bar("Secrets Scan Progress")
        
        # Results viewer with tabs
        self.add_results_viewer(["Summary", "Findings", "Risk Assessment", "Remediation"])
        
        # Status label
        self.status_label = tk.Label(right_panel, text="Ready", 
                                   bg=BG_COLOR, fg=TEXT_COLOR)
        self.status_label.pack(pady=5)
    
    def browse_directory(self):
        """Browse for directory to scan"""
        directory = filedialog.askdirectory(title="Select Directory to Scan")
        if directory:
            self.directory_entry.delete(0, tk.END)
            self.directory_entry.insert(0, directory)
    
    def start_scan(self):
        """Start the secrets scanning process"""
        if self.is_scanning:
            messagebox.showwarning("Scan in Progress", "A scan is already running.")
            return
        
        directory = self.directory_entry.get().strip()
        if not directory or not os.path.exists(directory):
            messagebox.showerror("Invalid Directory", "Please select a valid directory to scan.")
            return
        
        # Get selected secret types
        selected_types = [secret_type for secret_type, var in self.secret_type_vars.items() 
                         if var.get()]
        
        if not selected_types:
            messagebox.showerror("No Secret Types", "Please select at least one secret type to detect.")
            return
        
        # Start scan in separate thread
        self.is_scanning = True
        self.scan_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.scan_results = []
        self.update_progress(0, "Starting scan...")
        
        self.scan_thread = threading.Thread(target=self.run_scan, args=(directory, selected_types))
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        # Log the scan start
        self.log_security_activity("SECRETS_SCAN_STARTED", f"Secrets scan started on directory: {directory}")
    
    def run_scan(self, directory: str, selected_types: List[str]):
        """Run the actual secrets scan"""
        try:
            # Get file patterns
            patterns = [p.strip() for p in self.patterns_entry.get().split(',') if p.strip()]
            if not patterns:
                patterns = ['*']
            
            # Find files to scan
            files_to_scan = self.find_files_to_scan(directory, patterns)
            self.total_files = len(files_to_scan)
            self.scanned_files = 0
            
            if self.total_files == 0:
                self.update_progress(100, "No files found to scan")
                self.status_label.config(text="No files found")
                return
            
            self.update_progress(10, f"Found {self.total_files} files to scan")
            
            # Scan each file
            for file_path in files_to_scan:
                if not self.is_scanning:  # Check if scan was stopped
                    break
                
                self.scan_file(file_path, selected_types)
                self.scanned_files += 1
                
                progress = 10 + (self.scanned_files / self.total_files) * 80
                self.update_progress(progress, f"Scanned {self.scanned_files}/{self.total_files} files")
            
            if self.is_scanning:  # Only update if scan wasn't stopped
                self.update_progress(100, "Scan completed")
                self.process_scan_results()
                self.status_label.config(text=f"Scan completed - {len(self.scan_results)} secrets found")
            
        except Exception as e:
            self.update_progress(0, f"Error: {str(e)}")
            self.status_label.config(text=f"Error: {str(e)}")
            messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{str(e)}")
        
        finally:
            self.is_scanning = False
            self.scan_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.log_security_activity("SECRETS_SCAN_COMPLETED", 
                                     f"Secrets scan completed - {len(self.scan_results)} secrets found")
    
    def find_files_to_scan(self, directory: str, patterns: List[str]) -> List[str]:
        """Find files matching the specified patterns"""
        import fnmatch
        
        files_to_scan = []
        exclude_patterns = []
        
        if self.exclude_test_files.get():
            exclude_patterns = ['*test*', '*spec*', '*__pycache__*', '*.pyc', 
                              'node_modules/*', '.git/*', '.venv/*', 'venv/*']
        
        for root, dirs, files in os.walk(directory):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if not any(fnmatch.fnmatch(d, pattern) 
                                                 for pattern in exclude_patterns)]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                # Check if file matches any pattern
                if any(fnmatch.fnmatch(file, pattern) for pattern in patterns):
                    # Check if file should be excluded
                    if not any(fnmatch.fnmatch(file_path, pattern) for pattern in exclude_patterns):
                        files_to_scan.append(file_path)
        
        return files_to_scan
    
    def scan_file(self, file_path: str, selected_types: List[str]):
        """Scan a single file for secrets"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Scan for each selected secret type
            for secret_type in selected_types:
                if secret_type not in self.secret_patterns:
                    continue
                
                config = self.secret_patterns[secret_type]
                
                for pattern in config['patterns']:
                    flags = 0 if self.case_sensitive.get() else re.IGNORECASE
                    matches = re.finditer(pattern, content, flags)
                    
                    for match in matches:
                        # Get line number
                        line_num = content[:match.start()].count('\n') + 1
                        
                        # Get the line content
                        lines = content.split('\n')
                        line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                        
                        # Extract the secret value
                        secret_value = match.group(1) if match.groups() else match.group(0)
                        
                        # Assess risk
                        risk_level = self.assess_risk(secret_type, secret_value, file_path)
                        
                        finding = {
                            'file_path': file_path,
                            'line_number': line_num,
                            'line_content': line_content.strip(),
                            'secret_type': secret_type,
                            'secret_value': secret_value[:20] + "..." if len(secret_value) > 20 else secret_value,
                            'full_secret': secret_value,  # Store full secret for analysis
                            'severity': config['severity'],
                            'risk_level': risk_level,
                            'description': config['description'],
                            'pattern_matched': pattern
                        }
                        
                        self.scan_results.append(finding)
        
        except Exception as e:
            # Log error but continue scanning
            print(f"Error scanning file {file_path}: {e}")
    
    def assess_risk(self, secret_type: str, secret_value: str, file_path: str) -> str:
        """Assess the risk level of a detected secret"""
        risk_factors = []
        
        # Check file location risk
        if any(keyword in file_path.lower() for keyword in ['config', 'env', 'production', 'prod']):
            risk_factors.append("Configuration file")
        
        if any(keyword in file_path.lower() for keyword in ['public', 'www', 'web']):
            risk_factors.append("Public directory")
        
        # Check secret characteristics
        if len(secret_value) > 40:
            risk_factors.append("Long secret")
        
        if secret_type in ['aws_keys', 'github_tokens', 'private_keys']:
            risk_factors.append("High-value credential")
        
        # Determine overall risk
        if len(risk_factors) >= 3 or "High-value credential" in risk_factors:
            return "CRITICAL"
        elif len(risk_factors) >= 2:
            return "HIGH"
        elif len(risk_factors) >= 1:
            return "MEDIUM"
        else:
            return "LOW"
    
    def process_scan_results(self):
        """Process and display scan results"""
        if not self.scan_results:
            self.update_results_tab("Summary", "No secrets found in the scanned files.")
            self.update_results_tab("Findings", "No findings to display.")
            self.update_results_tab("Risk Assessment", "No risks identified.")
            self.update_results_tab("Remediation", "No remediation needed.")
            return
        
        # Update all tabs
        self.update_summary_tab()
        self.update_findings_tab()
        self.update_risk_assessment_tab()
        self.update_remediation_tab()
        
        # Set results data for export
        self.set_results_data({
            'scan_summary': self.generate_summary_data(),
            'findings': self.scan_results,
            'scan_metadata': {
                'total_files_scanned': self.total_files,
                'secrets_found': len(self.scan_results),
                'scan_timestamp': datetime.now().isoformat()
            }
        })
    
    def generate_summary_data(self) -> Dict:
        """Generate summary statistics"""
        summary = {
            'total_secrets': len(self.scan_results),
            'by_severity': {},
            'by_type': {},
            'by_risk': {},
            'files_affected': len(set(result['file_path'] for result in self.scan_results))
        }
        
        for result in self.scan_results:
            # Count by severity
            severity = result['severity']
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # Count by type
            secret_type = result['secret_type']
            summary['by_type'][secret_type] = summary['by_type'].get(secret_type, 0) + 1
            
            # Count by risk
            risk = result['risk_level']
            summary['by_risk'][risk] = summary['by_risk'].get(risk, 0) + 1
        
        return summary
    
    def update_summary_tab(self):
        """Update the summary tab"""
        summary_data = self.generate_summary_data()
        
        summary_text = f"""Secrets Scan Summary
{'='*30}

Total Secrets Found: {summary_data['total_secrets']}
Files Affected: {summary_data['files_affected']}
Total Files Scanned: {self.total_files}

By Severity:
"""
        for severity, count in sorted(summary_data['by_severity'].items()):
            summary_text += f"  {severity}: {count}\n"
        
        summary_text += "\nBy Secret Type:\n"
        for secret_type, count in sorted(summary_data['by_type'].items()):
            display_name = secret_type.replace('_', ' ').title()
            summary_text += f"  {display_name}: {count}\n"
        
        summary_text += "\nBy Risk Level:\n"
        for risk, count in sorted(summary_data['by_risk'].items()):
            summary_text += f"  {risk}: {count}\n"
        
        self.update_results_tab("Summary", summary_text)
    
    def update_findings_tab(self):
        """Update the findings tab with detailed results"""
        findings_text = f"""Detailed Findings
{'='*20}

"""
        
        # Group findings by file
        files_with_secrets = {}
        for result in self.scan_results:
            file_path = result['file_path']
            if file_path not in files_with_secrets:
                files_with_secrets[file_path] = []
            files_with_secrets[file_path].append(result)
        
        for file_path, findings in files_with_secrets.items():
            findings_text += f"\nFile: {file_path}\n"
            findings_text += f"{'─' * 50}\n"
            
            for finding in findings:
                findings_text += f"  Line {finding['line_number']}: {finding['description']}\n"
                findings_text += f"    Type: {finding['secret_type'].replace('_', ' ').title()}\n"
                findings_text += f"    Severity: {finding['severity']}\n"
                findings_text += f"    Risk: {finding['risk_level']}\n"
                findings_text += f"    Value: {finding['secret_value']}\n"
                findings_text += f"    Context: {finding['line_content'][:100]}...\n\n"
        
        self.update_results_tab("Findings", findings_text)
    
    def update_risk_assessment_tab(self):
        """Update the risk assessment tab"""
        risk_text = f"""Risk Assessment
{'='*20}

"""
        
        # Analyze risks
        critical_risks = [r for r in self.scan_results if r['risk_level'] == 'CRITICAL']
        high_risks = [r for r in self.scan_results if r['risk_level'] == 'HIGH']
        
        if critical_risks:
            risk_text += f"🚨 CRITICAL RISKS ({len(critical_risks)}):\n"
            for risk in critical_risks[:5]:  # Show top 5
                risk_text += f"  • {risk['description']} in {os.path.basename(risk['file_path'])}\n"
            if len(critical_risks) > 5:
                risk_text += f"  ... and {len(critical_risks) - 5} more\n"
            risk_text += "\n"
        
        if high_risks:
            risk_text += f"⚠️  HIGH RISKS ({len(high_risks)}):\n"
            for risk in high_risks[:5]:  # Show top 5
                risk_text += f"  • {risk['description']} in {os.path.basename(risk['file_path'])}\n"
            if len(high_risks) > 5:
                risk_text += f"  ... and {len(high_risks) - 5} more\n"
            risk_text += "\n"
        
        # Risk factors analysis
        risk_text += "Risk Factors Analysis:\n"
        config_files = len([r for r in self.scan_results if 'config' in r['file_path'].lower()])
        if config_files > 0:
            risk_text += f"  • {config_files} secrets found in configuration files\n"
        
        public_files = len([r for r in self.scan_results if any(keyword in r['file_path'].lower() 
                                                              for keyword in ['public', 'www', 'web'])])
        if public_files > 0:
            risk_text += f"  • {public_files} secrets found in potentially public directories\n"
        
        high_value_creds = len([r for r in self.scan_results if r['secret_type'] in 
                               ['aws_keys', 'github_tokens', 'private_keys']])
        if high_value_creds > 0:
            risk_text += f"  • {high_value_creds} high-value credentials detected\n"
        
        self.update_results_tab("Risk Assessment", risk_text)
    
    def update_remediation_tab(self):
        """Update the remediation tab with guidance"""
        remediation_text = f"""Remediation Guidance
{'='*25}

Immediate Actions Required:

1. ROTATE CREDENTIALS
   • Immediately rotate any exposed API keys, tokens, or passwords
   • Update applications to use new credentials
   • Monitor for unauthorized access using old credentials

2. REMOVE SECRETS FROM CODE
   • Remove hardcoded secrets from source code
   • Use environment variables or secure configuration management
   • Add secrets to .gitignore to prevent future commits

3. IMPLEMENT SECURE PRACTICES
   • Use secret management tools (HashiCorp Vault, AWS Secrets Manager)
   • Implement proper access controls and encryption
   • Regular security audits and automated scanning

Specific Recommendations by Secret Type:

"""
        
        # Generate specific recommendations based on found secret types
        secret_types_found = set(result['secret_type'] for result in self.scan_results)
        
        recommendations = {
            'api_keys': "• Store API keys in environment variables or secure vaults\n• Use API key rotation policies\n• Implement rate limiting and monitoring",
            'passwords': "• Use strong, unique passwords\n• Implement password hashing (bcrypt, Argon2)\n• Never store passwords in plain text",
            'tokens': "• Use short-lived tokens with refresh mechanisms\n• Implement token revocation capabilities\n• Store tokens securely with encryption",
            'aws_keys': "• Use IAM roles instead of access keys when possible\n• Implement least privilege access\n• Enable CloudTrail logging and monitoring",
            'github_tokens': "• Use fine-grained personal access tokens\n• Regularly audit and rotate tokens\n• Enable two-factor authentication",
            'private_keys': "• Store private keys in secure key management systems\n• Use proper file permissions (600)\n• Consider using hardware security modules (HSMs)",
            'database_urls': "• Use connection pooling with secure credentials\n• Implement database access controls\n• Use SSL/TLS for database connections"
        }
        
        for secret_type in secret_types_found:
            if secret_type in recommendations:
                display_name = secret_type.replace('_', ' ').title()
                remediation_text += f"{display_name}:\n{recommendations[secret_type]}\n\n"
        
        remediation_text += """
Prevention Measures:

• Implement pre-commit hooks to scan for secrets
• Use automated security scanning in CI/CD pipelines
• Provide security training for development teams
• Establish incident response procedures for exposed secrets
• Regular security audits and penetration testing
"""
        
        self.update_results_tab("Remediation", remediation_text)
    
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
            title="Export Secrets Scan Results as JSON"
        )
        
        if filename:
            try:
                export_data = {
                    'scan_metadata': {
                        'total_files_scanned': self.total_files,
                        'secrets_found': len(self.scan_results),
                        'scan_timestamp': datetime.now().isoformat(),
                        'scan_directory': self.directory_entry.get()
                    },
                    'summary': self.generate_summary_data(),
                    'findings': self.scan_results
                }
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
                messagebox.showinfo("Export Successful", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export results:\n{str(e)}")
    
    def export_csv(self):
        """Export results as CSV"""
        if not self.scan_results:
            messagebox.showwarning("No Results", "No scan results to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Export Secrets Scan Results as CSV"
        )
        
        if filename:
            try:
                import csv
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    
                    # Write header
                    writer.writerow(['File Path', 'Line Number', 'Secret Type', 'Severity', 
                                   'Risk Level', 'Description', 'Secret Value', 'Line Content'])
                    
                    # Write data
                    for result in self.scan_results:
                        writer.writerow([
                            result['file_path'],
                            result['line_number'],
                            result['secret_type'],
                            result['severity'],
                            result['risk_level'],
                            result['description'],
                            result['secret_value'],
                            result['line_content']
                        ])
                
                messagebox.showinfo("Export Successful", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export results:\n{str(e)}")


# Create the ToolFrame class that the main application expects
class ToolFrame(SecretsScanner):
    """Wrapper class for main application compatibility"""
    pass
        