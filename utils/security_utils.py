# security_utils.py - Security utilities framework for ethical validation and secure operations
import os
import json
import hashlib
import logging
import ipaddress
import re
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import socket
import threading

class SecurityUtils:
    """Security utilities for ethical validation, logging, and secure operations"""
    
    def __init__(self, log_file="security_audit.log"):
        self.log_file = log_file
        self.setup_logging()
        self.encryption_key = None
        self.load_or_generate_key()
        
    def setup_logging(self):
        """Setup security audit logging"""
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.logger = logging.getLogger('SecurityAudit')
    
    def load_or_generate_key(self):
        """Load existing encryption key or generate new one"""
        key_file = "security_key.key"
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                self.encryption_key = f.read()
        else:
            self.encryption_key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(self.encryption_key)
            # Secure the key file permissions
            os.chmod(key_file, 0o600)
    
    def validate_target_ethical(self, target: str, operation: str) -> Tuple[bool, str]:
        """Validate if target is ethical for security operations"""
        try:
            # Check if target is localhost or private network
            if self.is_local_or_private_target(target):
                self.log_activity("ETHICAL_CHECK", f"Local/private target approved: {target}", operation)
                return True, "Local or private network target approved"
            
            # Check if target is in whitelist
            if self.is_target_whitelisted(target):
                self.log_activity("ETHICAL_CHECK", f"Whitelisted target approved: {target}", operation)
                return True, "Whitelisted target approved"
            
            # For external targets, require explicit consent
            self.log_activity("ETHICAL_WARNING", f"External target requires consent: {target}", operation)
            return False, "External target requires explicit consent and authorization"
            
        except Exception as e:
            self.log_activity("ETHICAL_ERROR", f"Error validating target {target}: {str(e)}", operation)
            return False, f"Validation error: {str(e)}"
    
    def is_local_or_private_target(self, target: str) -> bool:
        """Check if target is localhost or private network"""
        try:
            # Handle domain names by resolving to IP
            if not self.is_ip_address(target):
                target = socket.gethostbyname(target)
            
            ip = ipaddress.ip_address(target)
            
            # Check for localhost
            if ip.is_loopback:
                return True
            
            # Check for private networks
            if ip.is_private:
                return True
            
            # Check for link-local addresses
            if ip.is_link_local:
                return True
                
            return False
            
        except (socket.gaierror, ipaddress.AddressValueError, ValueError):
            return False
    
    def is_ip_address(self, target: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(target)
            return True
        except ipaddress.AddressValueError:
            return False
    
    def is_target_whitelisted(self, target: str) -> bool:
        """Check if target is in the whitelist"""
        whitelist_file = "security_whitelist.json"
        if not os.path.exists(whitelist_file):
            return False
        
        try:
            with open(whitelist_file, 'r') as f:
                whitelist = json.load(f)
            
            return target in whitelist.get('approved_targets', [])
        except (json.JSONDecodeError, KeyError):
            return False
    
    def add_to_whitelist(self, target: str, reason: str = ""):
        """Add target to security whitelist"""
        whitelist_file = "security_whitelist.json"
        
        # Load existing whitelist or create new
        if os.path.exists(whitelist_file):
            with open(whitelist_file, 'r') as f:
                whitelist = json.load(f)
        else:
            whitelist = {"approved_targets": [], "entries": {}}
        
        # Add target
        if target not in whitelist["approved_targets"]:
            whitelist["approved_targets"].append(target)
            whitelist["entries"][target] = {
                "added_date": datetime.now().isoformat(),
                "reason": reason
            }
        
        # Save whitelist
        with open(whitelist_file, 'w') as f:
            json.dump(whitelist, f, indent=2)
        
        self.log_activity("WHITELIST_ADD", f"Added {target} to whitelist: {reason}")
    
    def log_activity(self, action: str, details: str, operation: str = "", user: str = "system"):
        """Log security-related activities"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "operation": operation,
            "user": user,
            "details": details,
            "source_ip": self.get_local_ip()
        }
        
        self.logger.info(json.dumps(log_entry))
    
    def get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            # Connect to a remote address to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data like API keys"""
        if not self.encryption_key:
            raise ValueError("Encryption key not available")
        
        fernet = Fernet(self.encryption_key)
        encrypted_data = fernet.encrypt(data.encode())
        return base64.b64encode(encrypted_data).decode()
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if not self.encryption_key:
            raise ValueError("Encryption key not available")
        
        fernet = Fernet(self.encryption_key)
        decoded_data = base64.b64decode(encrypted_data.encode())
        decrypted_data = fernet.decrypt(decoded_data)
        return decrypted_data.decode()
    
    def store_api_key(self, service_name: str, api_key: str):
        """Securely store API key"""
        encrypted_key = self.encrypt_sensitive_data(api_key)
        
        keys_file = "encrypted_keys.json"
        if os.path.exists(keys_file):
            with open(keys_file, 'r') as f:
                keys_data = json.load(f)
        else:
            keys_data = {}
        
        keys_data[service_name] = {
            "encrypted_key": encrypted_key,
            "stored_date": datetime.now().isoformat()
        }
        
        with open(keys_file, 'w') as f:
            json.dump(keys_data, f, indent=2)
        
        # Secure file permissions
        os.chmod(keys_file, 0o600)
        
        self.log_activity("API_KEY_STORED", f"API key stored for service: {service_name}")
    
    def retrieve_api_key(self, service_name: str) -> Optional[str]:
        """Retrieve and decrypt API key"""
        keys_file = "encrypted_keys.json"
        if not os.path.exists(keys_file):
            return None
        
        try:
            with open(keys_file, 'r') as f:
                keys_data = json.load(f)
            
            if service_name in keys_data:
                encrypted_key = keys_data[service_name]["encrypted_key"]
                decrypted_key = self.decrypt_sensitive_data(encrypted_key)
                self.log_activity("API_KEY_RETRIEVED", f"API key retrieved for service: {service_name}")
                return decrypted_key
            
        except (json.JSONDecodeError, KeyError, Exception) as e:
            self.log_activity("API_KEY_ERROR", f"Error retrieving key for {service_name}: {str(e)}")
        
        return None
    
    def validate_input_safety(self, input_data: str, operation: str) -> Tuple[bool, str]:
        """Validate input for potential security risks"""
        # Check for common injection patterns
        dangerous_patterns = [
            r'[;&|`$]',  # Command injection
            r'<script.*?>',  # XSS
            r'union.*select',  # SQL injection
            r'\.\./',  # Path traversal
            r'exec\s*\(',  # Code execution
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                self.log_activity("INPUT_VALIDATION_FAILED", 
                                f"Dangerous pattern detected in {operation}: {pattern}", operation)
                return False, f"Potentially dangerous input pattern detected: {pattern}"
        
        return True, "Input validation passed"
    
    def rate_limit_check(self, operation: str, max_requests: int = 10, 
                        time_window: int = 60) -> Tuple[bool, str]:
        """Check rate limiting for operations"""
        rate_limit_file = "rate_limits.json"
        current_time = datetime.now().timestamp()
        
        # Load existing rate limit data
        if os.path.exists(rate_limit_file):
            with open(rate_limit_file, 'r') as f:
                rate_data = json.load(f)
        else:
            rate_data = {}
        
        # Clean old entries
        if operation in rate_data:
            rate_data[operation] = [
                timestamp for timestamp in rate_data[operation]
                if current_time - timestamp < time_window
            ]
        else:
            rate_data[operation] = []
        
        # Check if limit exceeded
        if len(rate_data[operation]) >= max_requests:
            self.log_activity("RATE_LIMIT_EXCEEDED", 
                            f"Rate limit exceeded for {operation}: {len(rate_data[operation])}/{max_requests}")
            return False, f"Rate limit exceeded: {len(rate_data[operation])}/{max_requests} requests in {time_window}s"
        
        # Add current request
        rate_data[operation].append(current_time)
        
        # Save rate limit data
        with open(rate_limit_file, 'w') as f:
            json.dump(rate_data, f)
        
        return True, "Rate limit check passed"
    
    def get_security_audit_log(self, limit: int = 100) -> List[Dict]:
        """Retrieve recent security audit log entries"""
        try:
            with open(self.log_file, 'r') as f:
                lines = f.readlines()
            
            # Get last 'limit' lines
            recent_lines = lines[-limit:] if len(lines) > limit else lines
            
            audit_entries = []
            for line in recent_lines:
                try:
                    # Parse log line to extract JSON
                    json_start = line.find('{')
                    if json_start != -1:
                        json_data = json.loads(line[json_start:].strip())
                        audit_entries.append(json_data)
                except json.JSONDecodeError:
                    continue
            
            return audit_entries
            
        except FileNotFoundError:
            return []
    
    def generate_security_report(self) -> Dict:
        """Generate security activity report"""
        audit_log = self.get_security_audit_log(1000)  # Last 1000 entries
        
        report = {
            "report_generated": datetime.now().isoformat(),
            "total_activities": len(audit_log),
            "activity_summary": {},
            "recent_warnings": [],
            "rate_limit_violations": 0,
            "ethical_violations": 0
        }
        
        # Analyze activities
        for entry in audit_log:
            action = entry.get("action", "UNKNOWN")
            report["activity_summary"][action] = report["activity_summary"].get(action, 0) + 1
            
            if "WARNING" in action or "ERROR" in action:
                report["recent_warnings"].append(entry)
            
            if "RATE_LIMIT_EXCEEDED" in action:
                report["rate_limit_violations"] += 1
            
            if "ETHICAL" in action and ("WARNING" in action or "ERROR" in action):
                report["ethical_violations"] += 1
        
        return report


class SecurityToolBase:
    """Base class for security tools with ethical validation and logging"""
    
    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        self.security_utils = SecurityUtils()
        self.is_authorized = False
        
    def validate_and_authorize(self, target: str, operation: str) -> bool:
        """Validate target and get authorization for security operation"""
        # Ethical validation
        is_ethical, message = self.security_utils.validate_target_ethical(target, operation)
        if not is_ethical:
            self.security_utils.log_activity("AUTHORIZATION_DENIED", 
                                           f"Ethical validation failed for {target}: {message}", 
                                           f"{self.tool_name}:{operation}")
            return False
        
        # Rate limiting
        is_within_limit, limit_message = self.security_utils.rate_limit_check(
            f"{self.tool_name}:{operation}"
        )
        if not is_within_limit:
            return False
        
        # Log authorization
        self.security_utils.log_activity("AUTHORIZATION_GRANTED", 
                                       f"Security operation authorized for {target}", 
                                       f"{self.tool_name}:{operation}")
        self.is_authorized = True
        return True
    
    def log_security_activity(self, action: str, details: str, target: str = ""):
        """Log security tool activity"""
        full_details = f"Tool: {self.tool_name}, Target: {target}, Details: {details}"
        self.security_utils.log_activity(action, full_details, self.tool_name)
    
    def require_authorization(func):
        """Decorator to require authorization before executing security operations"""
        def wrapper(self, *args, **kwargs):
            if not self.is_authorized:
                raise PermissionError("Security operation not authorized. Call validate_and_authorize() first.")
            return func(self, *args, **kwargs)
        return wrapper


# Global security utilities instance
security_utils = SecurityUtils()