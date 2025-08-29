import re
import hashlib
import hmac
import time
import secrets
import logging
from typing import Tuple, Optional, Dict, Any
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.fernet import Fernet
import streamlit as st
from config import Config

logger = logging.getLogger(__name__)

class SecurityValidator:
    """Comprehensive security validation and sanitization"""
    
    # Regex patterns for various attack vectors
    PATTERNS = {
        'sql_injection': [
            r'(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)',
            r'(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\s+.*\b)',
            r'(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\s+.*\b)',
            r'(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\s+.*\b)',
        ],
        'xss': [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'<iframe[^>]*>',
            r'<object[^>]*>',
            r'<embed[^>]*>',
            r'<form[^>]*>',
            r'<input[^>]*>',
            r'<textarea[^>]*>',
            r'<select[^>]*>',
        ],
        'path_traversal': [
            r'\.\./',
            r'\.\.\\',
            r'%2e%2e%2f',
            r'%2e%2e%5c',
            r'..%2f',
            r'..%5c',
        ],
        'command_injection': [
            r'[;&|`$()]',
            r'\b(cat|ls|pwd|whoami|id|uname|wget|curl|nc|netcat|bash|sh|python|perl|ruby)\b',
        ],
        'ldap_injection': [
            r'[()&|!*]',
            r'\b(uid|cn|sn|givenName|mail|objectClass)\b',
        ]
    }
    
    @staticmethod
    def validate_input(input_data: str, input_type: str = 'general') -> Tuple[bool, str]:
        """Validate input data against various attack patterns"""
        if not input_data or not isinstance(input_data, str):
            return False, "Invalid input data"
        
        # Check for null bytes and control characters
        if '\x00' in input_data or any(ord(c) < 32 for c in input_data):
            return False, "Input contains invalid characters"
        
        # Check for various attack patterns
        for attack_type, patterns in SecurityValidator.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, input_data, re.IGNORECASE):
                    logger.warning(f"Potential {attack_type} attack detected in {input_type} input")
                    return False, f"Input contains potentially malicious content ({attack_type})"
        
        # Additional validation based on input type
        if input_type == 'username':
            if not re.match(r'^[a-zA-Z0-9_]{3,20}$', input_data):
                return False, "Username must be 3-20 characters long and contain only letters, numbers, and underscores"
        
        elif input_type == 'password':
            if len(input_data) < 8:
                return False, "Password must be at least 8 characters long"
            if not re.search(r'[A-Z]', input_data):
                return False, "Password must contain at least one uppercase letter"
            if not re.search(r'[a-z]', input_data):
                return False, "Password must contain at least one lowercase letter"
            if not re.search(r'\d', input_data):
                return False, "Password must contain at least one number"
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', input_data):
                return False, "Password must contain at least one special character"
        
        elif input_type == 'filename':
            if len(input_data) > 255:
                return False, "Filename too long"
            if re.search(r'[<>:"/\\|?*]', input_data):
                return False, "Filename contains invalid characters"
        
        return True, "Input validation passed"
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename for safe storage"""
        # Remove or replace dangerous characters
        sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
        # Limit length
        if len(sanitized) > 255:
            name, ext = sanitized.rsplit('.', 1) if '.' in sanitized else (sanitized, '')
            sanitized = name[:255-len(ext)-1] + ('.' + ext if ext else '')
        return sanitized
    
    @staticmethod
    def validate_file_content(file_content: bytes, filename: str) -> Tuple[bool, str]:
        """Validate file content for malicious patterns"""
        if not file_content:
            return False, "Empty file content"
        
        # Check file size
        if len(file_content) > Config.MAX_FILE_SIZE:
            return False, f"File size exceeds maximum allowed size of {Config.MAX_FILE_SIZE // (1024*1024)}MB"
        
        # Check for magic bytes to verify file type
        file_signatures = {
            b'\xff\xd8\xff': 'JPEG',
            b'\x89PNG\r\n\x1a\n': 'PNG',
            b'GIF87a': 'GIF',
            b'GIF89a': 'GIF',
            b'%PDF': 'PDF',
            b'PK\x03\x04': 'ZIP',
            b'PK\x05\x06': 'ZIP',
            b'PK\x07\x08': 'ZIP',
        }
        
        # Check if file content matches expected signature
        expected_extension = filename.lower().split('.')[-1] if '.' in filename else ''
        for signature, file_type in file_signatures.items():
            if file_content.startswith(signature):
                if expected_extension in ['jpg', 'jpeg'] and file_type == 'JPEG':
                    return True, "File validation passed"
                elif expected_extension == 'png' and file_type == 'PNG':
                    return True, "File validation passed"
                elif expected_extension == 'gif' and file_type == 'GIF':
                    return True, "File validation passed"
                elif expected_extension == 'pdf' and file_type == 'PDF':
                    return True, "File validation passed"
                elif expected_extension in ['zip', 'rar'] and file_type == 'ZIP':
                    return True, "File validation passed"
        
        # For text files, check for suspicious content
        if expected_extension in ['txt', 'md', 'py', 'js', 'html', 'css', 'json', 'xml']:
            try:
                text_content = file_content.decode('utf-8')
                # Check for suspicious patterns in text files
                suspicious_patterns = [
                    r'<script',
                    r'javascript:',
                    r'vbscript:',
                    r'data:text/html',
                    r'data:application/x-javascript',
                ]
                for pattern in suspicious_patterns:
                    if re.search(pattern, text_content, re.IGNORECASE):
                        logger.warning(f"Suspicious content detected in text file: {pattern}")
                        return False, f"File contains suspicious content: {pattern}"
            except UnicodeDecodeError:
                return False, "File content is not valid UTF-8 text"
        
        return True, "File validation passed"

class RateLimiter:
    """Rate limiting implementation for API endpoints"""
    
    def __init__(self):
        self.requests = {}
    
    def is_allowed(self, identifier: str) -> bool:
        """Check if request is allowed based on rate limiting"""
        current_time = time.time()
        window_start = current_time - Config.RATE_LIMIT_WINDOW
        
        # Clean old requests
        if identifier in self.requests:
            self.requests[identifier] = [req_time for req_time in self.requests[identifier] 
                                       if req_time > window_start]
        else:
            self.requests[identifier] = []
        
        # Check if request is allowed
        if len(self.requests[identifier]) >= Config.MAX_REQUESTS_PER_WINDOW:
            return False
        
        # Add current request
        self.requests[identifier].append(current_time)
        return True

class SessionManager:
    """Secure session management"""
    
    def __init__(self):
        self.sessions = {}
    
    def create_session(self, user_id: str) -> str:
        """Create a new secure session"""
        session_id = secrets.token_urlsafe(32)
        self.sessions[session_id] = {
            'user_id': user_id,
            'created_at': time.time(),
            'last_activity': time.time()
        }
        return session_id
    
    def validate_session(self, session_id: str) -> Optional[str]:
        """Validate session and return user_id if valid"""
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        current_time = time.time()
        
        # Check session timeout
        if current_time - session['created_at'] > Config.SESSION_TIMEOUT:
            del self.sessions[session_id]
            return None
        
        # Check inactivity timeout
        if current_time - session['last_activity'] > 1800:  # 30 minutes
            del self.sessions[session_id]
            return None
        
        # Update last activity
        session['last_activity'] = current_time
        return session['user_id']
    
    def destroy_session(self, session_id: str):
        """Destroy a session"""
        if session_id in self.sessions:
            del self.sessions[session_id]

# Global instances
security_validator = SecurityValidator()
rate_limiter = RateLimiter()
session_manager = SessionManager()

def check_rate_limit(identifier: str) -> bool:
    """Check rate limit for a given identifier"""
    return rate_limiter.is_allowed(identifier)

def validate_user_input(input_data: str, input_type: str = 'general') -> Tuple[bool, str]:
    """Validate user input using security validator"""
    return security_validator.validate_input(input_data, input_type)

def validate_uploaded_file(file_content: bytes, filename: str) -> Tuple[bool, str]:
    """Validate uploaded file content"""
    return security_validator.validate_file_content(file_content, filename)
