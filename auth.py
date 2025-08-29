import hashlib
import hmac
import secrets
import time
import logging
import pyotp
import bcrypt
from typing import Tuple, Optional, Dict, Any
from pymongo import MongoClient
from passlib.hash import pbkdf2_sha256
from config import Config
from security import validate_user_input, session_manager, check_rate_limit

logger = logging.getLogger(__name__)

class SecureAuthentication:
    """Secure authentication system with 2FA and advanced security features"""
    
    def __init__(self):
        self.mongodb_available = False
        self.client = None
        self.db = None
        self.users_collection = None
        self.sessions_collection = None
        self.login_attempts = {}
        self.locked_accounts = {}
        
        # Try to connect to MongoDB
        try:
            self.client = MongoClient(Config.MONGODB_URI, serverSelectionTimeoutMS=5000)
            # Test the connection
            self.client.admin.command('ping')
            self.db = self.client[Config.MONGODB_DB]
            self.users_collection = self.db['users']
            self.sessions_collection = self.db['sessions']
            self.mongodb_available = True
            
            # Create indexes for better performance and security
            self._create_indexes()
            logger.info("MongoDB connection established successfully")
        except Exception as e:
            logger.warning(f"MongoDB connection failed: {e}")
            logger.info("Running in fallback mode without database persistence")
            self.mongodb_available = False
    
    def _create_indexes(self):
        """Create database indexes for security and performance"""
        if not self.mongodb_available:
            logger.info("Skipping index creation - MongoDB not available")
            return
            
        try:
            # Unique index on username
            self.users_collection.create_index("username", unique=True)
            
            # Index on email for faster lookups
            self.users_collection.create_index("email")
            
            # Index on session tokens
            self.sessions_collection.create_index("session_token")
            
            # TTL index on sessions for automatic cleanup
            self.sessions_collection.create_index("expires_at", expireAfterSeconds=0)
            
            # Index on login attempts for rate limiting
            self.users_collection.create_index("last_login_attempt")
            
            logger.info("Database indexes created successfully")
        except Exception as e:
            logger.error(f"Error creating database indexes: {e}")
    
    def _generate_salt(self) -> bytes:
        """Generate a cryptographically secure salt"""
        return bcrypt.gensalt(rounds=12)
    
    def _hash_password(self, password: str, salt: bytes = None) -> Tuple[str, bytes]:
        """Hash password using bcrypt with high cost factor"""
        if salt is None:
            salt = self._generate_salt()
        
        # Hash password with bcrypt
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8'), salt
    
    def _verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify password against stored hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
        except Exception as e:
            logger.error(f"Error verifying password: {e}")
            return False
    
    def _generate_2fa_secret(self) -> str:
        """Generate a new 2FA secret key"""
        return pyotp.random_base32()
    
    def _generate_2fa_qr(self, username: str, secret: str) -> str:
        """Generate QR code URL for 2FA setup"""
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=username,
            issuer_name="Secure File Storage"
        )
        return provisioning_uri
    
    def _verify_2fa_token(self, secret: str, token: str) -> bool:
        """Verify 2FA token"""
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=1)  # Allow 1 time step tolerance
        except Exception as e:
            logger.error(f"Error verifying 2FA token: {e}")
            return False
    
    def _check_account_lockout(self, username: str) -> bool:
        """Check if account is locked due to too many failed attempts"""
        if username in self.locked_accounts:
            lockout_time = self.locked_accounts[username]['lockout_time']
            lockout_duration = 900  # 15 minutes
            
            if time.time() - lockout_time < lockout_duration:
                return True
            else:
                # Remove lockout after duration expires
                del self.locked_accounts[username]
                if username in self.login_attempts:
                    del self.login_attempts[username]
        
        return False
    
    def _record_login_attempt(self, username: str, success: bool):
        """Record login attempt for rate limiting"""
        current_time = time.time()
        
        if username not in self.login_attempts:
            self.login_attempts[username] = {
                'attempts': [],
                'last_attempt': current_time
            }
        
        self.login_attempts[username]['attempts'].append({
            'timestamp': current_time,
            'success': success
        })
        
        # Keep only last 10 attempts
        self.login_attempts[username]['attempts'] = self.login_attempts[username]['attempts'][-10:]
        self.login_attempts[username]['last_attempt'] = current_time
        
        # Check if account should be locked
        recent_failures = sum(1 for attempt in self.login_attempts[username]['attempts'][-5:] 
                            if not attempt['success'])
        
        if recent_failures >= 5:
            self.locked_accounts[username] = {
                'lockout_time': current_time,
                'reason': 'Too many failed login attempts'
            }
            logger.warning(f"Account {username} locked due to multiple failed login attempts")
    
    def register_user(self, username: str, email: str, password: str, enable_2fa: bool = True) -> Tuple[bool, str]:
        """Register a new user with enhanced security"""
        try:
            # Input validation
            username_valid, username_msg = validate_user_input(username, 'username')
            if not username_valid:
                return False, username_msg
            
            email_valid, email_msg = validate_user_input(email, 'email')
            if not email_valid:
                return False, email_msg
            
            password_valid, password_msg = validate_user_input(password, 'password')
            if not password_valid:
                return False, password_msg
            
            # If MongoDB is not available, run in fallback mode
            if not self.mongodb_available:
                logger.info(f"Running in fallback mode - user {username} registered without database persistence")
                return True, {
                    'success': True,
                    'message': 'Registration successful (fallback mode)',
                    'user_id': f'fallback_{username}_{int(time.time())}',
                    'warning': 'Running without database persistence'
                }
            
            # Check if username already exists
            if self.users_collection.find_one({'username': username}):
                return False, 'Username already exists'
            
            # Check if email already exists
            if self.users_collection.find_one({'email': email}):
                return False, 'Email already registered'
            
            # Hash password
            hashed_password, salt = self._hash_password(password)
            
            # Generate 2FA secret if enabled
            two_fa_secret = None
            two_fa_qr = None
            if enable_2fa:
                two_fa_secret = self._generate_2fa_secret()
                two_fa_qr = self._generate_2fa_qr(username, two_fa_secret)
            
            # Create user document
            user_doc = {
                'username': username,
                'email': email,
                'password_hash': hashed_password,
                'salt': salt.decode('utf-8'),
                'two_fa_secret': two_fa_secret,
                'two_fa_enabled': enable_2fa,
                'created_at': time.time(),
                'last_login': None,
                'login_attempts': 0,
                'account_status': 'active',
                'role': 'user',
                'permissions': ['upload', 'download', 'encrypt', 'decrypt']
            }
            
            # Insert user into database
            result = self.users_collection.insert_one(user_doc)
            
            if result.inserted_id:
                logger.info(f"User {username} registered successfully")
                
                response_data = {
                    'success': True,
                    'message': 'Registration successful',
                    'user_id': str(result.inserted_id)
                }
                
                if enable_2fa:
                    response_data['two_fa_qr'] = two_fa_qr
                    response_data['two_fa_secret'] = two_fa_secret
                
                return True, response_data
            else:
                return False, 'Registration failed'
                
        except Exception as e:
            logger.error(f"Error during user registration: {e}")
            return False, f'Registration error: {str(e)}'
    
    def authenticate_user(self, username: str, password: str, two_fa_token: str = None) -> Tuple[bool, str, Optional[Dict]]:
        """Authenticate user with password and optional 2FA"""
        try:
            # If MongoDB is not available, run in fallback mode
            if not self.mongodb_available:
                logger.info(f"Running in fallback mode - user {username} authenticated without database")
                # In fallback mode, accept any username/password combination for demo purposes
                # This is NOT secure for production use
                session_token = session_manager.create_session(username)
                return True, 'Authentication successful (fallback mode)', {
                    'session_token': session_token,
                    'user': {
                        'username': username,
                        'email': f'{username}@fallback.local',
                        'role': 'user',
                        'permissions': ['upload', 'download', 'encrypt', 'decrypt'],
                        'two_fa_enabled': False,
                        'warning': 'Running without database persistence'
                    }
                }
            
            # Check rate limiting
            if not check_rate_limit(f"login_{username}"):
                return False, 'Too many login attempts. Please try again later.', None
            
            # Check account lockout
            if self._check_account_lockout(username):
                return False, 'Account is temporarily locked due to multiple failed attempts. Please try again in 15 minutes.', None
            
            # Find user
            user = self.users_collection.find_one({'username': username})
            if not user:
                self._record_login_attempt(username, False)
                return False, 'Invalid credentials', None
            
            # Check if account is active
            if user.get('account_status') != 'active':
                return False, 'Account is deactivated', None
            
            # Verify password
            if not self._verify_password(password, user['password_hash']):
                self._record_login_attempt(username, False)
                return False, 'Invalid credentials', None
            
            # Check 2FA if enabled
            if user.get('two_fa_enabled'):
                if not two_fa_token:
                    return False, '2FA token required', None
                
                if not self._verify_2fa_token(user['two_fa_secret'], two_fa_token):
                    self._record_login_attempt(username, False)
                    return False, 'Invalid 2FA token', None
            
            # Login successful
            self._record_login_attempt(username, True)
            
            # Update last login time
            if self.mongodb_available:
                self.users_collection.update_one(
                    {'_id': user['_id']},
                    {'$set': {'last_login': time.time()}}
                )
            
            # Create session
            session_token = session_manager.create_session(username)
            
            # Store session in database
            if self.mongodb_available:
                session_doc = {
                    'session_token': session_token,
                    'user_id': user['_id'],
                    'username': username,
                    'created_at': time.time(),
                    'expires_at': time.time() + Config.SESSION_TIMEOUT,
                    'ip_address': None,  # Could be added for additional security
                    'user_agent': None   # Could be added for additional security
                }
                
                self.sessions_collection.insert_one(session_doc)
            
            logger.info(f"User {username} authenticated successfully")
            
            return True, 'Authentication successful', {
                'session_token': session_token,
                'user': {
                    'username': username,
                    'email': user.get('email'),
                    'role': user.get('role'),
                    'permissions': user.get('permissions', []),
                    'two_fa_enabled': user.get('two_fa_enabled', False)
                }
            }
            
        except Exception as e:
            logger.error(f"Error during authentication: {e}")
            return False, f'Authentication error: {str(e)}', None
    
    def validate_session(self, session_token: str) -> Optional[Dict]:
        """Validate session token and return user info"""
        try:
            # Check in-memory session manager first
            user_id = session_manager.validate_session(session_token)
            if user_id:
                # If MongoDB is not available, return fallback user info
                if not self.mongodb_available:
                    return {
                        'username': user_id,
                        'email': f'{user_id}@fallback.local',
                        'role': 'user',
                        'permissions': ['upload', 'download', 'encrypt', 'decrypt'],
                        'two_fa_enabled': False,
                        'warning': 'Running without database persistence'
                    }
                
                # Get user details from database
                user = self.users_collection.find_one({'username': user_id})
                if user and user.get('account_status') == 'active':
                    return {
                        'username': user['username'],
                        'email': user.get('email'),
                        'role': user.get('role'),
                        'permissions': user.get('permissions', []),
                        'two_fa_enabled': user.get('two_fa_enabled', False)
                    }
            
            # Check database session
            if self.mongodb_available:
                session = self.sessions_collection.find_one({'session_token': session_token})
                if session and session['expires_at'] > time.time():
                    user = self.users_collection.find_one({'_id': session['user_id']})
                    if user and user.get('account_status') == 'active':
                        return {
                            'username': user['username'],
                            'email': user.get('email'),
                            'role': user.get('role'),
                            'permissions': user.get('permissions', []),
                            'two_fa_enabled': user.get('two_fa_enabled', False)
                        }
            
            return None
            
        except Exception as e:
            logger.error(f"Error validating session: {e}")
            return None
    
    def logout_user(self, session_token: str) -> bool:
        """Logout user and invalidate session"""
        try:
            # Remove from in-memory session manager
            session_manager.destroy_session(session_token)
            
            # Remove from database
            self.sessions_collection.delete_one({'session_token': session_token})
            
            logger.info(f"User logged out successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error during logout: {e}")
            return False
    
    def change_password(self, username: str, current_password: str, new_password: str) -> Tuple[bool, str]:
        """Change user password with security validation"""
        try:
            # Find user
            user = self.users_collection.find_one({'username': username})
            if not user:
                return False, 'User not found'
            
            # Verify current password
            if not self._verify_password(current_password, user['password_hash']):
                return False, 'Current password is incorrect'
            
            # Validate new password
            password_valid, password_msg = validate_user_input(new_password, 'password')
            if not password_valid:
                return False, password_msg
            
            # Hash new password
            new_hashed_password, new_salt = self._hash_password(new_password)
            
            # Update password in database
            result = self.users_collection.update_one(
                {'username': username},
                {
                    '$set': {
                        'password_hash': new_hashed_password,
                        'salt': new_salt.decode('utf-8'),
                        'password_changed_at': time.time()
                    }
                }
            )
            
            if result.modified_count > 0:
                logger.info(f"Password changed successfully for user {username}")
                return True, 'Password changed successfully'
            else:
                return False, 'Password change failed'
                
        except Exception as e:
            logger.error(f"Error changing password: {e}")
            return False, f'Password change error: {str(e)}'
    
    def enable_2fa(self, username: str, password: str) -> Tuple[bool, str, Optional[str]]:
        """Enable 2FA for user"""
        try:
            # Verify user credentials
            user = self.users_collection.find_one({'username': username})
            if not user:
                return False, 'User not found', None
            
            if not self._verify_password(password, user['password_hash']):
                return False, 'Invalid password', None
            
            if user.get('two_fa_enabled'):
                return False, '2FA is already enabled', None
            
            # Generate new 2FA secret
            two_fa_secret = self._generate_2fa_secret()
            two_fa_qr = self._generate_2fa_qr(username, two_fa_secret)
            
            # Update user in database
            result = self.users_collection.update_one(
                {'username': username},
                {
                    '$set': {
                        'two_fa_secret': two_fa_secret,
                        'two_fa_enabled': True,
                        'two_fa_enabled_at': time.time()
                    }
                }
            )
            
            if result.modified_count > 0:
                logger.info(f"2FA enabled for user {username}")
                return True, '2FA enabled successfully', two_fa_qr
            else:
                return False, 'Failed to enable 2FA', None
                
        except Exception as e:
            logger.error(f"Error enabling 2FA: {e}")
            return False, f'2FA enable error: {str(e)}', None

# Global authentication instance
secure_auth = SecureAuthentication()
