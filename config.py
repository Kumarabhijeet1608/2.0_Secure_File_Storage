import os
from dotenv import load_dotenv
import logging
from pathlib import Path

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('secure_storage.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class Config:
    # Security Settings
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(32).hex())
    SESSION_TIMEOUT = int(os.getenv('SESSION_TIMEOUT', 3600))  # 1 hour
    MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', 5))
    RATE_LIMIT_WINDOW = int(os.getenv('RATE_LIMIT_WINDOW', 300))  # 5 minutes
    MAX_REQUESTS_PER_WINDOW = int(os.getenv('MAX_REQUESTS_PER_WINDOW', 100))
    
    # File Security
    MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', 100 * 1024 * 1024))  # 100MB
    ALLOWED_EXTENSIONS = {
        'text': ['.txt', '.md', '.py', '.js', '.html', '.css', '.json', '.xml', '.csv'],
        'media': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.mp3', '.mp4', '.wav', '.avi'],
        'documents': ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'],
        'archives': ['.zip', '.rar', '.7z', '.tar', '.gz']
    }
    BLOCKED_EXTENSIONS = ['.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.js']
    
    # Encryption Settings
    ENCRYPTION_ALGORITHMS = {
        'AES': {'key_size': 256, 'mode': 'GCM'},
        'ChaCha20': {'key_size': 256, 'mode': 'Poly1305'},
        'RSA': {'key_size': 4096},
        'Fernet': {'key_size': 256}
    }
    
    # AWS Configuration
    AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
    AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
    S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')
    
    # MongoDB Configuration
    MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
    MONGODB_DB = os.getenv('MONGODB_DB', 'secure_file_storage')
    
    # Redis Configuration (for rate limiting and caching)
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
    
    # File Paths
    BASE_DIR = Path(__file__).parent
    ENCRYPTED_FILES_DIR = BASE_DIR / "EncryptedFiles"
    SPLIT_FILES_DIR = BASE_DIR / "SplitFiles"
    TEMP_DIR = BASE_DIR / "temp"
    LOGS_DIR = BASE_DIR / "logs"
    
    # Security Headers
    SECURITY_HEADERS = {
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    }

def create_directories():
    """Create necessary directories if they don't exist"""
    directories = [
        Config.ENCRYPTED_FILES_DIR,
        Config.SPLIT_FILES_DIR,
        Config.TEMP_DIR,
        Config.LOGS_DIR
    ]
    
    for directory in directories:
        directory.mkdir(exist_ok=True)
        logger.info(f"Directory {directory} created/verified")

def validate_file_extension(filename):
    """Validate file extension against allowed and blocked lists"""
    if not filename or '.' not in filename:
        return False, "Invalid filename"
    
    extension = filename.lower().split('.')[-1]
    
    # Check blocked extensions
    if f'.{extension}' in Config.BLOCKED_EXTENSIONS:
        return False, f"File extension .{extension} is not allowed for security reasons"
    
    # Check if extension is allowed
    for category, extensions in Config.ALLOWED_EXTENSIONS.items():
        if f'.{extension}' in extensions:
            return True, category
    
    return False, f"File extension .{extension} is not supported"

def get_file_category(filename):
    """Get the category of a file based on its extension"""
    success, result = validate_file_extension(filename)
    if success:
        return result
    return "unknown"

# Directories will be created when needed, not automatically on import
# create_directories()        
        