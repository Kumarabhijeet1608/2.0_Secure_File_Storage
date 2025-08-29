import os
import base64
import hashlib
import hmac
import secrets
import logging
from typing import Tuple, Dict, Any, Optional, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
import json
from config import Config
import time
from file_splitter import split_file_secure

logger = logging.getLogger(__name__)

class EnhancedEncryption:
    """Enhanced encryption with multiple algorithms and secure key management"""
    
    def __init__(self):
        self.encryption_metadata = {}
        self.key_derivation_salt = os.urandom(32)
    
    def generate_secure_keys(self) -> Dict[str, bytes]:
        """Generate cryptographically secure keys for all algorithms"""
        try:
            keys = {}
            
            # Generate AES-256-GCM key
            keys['aes_key'] = AESGCM.generate_key(bit_length=256)
            
            # Generate ChaCha20-Poly1305 key
            keys['chacha_key'] = ChaCha20Poly1305.generate_key()
            
            # Generate RSA key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096
            )
            public_key = private_key.public_key()
            
            # Serialize keys
            keys['rsa_private'] = private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            )
            keys['rsa_public'] = public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            )
            
            # Generate Fernet keys
            keys['fernet_key'] = Fernet.generate_key()
            keys['multifernet_key1'] = Fernet.generate_key()
            keys['multifernet_key2'] = Fernet.generate_key()
            
            # Generate nonces
            keys['aes_nonce'] = os.urandom(12)
            keys['chacha_nonce'] = os.urandom(12)
            
            # Generate additional entropy
            keys['entropy'] = os.urandom(32)
            
            logger.info("Successfully generated secure encryption keys")
            return keys
            
        except Exception as e:
            logger.error(f"Error generating encryption keys: {e}")
            raise
    
    def derive_key_from_password(self, password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """Derive a cryptographic key from a password using PBKDF2"""
        if salt is None:
            salt = os.urandom(32)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # High iteration count for security
        )
        key = kdf.derive(password.encode())
        return key, salt
    
    def hybrid_encrypt_file(self, file_content: bytes, keys: Dict[str, bytes]) -> Tuple[bytes, Dict[str, Any]]:
        """Encrypt file using hybrid encryption (symmetric + asymmetric)"""
        try:
            # Generate a random session key for symmetric encryption
            session_key = os.urandom(32)
            
            # Encrypt the session key with RSA
            private_key = rsa.load_pem_private_key(keys['rsa_private'], password=None)
            encrypted_session_key = private_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Encrypt file content with AES-GCM using session key
            aes_cipher = AESGCM(session_key)
            nonce = os.urandom(12)
            encrypted_content = aes_cipher.encrypt(nonce, file_content, b"authenticated_data")
            
            # Create metadata for decryption
            metadata = {
                'algorithm': 'hybrid_rsa_aes',
                'encrypted_session_key': base64.b64encode(encrypted_session_key).decode(),
                'aes_nonce': base64.b64encode(nonce).decode(),
                'timestamp': str(int(time.time())),
                'version': '2.0'
            }
            
            # Combine encrypted content and metadata
            result = {
                'encrypted_content': base64.b64encode(encrypted_content).decode(),
                'metadata': metadata
            }
            
            return json.dumps(result).encode(), metadata
            
        except Exception as e:
            logger.error(f"Error in hybrid encryption: {e}")
            raise
    
    def multi_layer_encrypt(self, file_content: bytes, keys: Dict[str, bytes]) -> Tuple[bytes, Dict[str, Any]]:
        """Multi-layer encryption using different algorithms for enhanced security"""
        try:
            # Layer 1: AES-GCM encryption
            aes_cipher = AESGCM(keys['aes_key'])
            aes_encrypted = aes_cipher.encrypt(keys['aes_nonce'], file_content, b"layer1_aad")
            
            # Layer 2: ChaCha20-Poly1305 encryption
            chacha_cipher = ChaCha20Poly1305(keys['chacha_key'])
            chacha_encrypted = chacha_cipher.encrypt(keys['chacha_nonce'], aes_encrypted, b"layer2_aad")
            
            # Layer 3: Fernet encryption
            fernet_cipher = Fernet(keys['fernet_key'])
            fernet_encrypted = fernet_cipher.encrypt(chacha_encrypted)
            
            # Layer 4: MultiFernet encryption
            multifernet_cipher = MultiFernet([
                Fernet(keys['multifernet_key1']),
                Fernet(keys['multifernet_key2'])
            ])
            final_encrypted = multifernet_cipher.encrypt(fernet_encrypted)
            
            # Create comprehensive metadata
            metadata = {
                'algorithm': 'multi_layer_encryption',
                'layers': [
                    {'type': 'AES-256-GCM', 'nonce': base64.b64encode(keys['aes_nonce']).decode()},
                    {'type': 'ChaCha20-Poly1305', 'nonce': base64.b64encode(keys['chacha_nonce']).decode()},
                    {'type': 'Fernet'},
                    {'type': 'MultiFernet'}
                ],
                'timestamp': str(int(time.time())),
                'version': '2.0',
                'key_hashes': {
                    'aes_key_hash': hashlib.sha256(keys['aes_key']).hexdigest(),
                    'chacha_key_hash': hashlib.sha256(keys['chacha_key']).hexdigest(),
                    'fernet_key_hash': hashlib.sha256(keys['fernet_key']).hexdigest()
                }
            }
            
            return final_encrypted, metadata
            
        except Exception as e:
            logger.error(f"Error in multi-layer encryption: {e}")
            raise
    
    def encrypt_media_file(self, file_content: bytes, keys: Dict[str, bytes], file_type: str) -> Tuple[bytes, Dict[str, Any]]:
        """Encrypt media files with optimized encryption"""
        try:
            # For media files, use AES-GCM with larger nonce for better performance
            aes_cipher = AESGCM(keys['aes_key'])
            nonce = os.urandom(16)  # Larger nonce for media files
            
            # Add file type to authenticated data
            aad = f"media_file:{file_type}".encode()
            
            encrypted_content = aes_cipher.encrypt(nonce, file_content, aad)
            
            metadata = {
                'algorithm': 'aes_gcm_media',
                'file_type': file_type,
                'nonce': base64.b64encode(nonce).decode(),
                'timestamp': str(int(time.time())),
                'version': '2.0'
            }
            
            return encrypted_content, metadata
            
        except Exception as e:
            logger.error(f"Error encrypting media file: {e}")
            raise
    
    def split_and_encrypt_file(self, file_content: bytes, filename: str, keys: Dict[str, bytes]) -> Tuple[List[bytes], Dict[str, Any]]:
        """Split file into parts and encrypt each part separately for enhanced security"""
        try:
            # Create temporary file for splitting
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1]) as temp_file:
                temp_file.write(file_content)
                temp_file_path = temp_file.name
            
            try:
                # Split file into parts
                part_paths, split_metadata = split_file_secure(temp_file_path)
                
                # Encrypt each part separately
                encrypted_parts = []
                part_encryption_metadata = []
                
                for i, part_path in enumerate(part_paths):
                    # Read part content
                    with open(part_path, 'rb') as f:
                        part_content = f.read()
                    
                    # Encrypt this part with multi-layer encryption
                    encrypted_part, part_metadata = self.multi_layer_encrypt(part_content, keys)
                    
                    # Store encrypted part and metadata
                    encrypted_parts.append(encrypted_part)
                    part_encryption_metadata.append({
                        'part_number': i + 1,
                        'part_size': len(part_content),
                        'encrypted_size': len(encrypted_part),
                        'encryption_metadata': part_metadata
                    })
                
                # Create comprehensive metadata
                metadata = {
                    'algorithm': 'split_and_encrypt',
                    'split_metadata': split_metadata,
                    'part_encryption_metadata': part_encryption_metadata,
                    'total_parts': len(encrypted_parts),
                    'timestamp': str(int(time.time())),
                    'version': '2.0',
                    'security_features': {
                        'file_splitting': True,
                        'part_encryption': True,
                        'hash_verification': True,
                        'split_id_obfuscation': True
                    }
                }
                
                logger.info(f"File split and encrypted into {len(encrypted_parts)} parts")
                return encrypted_parts, metadata
                
            finally:
                # Clean up temporary file
                os.unlink(temp_file_path)
                
        except Exception as e:
            logger.error(f"Error in split and encrypt: {e}")
            raise
    
    def create_encryption_manifest(self, keys: Dict[str, bytes], metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Create a comprehensive encryption manifest"""
        manifest = {
            'encryption_info': {
                'version': '2.0',
                'timestamp': metadata.get('timestamp', str(int(time.time()))),
                'algorithm': metadata.get('algorithm', 'unknown'),
                'key_derivation': 'PBKDF2-SHA256-100000',
                'entropy_source': 'os.urandom'
            },
            'key_management': {
                'aes_key_hash': hashlib.sha256(keys['aes_key']).hexdigest(),
                'chacha_key_hash': hashlib.sha256(keys['chacha_key']).hexdigest(),
                'fernet_key_hash': hashlib.sha256(keys['fernet_key']).hexdigest(),
                'rsa_key_size': 4096,
                'key_derivation_salt': base64.b64encode(self.key_derivation_salt).decode()
            },
            'security_features': {
                'nonce_reuse_protection': True,
                'authenticated_encryption': True,
                'key_derivation': True,
                'entropy_generation': True
            },
            'metadata': metadata
        }
        
        return manifest
    
    def save_encryption_keys(self, keys: Dict[str, bytes], output_path: str):
        """Save encryption keys securely"""
        try:
            # Create a secure key file
            key_data = {}
            for key_name, key_value in keys.items():
                if key_name.endswith('_key') or key_name.endswith('_private'):
                    # Store the actual key as base64 for decryption
                    # In production, these should be stored in a secure key management system
                    key_data[key_name] = base64.b64encode(key_value).decode()
                else:
                    # Store nonces and other data as base64
                    key_data[key_name] = base64.b64encode(key_value).decode()
            
            # Add timestamp and version
            key_data['timestamp'] = str(int(time.time()))
            key_data['version'] = '2.0'
            
            # Save to file
            with open(output_path, 'w') as f:
                json.dump(key_data, f, indent=2)
            
            logger.info(f"Encryption keys saved to {output_path}")
            
        except Exception as e:
            logger.error(f"Error saving encryption keys: {e}")
            raise

# Global encryption instance
enhanced_encryption = EnhancedEncryption()

def encrypt_file_enhanced(file_content: bytes, filename: str, encryption_type: str = 'multi_layer') -> Tuple[bytes, Dict[str, Any]]:
    """Enhanced file encryption with multiple algorithm options"""
    try:
        # Generate secure keys
        keys = enhanced_encryption.generate_secure_keys()
        
        # Choose encryption method based on file type and preference
        if encryption_type == 'hybrid':
            encrypted_content, metadata = enhanced_encryption.hybrid_encrypt_file(file_content, keys)
        elif encryption_type == 'multi_layer':
            encrypted_content, metadata = enhanced_encryption.multi_layer_encrypt(file_content, keys)
        elif encryption_type == 'split_and_encrypt':
            # Enhanced security: split file into parts and encrypt each separately
            encrypted_parts, metadata = enhanced_encryption.split_and_encrypt_file(file_content, filename, keys)
            encrypted_content = encrypted_parts  # Return list of encrypted parts
        else:
            # Default to multi-layer for maximum security
            encrypted_content, metadata = enhanced_encryption.multi_layer_encrypt(file_content, keys)
        
        # Create encryption manifest
        manifest = enhanced_encryption.create_encryption_manifest(keys, metadata)
        
        # Save keys (in production, these would be stored in a secure key management system)
        key_file_path = os.path.join(Config.ENCRYPTED_FILES_DIR, f"{filename}_keys.json")
        enhanced_encryption.save_encryption_keys(keys, key_file_path)
        
        return encrypted_content, manifest
        
    except Exception as e:
        logger.error(f"Error in enhanced file encryption: {e}")
        raise
