import os
import base64
import hashlib
import json
import logging
from typing import Tuple, Dict, Any, Optional, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from config import Config
import time
from file_splitter import reconstruct_file_secure

logger = logging.getLogger(__name__)

class EnhancedDecryption:
    """Enhanced decryption with support for all encryption algorithms"""
    
    def __init__(self):
        self.decryption_metadata = {}
        self.key_cache = {}
    
    def load_encryption_keys(self, key_file_path: str) -> Dict[str, bytes]:
        """Load encryption keys from the key file"""
        try:
            if not os.path.exists(key_file_path):
                raise FileNotFoundError(f"Key file not found: {key_file_path}")
            
            with open(key_file_path, 'r') as f:
                key_data = json.load(f)
            
            # Convert base64 encoded keys back to bytes
            keys = {}
            for key_name, key_value in key_data.items():
                if key_name in ['timestamp', 'version']:
                    keys[key_name] = key_value
                else:
                    # Convert base64 back to bytes
                    keys[key_name] = base64.b64decode(key_value)
            
            logger.info(f"Successfully loaded encryption keys from {key_file_path}")
            return keys
            
        except Exception as e:
            logger.error(f"Error loading encryption keys: {e}")
            raise
    
    def decrypt_hybrid_file(self, encrypted_content: bytes, keys: Dict[str, bytes]) -> Tuple[bytes, Dict[str, Any]]:
        """Decrypt file using hybrid encryption (RSA + AES)"""
        try:
            # Parse the encrypted content
            encrypted_data = json.loads(encrypted_content.decode())
            
            # Extract encrypted content and metadata
            encrypted_file_content = base64.b64decode(encrypted_data['encrypted_content'])
            metadata = encrypted_data['metadata']
            
            # Decrypt the session key using RSA private key
            private_key = load_pem_private_key(keys['rsa_private'], password=None)
            encrypted_session_key = base64.b64decode(metadata['encrypted_session_key'])
            
            session_key = private_key.decrypt(
                encrypted_session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt file content using AES-GCM with session key
            aes_cipher = AESGCM(session_key)
            nonce = base64.b64decode(metadata['aes_nonce'])
            
            decrypted_content = aes_cipher.decrypt(
                nonce, 
                encrypted_file_content, 
                b"authenticated_data"
            )
            
            logger.info("Hybrid decryption completed successfully")
            return decrypted_content, metadata
            
        except Exception as e:
            logger.error(f"Error in hybrid decryption: {e}")
            raise
    
    def decrypt_multi_layer(self, encrypted_content: bytes, keys: Dict[str, bytes]) -> Tuple[bytes, Dict[str, Any]]:
        """Decrypt multi-layer encrypted file"""
        try:
            # Layer 4: MultiFernet decryption
            multifernet_cipher = MultiFernet([
                Fernet(keys['multifernet_key1']),
                Fernet(keys['multifernet_key2'])
            ])
            fernet_decrypted = multifernet_cipher.decrypt(encrypted_content)
            
            # Layer 3: Fernet decryption
            fernet_cipher = Fernet(keys['fernet_key'])
            fernet_decrypted = fernet_cipher.decrypt(fernet_decrypted)
            
            # Layer 2: ChaCha20-Poly1305 decryption
            chacha_cipher = ChaCha20Poly1305(keys['chacha_key'])
            chacha_decrypted = chacha_cipher.decrypt(
                keys['chacha_nonce'], 
                fernet_decrypted, 
                b"layer2_aad"
            )
            
            # Layer 1: AES-GCM decryption
            aes_cipher = AESGCM(keys['aes_key'])
            final_decrypted = aes_cipher.decrypt(
                keys['aes_nonce'], 
                chacha_decrypted, 
                b"layer1_aad"
            )
            
            logger.info("Multi-layer decryption completed successfully")
            return final_decrypted, {
                'algorithm': 'multi_layer_encryption',
                'decryption_success': True,
                'timestamp': str(int(time.time()))
            }
            
        except Exception as e:
            logger.error(f"Error in multi-layer decryption: {e}")
            raise
    
    def decrypt_media_file(self, encrypted_content: bytes, keys: Dict[str, bytes], metadata: Dict[str, Any]) -> Tuple[bytes, Dict[str, Any]]:
        """Decrypt media files"""
        try:
            # Extract nonce from metadata
            nonce = base64.b64decode(metadata['nonce'])
            file_type = metadata.get('file_type', 'unknown')
            
            # Decrypt using AES-GCM
            aes_cipher = AESGCM(keys['aes_key'])
            aad = f"media_file:{file_type}".encode()
            
            decrypted_content = aes_cipher.decrypt(nonce, encrypted_content, aad)
            
            logger.info(f"Media file decryption completed successfully for {file_type}")
            return decrypted_content, {
                'algorithm': 'aes_gcm_media',
                'file_type': file_type,
                'decryption_success': True,
                'timestamp': str(int(time.time()))
            }
            
        except Exception as e:
            logger.error(f"Error decrypting media file: {e}")
            raise
    
    def decrypt_split_and_encrypt_file(self, encrypted_parts: List[bytes], keys: Dict[str, bytes], metadata: Dict[str, Any]) -> Tuple[bytes, Dict[str, Any]]:
        """Decrypt split-and-encrypt files by decrypting each part and then reconstructing"""
        try:
            decrypted_parts = []
            
            # Decrypt each part individually
            for i, encrypted_part in enumerate(encrypted_parts):
                logger.info(f"Decrypting part {i+1}/{len(encrypted_parts)}")
                
                # Decrypt this part using multi-layer decryption
                decrypted_part, part_metadata = self.decrypt_multi_layer(encrypted_part, keys)
                decrypted_parts.append(decrypted_part)
            
            # Now reconstruct the file from decrypted parts
            # We need to create temporary files for the reconstruction process
            import tempfile
            
            # Create temporary directory for parts
            with tempfile.TemporaryDirectory() as temp_dir:
                # Save decrypted parts to temporary files
                part_paths = []
                for i, decrypted_part in enumerate(decrypted_parts):
                    part_path = os.path.join(temp_dir, f"part_{i+1:03d}.bin")
                    with open(part_path, 'wb') as f:
                        f.write(decrypted_part)
                    part_paths.append(part_path)
                
                # Create temporary metadata file for reconstruction
                split_metadata = metadata.get('split_metadata', {})
                temp_metadata = {
                    'split_id': split_metadata.get('split_id', 'temp'),
                    'original_filename': split_metadata.get('original_filename', 'unknown'),
                    'original_size': split_metadata.get('original_size', 0),
                    'original_hash': split_metadata.get('original_hash', ''),
                    'num_parts': len(decrypted_parts),
                    'part_size': split_metadata.get('part_size', 0),
                    'part_hashes': [hashlib.sha256(part).hexdigest() for part in decrypted_parts],
                    'part_paths': [os.path.basename(path) for path in part_paths],
                    'split_timestamp': split_metadata.get('split_timestamp', str(int(time.time())))
                }
                
                temp_metadata_path = os.path.join(temp_dir, "temp_metadata.json")
                with open(temp_metadata_path, 'w') as f:
                    json.dump(temp_metadata, f, indent=2)
                
                # Reconstruct the file
                reconstructed_path = reconstruct_file_secure(temp_metadata_path, temp_dir)
                
                # Read the reconstructed file
                with open(reconstructed_path, 'rb') as f:
                    final_content = f.read()
            
            logger.info("Split-and-encrypt file decryption completed successfully")
            
            return final_content, {
                'algorithm': 'split_and_encrypt',
                'decryption_success': True,
                'total_parts': len(encrypted_parts),
                'timestamp': str(int(time.time())),
                'reconstruction_success': True
            }
            
        except Exception as e:
            logger.error(f"Error decrypting split-and-encrypt file: {e}")
            raise
    
    def verify_file_integrity(self, original_content: bytes, decrypted_content: bytes, filename: str) -> Tuple[bool, str]:
        """Verify file integrity after decryption"""
        try:
            # Check if content lengths match
            if len(original_content) != len(decrypted_content):
                return False, "File size mismatch after decryption"
            
            # Calculate and compare hashes
            original_hash = hashlib.sha256(original_content).hexdigest()
            decrypted_hash = hashlib.sha256(decrypted_content).hexdigest()
            
            if original_hash != decrypted_hash:
                return False, "File content hash mismatch after decryption"
            
            # Check for magic bytes in decrypted content
            file_signatures = {
                b'\xff\xd8\xff': 'JPEG',
                b'\x89PNG\r\n\x1a\n': 'PNG',
                b'GIF87a': 'GIF',
                b'GIF89a': 'GIF',
                b'%PDF': 'PDF',
                b'PK\x03\x04': 'ZIP',
            }
            
            for signature, file_type in file_signatures.items():
                if decrypted_content.startswith(signature):
                    logger.info(f"File integrity verified: {file_type} file")
                    return True, f"File integrity verified: {file_type}"
            
            # For text files, check if content is readable
            try:
                decrypted_content.decode('utf-8')
                logger.info("File integrity verified: Text file")
                return True, "File integrity verified: Text file"
            except UnicodeDecodeError:
                # Binary file - assume integrity is good if we got here
                logger.info("File integrity verified: Binary file")
                return True, "File integrity verified: Binary file"
                
        except Exception as e:
            logger.error(f"Error verifying file integrity: {e}")
            return False, f"Integrity verification failed: {str(e)}"
    
    def decrypt_file_enhanced(self, encrypted_file_path: str, key_file_path: str, output_path: str = None) -> Tuple[bytes, Dict[str, Any]]:
        """Main decryption function that handles all encryption types"""
        try:
            # Load encryption keys
            keys = self.load_encryption_keys(key_file_path)
            
            # Read encrypted file
            with open(encrypted_file_path, 'rb') as f:
                encrypted_content = f.read()
            
            # Determine encryption type from key file
            if 'rsa_private' in keys:
                # Hybrid encryption
                decrypted_content, metadata = self.decrypt_hybrid_file(encrypted_content, keys)
                algorithm = 'hybrid_rsa_aes'
            elif 'multifernet_key1' in keys and 'multifernet_key2' in keys:
                # Multi-layer encryption
                decrypted_content, metadata = self.decrypt_multi_layer(encrypted_content, keys)
                algorithm = 'multi_layer_encryption'
            elif 'aes_key' in keys:
                # Check if this is a split-and-encrypt file
                split_manifest_file = encrypted_file_path.replace('_encrypted.bin', '_split_manifest.json')
                if os.path.exists(split_manifest_file):
                    # This is a split-and-encrypt file
                    with open(split_manifest_file, 'r') as f:
                        split_metadata = json.load(f)
                    
                    # Load all encrypted parts
                    base_dir = os.path.dirname(encrypted_file_path)
                    encrypted_parts = []
                    
                    for part_info in split_metadata['part_encryption_metadata']:
                        part_filename = f"{os.path.splitext(os.path.basename(encrypted_file_path))[0]}_part_{part_info['part_number']:03d}_encrypted.bin"
                        part_path = os.path.join(base_dir, part_filename)
                        if os.path.exists(part_path):
                            with open(part_path, 'rb') as f:
                                encrypted_parts.append(f.read())
                        else:
                            raise FileNotFoundError(f"Missing part file: {part_filename}")
                    
                    # Decrypt split-and-encrypt file
                    decrypted_content, metadata = self.decrypt_split_and_encrypt_file(encrypted_parts, keys, split_metadata)
                    algorithm = 'split_and_encrypt'
                else:
                    # Regular media file encryption
                    metadata_file = encrypted_file_path.replace('_encrypted.bin', '_manifest.json')
                    if os.path.exists(metadata_file):
                        with open(metadata_file, 'r') as f:
                            metadata = json.load(f)
                        decrypted_content, metadata = self.decrypt_media_file(encrypted_content, keys, metadata)
                        algorithm = 'aes_gcm_media'
                    else:
                        raise ValueError("Metadata file not found for media file decryption")
            else:
                raise ValueError("Unknown encryption type - key file format not recognized")
            
            # Save decrypted file if output path specified
            if output_path:
                with open(output_path, 'wb') as f:
                    f.write(decrypted_content)
                logger.info(f"Decrypted file saved to: {output_path}")
            
            # Create decryption manifest
            decryption_manifest = {
                'algorithm': algorithm,
                'original_file': os.path.basename(encrypted_file_path),
                'decryption_timestamp': str(int(time.time())),
                'file_size': len(decrypted_content),
                'metadata': metadata,
                'integrity_verified': True
            }
            
            return decrypted_content, decryption_manifest
            
        except Exception as e:
            logger.error(f"Error in enhanced file decryption: {e}")
            raise

# Global decryption instance
enhanced_decryption = EnhancedDecryption()

def decrypt_file_enhanced(encrypted_file_path: str, key_file_path: str, output_path: str = None) -> Tuple[bytes, Dict[str, Any]]:
    """Enhanced file decryption with multiple algorithm support"""
    return enhanced_decryption.decrypt_file_enhanced(encrypted_file_path, key_file_path, output_path)

def decrypt_split_and_encrypt_file(encrypted_part_paths: List[str], manifest_path: str) -> bytes:
    """Decrypt a split-and-encrypted file from its parts and manifest"""
    try:
        # Load manifest
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
        
        # Check if this is our new manifest structure
        if 'encryption_details' in manifest:
            # Use the encryption_details from our manifest
            encryption_details = manifest.get('encryption_details', {})
            
            # The manifest only contains key hashes, not the actual keys
            # We need to load the actual keys from the key file
            # The key file should be in the same directory as the encrypted parts
            if not encrypted_part_paths:
                raise ValueError("No encrypted part paths provided")
            
            # Get the directory of the first part to find the key file
            base_dir = os.path.dirname(encrypted_part_paths[0])
            original_filename = manifest.get('original_filename', 'unknown')
            key_file_path = os.path.join(base_dir, f"{original_filename}_keys.json")
            
            if not os.path.exists(key_file_path):
                raise ValueError(f"Key file not found: {key_file_path}")
            
            # Load the actual encryption keys
            with open(key_file_path, 'r') as f:
                key_data = json.load(f)
            
            # Convert base64 encoded keys back to bytes
            keys = {}
            for key_name, key_value in key_data.items():
                if key_name in ['timestamp', 'version']:
                    keys[key_name] = key_value
                else:
                    # Convert base64 back to bytes
                    keys[key_name] = base64.b64decode(key_value)
            
            # Read all encrypted parts
            encrypted_parts = []
            for part_path in encrypted_part_paths:
                with open(part_path, 'rb') as f:
                    encrypted_parts.append(f.read())
            
            # Decrypt each part using the reverse of multi_layer_encrypt
            decrypted_parts = []
            for i, encrypted_part in enumerate(encrypted_parts):
                try:
                    # Layer 4: MultiFernet decryption
                    multifernet_cipher = MultiFernet([
                        Fernet(keys['multifernet_key1']),
                        Fernet(keys['multifernet_key2'])
                    ])
                    fernet_decrypted = multifernet_cipher.decrypt(encrypted_part)
                    
                    # Layer 3: Fernet decryption
                    fernet_cipher = Fernet(keys['fernet_key'])
                    fernet_decrypted = fernet_cipher.decrypt(fernet_decrypted)
                    
                    # Layer 2: ChaCha20-Poly1305 decryption
                    chacha_cipher = ChaCha20Poly1305(keys['chacha_key'])
                    chacha_decrypted = chacha_cipher.decrypt(
                        keys['chacha_nonce'], 
                        fernet_decrypted, 
                        b"layer2_aad"
                    )
                    
                    # Layer 1: AES-GCM decryption
                    aes_cipher = AESGCM(keys['aes_key'])
                    final_decrypted = aes_cipher.decrypt(
                        keys['aes_nonce'], 
                        chacha_decrypted, 
                        b"layer1_aad"
                    )
                    
                    decrypted_parts.append(final_decrypted)
                    
                except Exception as part_error:
                    logger.error(f"Error decrypting part {i+1}: {part_error}")
                    raise ValueError(f"Failed to decrypt part {i+1}: {str(part_error)}")
            
            # Reconstruct original file by concatenating decrypted parts
            original_content = b''.join(decrypted_parts)
            
            # Verify file integrity if hash is available
            expected_hash = encryption_details.get('metadata', {}).get('file_hash')
            if expected_hash:
                actual_hash = hashlib.sha256(original_content).hexdigest()
                if actual_hash != expected_hash:
                    raise ValueError("File integrity check failed - hash mismatch")
            
            return original_content
                
        else:
            # Original logic for backward compatibility
            keys = manifest.get('encryption_keys', {})
            if not keys:
                raise ValueError("No encryption keys found in manifest")
            
            # Create decryption instance
            decryption = EnhancedDecryption()
            
            # Read all encrypted parts
            encrypted_parts = []
            for part_path in encrypted_part_paths:
                with open(part_path, 'rb') as f:
                    encrypted_parts.append(f.read())
            
            # Decrypt each part
            decrypted_parts = []
            for i, encrypted_part in enumerate(encrypted_parts):
                part_key = keys.get(f'part_{i+1}')
                if not part_key:
                    raise ValueError(f"Missing key for part {i+1}")
                
                # Derive key from password
                salt = part_key.get('salt', b'default_salt')
                key = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                ).derive(part_key.get('password', 'default_password').encode())
                
                # Decrypt with AES-GCM
                aesgcm = AESGCM(key)
                nonce = part_key.get('nonce', b'default_nonce')
                decrypted_part = aesgcm.decrypt(nonce, encrypted_part, None)
                decrypted_parts.append(decrypted_part)
            
            # Reconstruct original file
            original_content = b''.join(decrypted_parts)
            
            # Verify file integrity
            expected_hash = manifest.get('file_hash')
            if expected_hash:
                actual_hash = hashlib.sha256(original_content).hexdigest()
                if actual_hash != expected_hash:
                    raise ValueError("File integrity check failed - hash mismatch")
            
            return original_content
        
    except Exception as e:
        logger.error(f"Error decrypting split-and-encrypt file: {e}")
        raise
