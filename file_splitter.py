import os
import hashlib
import json
import logging
from typing import List, Tuple, Dict, Any
from pathlib import Path
from config import Config
import math

logger = logging.getLogger(__name__)

class SecureFileSplitter:
    """Secure file splitting for enhanced security"""
    
    def __init__(self):
        self.split_metadata = {}
        self.part_size = 1024 * 1024  # 1MB default part size
        self.min_parts = 3  # Minimum number of parts
        self.max_parts = 10  # Maximum number of parts
    
    def calculate_optimal_parts(self, file_size: int) -> int:
        """Calculate optimal number of parts based on file size"""
        if file_size <= self.part_size:
            return self.min_parts
        
        # Calculate parts needed
        parts_needed = math.ceil(file_size / self.part_size)
        
        # Ensure we have at least min_parts and at most max_parts
        if parts_needed < self.min_parts:
            parts_needed = self.min_parts
        elif parts_needed > self.max_parts:
            parts_needed = self.max_parts
        
        return parts_needed
    
    def split_file_secure(self, file_path: str, output_dir: str = None) -> Tuple[List[str], Dict[str, Any]]:
        """
        Split file into multiple parts with enhanced security
        
        Args:
            file_path: Path to the file to split
            output_dir: Directory to save split parts (default: SplitFiles)
            
        Returns:
            Tuple of (part_paths, metadata)
        """
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Set output directory
            if output_dir is None:
                output_dir = Config.SPLIT_FILES_DIR
            
            # Ensure output directory exists
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            
            # Get file information
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            file_hash = self._calculate_file_hash(file_path)
            
            # Calculate optimal number of parts
            num_parts = self.calculate_optimal_parts(file_size)
            part_size = math.ceil(file_size / num_parts)
            
            # Generate unique identifier for this split operation
            split_id = self._generate_split_id(file_name, file_hash)
            
            part_paths = []
            part_hashes = []
            
            logger.info(f"Splitting file {file_name} into {num_parts} parts")
            
            with open(file_path, 'rb') as source_file:
                for part_num in range(num_parts):
                    # Read part data
                    part_data = source_file.read(part_size)
                    if not part_data:
                        break
                    
                    # Generate part filename
                    part_filename = f"{split_id}_part_{part_num + 1:03d}.bin"
                    part_path = os.path.join(output_dir, part_filename)
                    
                    # Write part to file
                    with open(part_path, 'wb') as part_file:
                        part_file.write(part_data)
                    
                    # Calculate part hash
                    part_hash = hashlib.sha256(part_data).hexdigest()
                    part_hashes.append(part_hash)
                    
                    part_paths.append(part_path)
                    
                    logger.info(f"Created part {part_num + 1}/{num_parts}: {part_filename}")
            
            # Create comprehensive metadata
            metadata = {
                'split_id': split_id,
                'original_filename': file_name,
                'original_size': file_size,
                'original_hash': file_hash,
                'num_parts': len(part_paths),
                'part_size': part_size,
                'part_hashes': part_hashes,
                'part_paths': [os.path.basename(path) for path in part_paths],
                'split_timestamp': str(int(os.path.getmtime(file_path))),
                'algorithm': 'secure_file_splitting_v2',
                'security_features': {
                    'randomized_part_names': True,
                    'part_hash_verification': True,
                    'split_id_obfuscation': True
                }
            }
            
            # Save metadata
            metadata_path = os.path.join(output_dir, f"{split_id}_metadata.json")
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"File splitting completed successfully. Parts saved to: {output_dir}")
            return part_paths, metadata
            
        except Exception as e:
            logger.error(f"Error splitting file: {e}")
            raise
    
    def reconstruct_file_secure(self, metadata_path: str, output_path: str = None) -> str:
        """
        Reconstruct file from split parts with integrity verification
        
        Args:
            metadata_path: Path to the metadata file
            output_path: Path to save reconstructed file
            
        Returns:
            Path to reconstructed file
        """
        try:
            # Load metadata
            if not os.path.exists(metadata_path):
                raise FileNotFoundError(f"Metadata file not found: {metadata_path}")
            
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            # Determine output path
            if output_path is None:
                output_dir = Config.SPLIT_FILES_DIR
                output_filename = f"reconstructed_{metadata['original_filename']}"
                output_path = os.path.join(output_dir, output_filename)
            
            # Get directory from metadata path
            base_dir = os.path.dirname(metadata_path)
            
            # Verify all parts exist
            missing_parts = []
            for part_filename in metadata['part_paths']:
                part_path = os.path.join(base_dir, part_filename)
                if not os.path.exists(part_path):
                    missing_parts.append(part_filename)
            
            if missing_parts:
                raise FileNotFoundError(f"Missing parts: {missing_parts}")
            
            logger.info(f"Reconstructing file from {metadata['num_parts']} parts")
            
            # Reconstruct file
            with open(output_path, 'wb') as output_file:
                for part_filename in metadata['part_paths']:
                    part_path = os.path.join(base_dir, part_filename)
                    
                    # Read and verify part
                    with open(part_path, 'rb') as part_file:
                        part_data = part_file.read()
                    
                    # Verify part hash
                    part_hash = hashlib.sha256(part_data).hexdigest()
                    part_index = metadata['part_paths'].index(part_filename)
                    expected_hash = metadata['part_hashes'][part_index]
                    
                    if part_hash != expected_hash:
                        raise ValueError(f"Part hash mismatch for {part_filename}")
                    
                    # Write part to output file
                    output_file.write(part_data)
                    
                    logger.info(f"Processed part: {part_filename}")
            
            # Verify reconstructed file
            reconstructed_size = os.path.getsize(output_path)
            reconstructed_hash = self._calculate_file_hash(output_path)
            
            if reconstructed_size != metadata['original_size']:
                raise ValueError(f"File size mismatch: expected {metadata['original_size']}, got {reconstructed_size}")
            
            if reconstructed_hash != metadata['original_hash']:
                raise ValueError("File hash mismatch - file may be corrupted")
            
            logger.info(f"File reconstruction completed successfully: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error reconstructing file: {e}")
            raise
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def _generate_split_id(self, filename: str, file_hash: str) -> str:
        """Generate unique split identifier"""
        import secrets
        import time
        
        # Create unique identifier combining filename, hash, and random elements
        timestamp = str(int(time.time()))
        random_suffix = secrets.token_hex(8)
        
        # Create split ID
        split_id = f"{hashlib.md5(f'{filename}_{file_hash}_{timestamp}_{random_suffix}'.encode()).hexdigest()[:16]}"
        
        return split_id
    
    def get_split_info(self, metadata_path: str) -> Dict[str, Any]:
        """Get information about a split file without reconstructing"""
        try:
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            # Check which parts exist
            base_dir = os.path.dirname(metadata_path)
            existing_parts = []
            missing_parts = []
            
            for part_filename in metadata['part_paths']:
                part_path = os.path.join(base_dir, part_filename)
                if os.path.exists(part_path):
                    existing_parts.append(part_filename)
                else:
                    missing_parts.append(part_filename)
            
            # Calculate completion percentage
            completion_percentage = (len(existing_parts) / metadata['num_parts']) * 100
            
            return {
                'split_id': metadata['split_id'],
                'original_filename': metadata['original_filename'],
                'original_size': metadata['original_size'],
                'num_parts': metadata['num_parts'],
                'existing_parts': existing_parts,
                'missing_parts': missing_parts,
                'completion_percentage': completion_percentage,
                'can_reconstruct': len(missing_parts) == 0,
                'split_timestamp': metadata['split_timestamp']
            }
            
        except Exception as e:
            logger.error(f"Error getting split info: {e}")
            raise

# Global file splitter instance
secure_file_splitter = SecureFileSplitter()

def split_file_secure(file_path: str, output_dir: str = None) -> Tuple[List[str], Dict[str, Any]]:
    """Split file into secure parts"""
    return secure_file_splitter.split_file_secure(file_path, output_dir)

def reconstruct_file_secure(metadata_path: str, output_path: str = None) -> str:
    """Reconstruct file from secure parts"""
    return secure_file_splitter.reconstruct_file_secure(metadata_path, output_path)

def get_split_info(metadata_path: str) -> Dict[str, Any]:
    """Get information about split file"""
    return secure_file_splitter.get_split_info(metadata_path)
