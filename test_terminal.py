#!/usr/bin/env python3
"""
Terminal Test Script for Secure File Storage
Tests complete encryption and decryption flow
"""

import os
import json
import tempfile
import shutil
import time
from pathlib import Path

def test_complete_flow():
    """Test the complete encryption and decryption flow"""
    print("Secure File Storage - Terminal Test")
    print("=" * 50)
    
    # Test file content
    test_content = b"This is a test file content for encryption and decryption testing. " * 100
    test_filename = "test_document.txt"
    
    print(f"Test file: {test_filename}")
    print(f"File size: {len(test_content)} bytes")
    print()
    
    try:
        # Step 1: Test Encryption
        print("Step 1: Testing Encryption...")
        from enhanced_encrypt import encrypt_file_enhanced
        
        encrypted_parts, manifest = encrypt_file_enhanced(
            test_content, 
            test_filename, 
            'split_and_encrypt'
        )
        
        print("Encryption successful!")
        print(f"Created {len(encrypted_parts)} encrypted parts")
        print(f"Manifest created with {len(manifest)} fields")
        
        # Step 2: Save encrypted parts to backend
        print("\nStep 2: Saving encrypted parts to backend...")
        from config import Config
        
        # Ensure directory exists
        os.makedirs(Config.ENCRYPTED_FILES_DIR, exist_ok=True)
        
        # Save encrypted parts
        for i, part in enumerate(encrypted_parts):
            part_filename = f"{test_filename}_part_{i+1:03d}_encrypted.bin"
            part_path = os.path.join(Config.ENCRYPTED_FILES_DIR, part_filename)
            
            with open(part_path, 'wb') as f:
                f.write(part)
            print(f"Saved part {i+1}: {part_filename}")
        
        # Step 3: Test Decryption
        print("\nStep 3: Testing Decryption...")
        from enhanced_decrypt import decrypt_split_and_encrypt_file
        
        # Create temporary directory for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            # Copy encrypted parts to temp directory
            temp_part_paths = []
            for i in range(len(encrypted_parts)):
                part_filename = f"{test_filename}_part_{i+1:03d}_encrypted.bin"
                source_path = os.path.join(Config.ENCRYPTED_FILES_DIR, part_filename)
                temp_path = os.path.join(temp_dir, f"part_{i+1:03d}_encrypted.bin")
                
                shutil.copy2(source_path, temp_path)
                temp_part_paths.append(temp_path)
                print(f"Copied part {i+1} to temp directory")
            
            # Copy key file to temp directory
            key_filename = f"{test_filename}_keys.json"
            source_key_path = os.path.join(Config.ENCRYPTED_FILES_DIR, key_filename)
            temp_key_path = os.path.join(temp_dir, key_filename)
            
            if os.path.exists(source_key_path):
                shutil.copy2(source_key_path, temp_key_path)
                print("Copied key file to temp directory")
            else:
                print(f"Key file not found: {source_key_path}")
                return False
            
            # Create temporary manifest with proper structure (like Streamlit app)
            temp_manifest_path = os.path.join(temp_dir, "manifest.json")
            
            # Create the manifest structure that the decryption function expects
            proper_manifest = {
                'original_filename': test_filename,
                'encryption_type': 'split_and_encrypt',
                'total_parts': len(encrypted_parts),
                'encryption_timestamp': str(int(time.time())),
                'file_size': len(test_content),
                'encryption_details': manifest  # This is what the decryption function looks for
            }
            
            with open(temp_manifest_path, 'w') as f:
                json.dump(proper_manifest, f, indent=2)
            print("Created temporary manifest with proper structure")
            
            # Perform decryption
            print("Decrypting...")
            decrypted_content = decrypt_split_and_encrypt_file(temp_part_paths, temp_manifest_path)
            
            print("Decryption successful!")
            print(f"Decrypted size: {len(decrypted_content)} bytes")
        
        # Step 4: Verify Results
        print("\nStep 4: Verifying Results...")
        
        if decrypted_content == test_content:
            print("SUCCESS: Original content matches decrypted content!")
            print("Complete encryption/decryption flow is working perfectly!")
        else:
            print("FAILED: Content mismatch!")
            print(f"Original length: {len(test_content)}")
            print(f"Decrypted length: {len(decrypted_content)}")
            return False
        
        # Step 5: Cleanup
        print("\nStep 5: Cleaning up...")
        for i in range(len(encrypted_parts)):
            part_filename = f"{test_filename}_part_{i+1:03d}_encrypted.bin"
            part_path = os.path.join(Config.ENCRYPTED_FILES_DIR, part_filename)
            if os.path.exists(part_path):
                os.remove(part_path)
                print(f"Removed {part_filename}")
        
        # Remove key file
        key_path = os.path.join(Config.ENCRYPTED_FILES_DIR, f"{test_filename}_keys.json")
        if os.path.exists(key_path):
            os.remove(key_path)
            print("Removed key file")
        
        print("\nTEST COMPLETED SUCCESSFULLY!")
        return True
        
    except Exception as e:
        print(f"Test failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def test_file_operations():
    """Test file operations and directory creation"""
    print("\nTesting File Operations...")
    
    from config import Config
    
    # Test directory creation
    test_dirs = [
        Config.ENCRYPTED_FILES_DIR,
        Config.SPLIT_FILES_DIR,
        Config.TEMP_DIR
    ]
    
    for dir_path in test_dirs:
        os.makedirs(dir_path, exist_ok=True)
        if os.path.exists(dir_path):
            print(f"Directory exists: {dir_path}")
        else:
            print(f"Failed to create: {dir_path}")
    
    # Test file writing
    test_file_path = os.path.join(Config.TEMP_DIR, "test_write.txt")
    try:
        with open(test_file_path, 'w') as f:
            f.write("Test content")
        print(f"File write test: {test_file_path}")
        
        # Cleanup
        os.remove(test_file_path)
        print("Cleaned up test file")
    except Exception as e:
        print(f"File write test failed: {e}")

if __name__ == "__main__":
    print("Starting Secure File Storage Terminal Tests...")
    print()
    
    # Test 1: File operations
    test_file_operations()
    
    # Test 2: Complete encryption/decryption flow
    success = test_complete_flow()
    
    print("\n" + "=" * 50)
    if success:
        print("ALL TESTS PASSED! Your system is working perfectly!")
    else:
        print("SOME TESTS FAILED! Check the errors above.")
    
    print("=" * 50)
