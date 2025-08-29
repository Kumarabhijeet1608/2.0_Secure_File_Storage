#!/usr/bin/env python3
"""
Simple startup script for Secure File Storage v2.0
"""
import os
import sys
from pathlib import Path

def create_essential_directories():
    """Create only the essential directories needed for the app"""
    essential_dirs = [
        "EncryptedFiles",
        "SplitFiles", 
        "Uploads"
    ]
    
    for dir_name in essential_dirs:
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)
            print(f"Created directory: {dir_name}")
        else:
            print(f"Directory exists: {dir_name}")

def main():
    """Start the Secure File Storage application"""
    print("Secure File Storage v2.0 - Enhanced UI")
    print("=" * 60)
    
    # Create essential directories
    create_essential_directories()
    
    print("\nStarting Enhanced Streamlit Application...")
    print("Open your browser and go to: http://localhost:8501")
    print("Press Ctrl+C to stop the application")
    print("=" * 60)
    
    # Start Streamlit with enhanced configuration
    os.system("streamlit run main_enhanced.py --server.port 8501 --server.address localhost --theme.base light")

if __name__ == "__main__":
    main()
