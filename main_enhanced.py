import streamlit as st
import os
import json
import time

# Import our enhanced modules
from config import Config
from enhanced_encrypt import encrypt_file_enhanced
from enhanced_decrypt import decrypt_file_enhanced

# Configure page
st.set_page_config(
    page_title="Secure File Storage v2.0",
    page_icon="lock",
    layout="wide"
)

# Simple Custom CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #1f77b4, #ff7f0e);
        color: white;
        padding: 2rem;
        border-radius: 15px;
        margin-bottom: 2rem;
        text-align: center;
    }
    
    .upload-area {
        border: 2px dashed #ccc;
        border-radius: 10px;
        padding: 2rem;
        text-align: center;
        background: #f8f9fa;
        margin: 1rem 0;
    }
    
    .success-box {
        background: #d4edda;
        color: #155724;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #28a745;
        margin: 1rem 0;
    }
    
    .warning-box {
        background: #fff3cd;
        color: #856404;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #ffc107;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

def main_header():
    """Display simple main header"""
    st.markdown("""
    <div class="main-header">
        <h1>Secure File Storage v2.0</h1>
        <p>Simple and secure file encryption with file splitting</p>
    </div>
    """, unsafe_allow_html=True)

def show_encryption():
    """Simple file encryption interface"""
    st.markdown("## File Encryption")
    
    st.markdown("""
    <div class="upload-area">
        <h3>Upload File to Encrypt</h3>
        <p>Your file will be encrypted with military-grade encryption</p>
    </div>
    """, unsafe_allow_html=True)
    
    uploaded_file = st.file_uploader(
        "Choose a file to encrypt",
        type=None,
        help="Select any file to encrypt"
    )
    
    if uploaded_file is not None:
        st.write(f"**File:** {uploaded_file.name}")
        st.write(f"**Size:** {uploaded_file.size / (1024*1024):.2f} MB")
        
        # Simple encryption options
        encryption_type = st.selectbox(
            "Encryption Method",
            ["split_and_encrypt", "multi_layer", "hybrid"],
            format_func=lambda x: {
                "split_and_encrypt": "Split + Encrypt (Your Original Concept!)",
                "multi_layer": "Multi-Layer Encryption",
                "hybrid": "Hybrid (RSA + AES)"
            }[x]
        )
        
        if st.button("Encrypt File", type="primary"):
            try:
                file_content = uploaded_file.read()
                
                with st.spinner("Encrypting file..."):
                    encrypted_content, manifest = encrypt_file_enhanced(
                        file_content, uploaded_file.name, encryption_type
                    )
                    
                    if encryption_type == 'split_and_encrypt':
                        # Handle split and encrypt
                        st.markdown("""
                        <div class="success-box">
                            <h3>File Split and Encrypted Successfully!</h3>
                            <p>Your file has been split into multiple parts and encrypted!</p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # Save each encrypted part to backend (no download)
                        part_files = []
                        for i, encrypted_part in enumerate(encrypted_content):
                            part_filename = f"{uploaded_file.name}_part_{i+1:03d}_encrypted.bin"
                            part_path = os.path.join(Config.ENCRYPTED_FILES_DIR, part_filename)
                            
                            with open(part_path, 'wb') as f:
                                f.write(encrypted_part)
                            
                            part_files.append(part_path)
                        
                        # Save manifest
                        manifest_path = os.path.join(
                            Config.ENCRYPTED_FILES_DIR,
                            f"{uploaded_file.name}_split_manifest.json"
                        )
                        
                        # Create a proper manifest with required fields
                        split_manifest = {
                            'original_filename': uploaded_file.name,
                            'encryption_type': 'split_and_encrypt',
                            'total_parts': len(encrypted_content),
                            'encryption_timestamp': str(int(time.time())),
                            'file_size': len(file_content),
                            'encryption_details': manifest
                        }
                        
                        with open(manifest_path, 'w') as f:
                            json.dump(split_manifest, f, indent=2)
                        
                        # Only download manifest (encrypted parts stay in backend)
                        st.markdown("### Download Manifest")
                        st.info(f"File split into {len(encrypted_content)} parts and saved to backend")
                        st.info("Download the manifest file to decrypt later")
                        
                        with open(manifest_path, 'r') as f:
                            st.download_button(
                                label="Download Manifest",
                                data=f.read(),
                                file_name=f"{uploaded_file.name}_split_manifest.json",
                                mime="application/json",
                                use_container_width=True
                            )
                        
                        st.success("All encrypted parts are safely stored in backend. Just upload the manifest to decrypt!")
                        
                    else:
                        # Handle regular encryption
                        st.markdown("""
                        <div class="success-box">
                            <h3>File Encrypted Successfully!</h3>
                            <p>Your file has been encrypted with military-grade encryption!</p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # Save encrypted file
                        encrypted_file_path = os.path.join(
                            Config.ENCRYPTED_FILES_DIR,
                            f"{uploaded_file.name}_encrypted.bin"
                        )
                        
                        with open(encrypted_file_path, 'wb') as f:
                            f.write(encrypted_content)
                        
                        # Save manifest
                        manifest_path = os.path.join(
                            Config.ENCRYPTED_FILES_DIR,
                            f"{uploaded_file.name}_manifest.json"
                        )
                        
                        with open(manifest_path, 'w') as f:
                            json.dump(manifest, f, indent=2)
                        
                        # Download
                        st.markdown("### 📥 Download Encrypted File")
                        with open(encrypted_file_path, 'rb') as f:
                            st.download_button(
                                label="📥 Download Encrypted File",
                                data=f.read(),
                                file_name=f"{uploaded_file.name}_encrypted.bin",
                                mime="application/octet-stream",
                                use_container_width=True
                            )
                    
                    # Show manifest
                    with st.expander("View Encryption Details"):
                        st.json(manifest)
                    
                    uploaded_file.seek(0)
                    
            except Exception as e:
                st.error(f"Encryption failed: {str(e)}")

def show_decryption():
    """Simple file decryption interface"""
    st.markdown("## File Decryption")
    
    st.markdown("""
    <div class="upload-area">
        <h3>Upload Manifest to Decrypt</h3>
        <p>Upload the manifest file you downloaded during encryption</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Simple manifest upload
    manifest_file = st.file_uploader(
        "Choose manifest file (.json)",
        type=['json'],
        help="Upload the manifest file from your encrypted file"
    )
    
    if manifest_file:
        try:
            manifest_data = json.loads(manifest_file.getvalue().decode())
            st.success("Manifest loaded successfully!")
            
            # Show file info
            st.write(f"**Original filename:** {manifest_data.get('original_filename', 'Unknown')}")
            st.write(f"**Encryption type:** {manifest_data.get('encryption_type', 'Unknown')}")
            
            if st.button("Decrypt File", type="primary", use_container_width=True):
                try:
                    with st.spinner("Decrypting file from backend..."):
                        # Get the original filename from manifest
                        original_filename = manifest_data.get('original_filename', 'decrypted_file')
                        encryption_type = manifest_data.get('encryption_type', 'unknown')
                        
                        if encryption_type == 'split_and_encrypt':
                            # For split and encrypt files, retrieve parts from backend
                            st.info("Retrieving encrypted parts from backend...")
                            
                            # Find all encrypted parts in the backend directory
                            base_filename = original_filename
                            encrypted_parts = []
                            part_number = 1
                            
                            while True:
                                part_filename = f"{base_filename}_part_{part_number:03d}_encrypted.bin"
                                part_path = os.path.join(Config.ENCRYPTED_FILES_DIR, part_filename)
                                
                                if os.path.exists(part_path):
                                    with open(part_path, 'rb') as f:
                                        encrypted_parts.append(f.read())
                                    part_number += 1
                                else:
                                    break
                            
                            if encrypted_parts:
                                st.success(f"Found {len(encrypted_parts)} encrypted parts in backend")
                                
                                # Decrypt the parts using the manifest
                                try:
                                    from enhanced_decrypt import decrypt_split_and_encrypt_file
                                    
                                    # Create temporary directory for processing
                                    import tempfile
                                    with tempfile.TemporaryDirectory() as temp_dir:
                                        # Save all parts to temporary files
                                        temp_part_paths = []
                                        for i, encrypted_part in enumerate(encrypted_parts):
                                            temp_part_path = os.path.join(temp_dir, f"part_{i+1:03d}_encrypted.bin")
                                            with open(temp_part_path, 'wb') as f:
                                                f.write(encrypted_part)
                                            temp_part_paths.append(temp_part_path)
                                        
                                        # Save manifest to temporary file
                                        temp_manifest_path = os.path.join(temp_dir, "manifest.json")
                                        with open(temp_manifest_path, 'w') as f:
                                            f.write(manifest_file.getvalue().decode())
                                        
                                        # Perform decryption
                                        # We need to pass the actual backend directory for key file lookup
                                        # The decrypt function will look for keys relative to the part paths
                                        # So we need to create a custom key file path in the temp directory
                                        # that points to the actual backend directory
                                        
                                        # Copy the key file to temp directory with the expected name
                                        backend_key_file = os.path.join(Config.ENCRYPTED_FILES_DIR, f"{original_filename}_keys.json")
                                        if os.path.exists(backend_key_file):
                                            temp_key_file = os.path.join(temp_dir, f"{original_filename}_keys.json")
                                            import shutil
                                            shutil.copy2(backend_key_file, temp_key_file)
                                        
                                        decrypted_content = decrypt_split_and_encrypt_file(
                                            temp_part_paths, temp_manifest_path
                                        )
                                        
                                        st.success("File decrypted successfully!")
                                        
                                        # Download decrypted file
                                        st.markdown("### Download Original File")
                                        st.download_button(
                                            label="Download Original File",
                                            data=decrypted_content,
                                            file_name=original_filename,
                                            mime="application/octet-stream",
                                            use_container_width=True
                                        )
                                        
                                except Exception as decrypt_error:
                                    st.error(f"Decryption failed: {str(decrypt_error)}")
                                    st.info("Make sure the manifest file is correct and encrypted parts exist in backend")
                            else:
                                st.error("No encrypted parts found in backend")
                                st.info("Make sure you encrypted the file first and the parts are saved")
                                
                        else:
                            # For other encryption types, handle accordingly
                            st.info(f"Processing {encryption_type} encryption...")
                            st.warning("This encryption type needs manual implementation")
                            
                except Exception as e:
                    st.error(f"Decryption failed: {str(e)}")
                    st.info("Check if the manifest file is valid and encrypted parts exist")
                    
        except Exception as e:
            st.error(f"Error reading manifest: {str(e)}")
            st.info("Make sure you uploaded a valid manifest file")

def main():
    """Main application function"""
    main_header()
    
    # Simple navigation
    tab1, tab2 = st.tabs(["Encrypt", "Decrypt"])
    
    with tab1:
        show_encryption()
    
    with tab2:
        show_decryption()

if __name__ == "__main__":
    main()
