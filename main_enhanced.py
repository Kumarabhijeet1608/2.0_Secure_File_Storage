import streamlit as st
import streamlit_authenticator as stauth
from streamlit_option_menu import option_menu
import time
import os
import logging
from pathlib import Path
import json
from datetime import datetime, timedelta

# Import our enhanced modules
from config import Config
from security import validate_user_input, validate_uploaded_file, check_rate_limit
from auth import secure_auth
from enhanced_encrypt import encrypt_file_enhanced
from enhanced_decrypt import decrypt_file_enhanced
from file_checker import is_media_file

# Configure page
st.set_page_config(
    page_title="Secure File Storage v2.0",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enhanced Custom CSS for modern, professional appearance
st.markdown("""
<style>
    /* Modern Color Scheme */
    :root {
        --primary-color: #1f77b4;
        --secondary-color: #ff7f0e;
        --success-color: #2ca02c;
        --warning-color: #d62728;
        --info-color: #17a2b8;
        --light-bg: #f8f9fa;
        --dark-text: #2c3e50;
        --border-color: #e9ecef;
    }
    
    /* Main Header with Gradient */
    .main-header {
        background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
        color: white;
        padding: 2rem;
        border-radius: 15px;
        margin-bottom: 2rem;
        text-align: center;
        box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        backdrop-filter: blur(10px);
    }
    
    .main-header h1 {
        font-size: 2.5rem;
        margin-bottom: 0.5rem;
        font-weight: 700;
    }
    
    .main-header p {
        font-size: 1.1rem;
        opacity: 0.9;
        margin-bottom: 1rem;
    }
    
    /* Security Badge */
    .security-badge {
        background: linear-gradient(45deg, var(--success-color), #28a745);
        color: white;
        padding: 0.8rem 1.5rem;
        border-radius: 25px;
        font-size: 0.9rem;
        font-weight: 600;
        display: inline-block;
        box-shadow: 0 4px 15px rgba(40, 167, 69, 0.3);
    }
    
    /* Enhanced File Upload Area */
    .file-upload-area {
        border: 3px dashed var(--border-color);
        border-radius: 15px;
        padding: 3rem;
        text-align: center;
        background: var(--light-bg);
        transition: all 0.3s ease;
        cursor: pointer;
    }
    
    .file-upload-area:hover {
        border-color: var(--primary-color);
        background: #e3f2fd;
        transform: translateY(-2px);
        box-shadow: 0 8px 25px rgba(31, 119, 180, 0.15);
    }
    
    /* Status Messages */
    .status-success {
        background: linear-gradient(45deg, #d4edda, #c3e6cb);
        color: #155724;
        padding: 1.2rem;
        border-radius: 10px;
        border-left: 5px solid var(--success-color);
        box-shadow: 0 4px 15px rgba(40, 167, 69, 0.1);
        margin: 1rem 0;
    }
    
    .status-error {
        background: linear-gradient(45deg, #f8d7da, #f5c6cb);
        color: #721c24;
        padding: 1.2rem;
        border-radius: 10px;
        border-left: 5px solid var(--warning-color);
        box-shadow: 0 4px 15px rgba(220, 53, 69, 0.1);
        margin: 1rem 0;
    }
    
    .status-info {
        background: linear-gradient(45deg, #d1ecf1, #bee5eb);
        color: #0c5460;
        padding: 1.2rem;
        border-radius: 10px;
        border-left: 5px solid var(--info-color);
        box-shadow: 0 4px 15px rgba(23, 162, 184, 0.1);
        margin: 1rem 0;
    }
    
    /* Card Design */
    .feature-card {
        background: white;
        border-radius: 15px;
        padding: 1.5rem;
        margin: 1rem 0;
        box-shadow: 0 4px 20px rgba(0,0,0,0.08);
        border: 1px solid var(--border-color);
        transition: all 0.3s ease;
    }
    
    .feature-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 8px 30px rgba(0,0,0,0.12);
    }
    
    /* Button Styling */
    .stButton > button {
        border-radius: 25px;
        font-weight: 600;
        padding: 0.5rem 2rem;
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 15px rgba(0,0,0,0.2);
    }
    
    /* Sidebar Enhancement */
    .css-1d391kg {
        background: linear-gradient(180deg, var(--light-bg), white);
    }
    
    /* Progress Bar */
    .stProgress > div > div > div > div {
        background-color: var(--primary-color);
    }
    
    /* File Info Display */
    .file-info {
        background: var(--light-bg);
        border-radius: 10px;
        padding: 1rem;
        margin: 0.5rem 0;
        border-left: 4px solid var(--info-color);
    }
    
    /* Encryption Method Selector */
    .encryption-selector {
        background: white;
        border-radius: 10px;
        padding: 1.5rem;
        border: 2px solid var(--border-color);
        margin: 1rem 0;
    }
    
    /* Stats Display */
    .stats-container {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 1rem;
        margin: 1rem 0;
    }
    
    .stat-card {
        background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
        color: white;
        padding: 1.5rem;
        border-radius: 15px;
        text-align: center;
        box-shadow: 0 4px 20px rgba(31, 119, 180, 0.3);
    }
    
    .stat-number {
        font-size: 2rem;
        font-weight: 700;
        margin-bottom: 0.5rem;
    }
    
    .stat-label {
        font-size: 0.9rem;
        opacity: 0.9;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'user_info' not in st.session_state:
    st.session_state.user_info = None
if 'session_token' not in st.session_state:
    st.session_state.session_token = None
if 'uploaded_files' not in st.session_state:
    st.session_state.uploaded_files = []
if 'encrypted_files' not in st.session_state:
    st.session_state.encrypted_files = []

def main_header():
    """Display enhanced main application header"""
    st.markdown("""
    <div class="main-header">
        <h1>🔒 Secure File Storage v2.0</h1>
        <p>Enterprise-grade encryption with multi-layer security, file splitting, and cyber attack prevention</p>
        <div class="security-badge">
            🛡️ FIPS 140-2 Compliant | 🔐 End-to-End Encrypted | 🚫 Cyber Attack Protected | ✂️ File Splitting Security
        </div>
    </div>
    """, unsafe_allow_html=True)

def show_stats():
    """Display system statistics"""
    st.markdown("### 📊 System Statistics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        <div class="stat-card">
            <div class="stat-number">🔒</div>
            <div class="stat-label">Encryption Layers</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="stat-card">
            <div class="stat-number">✂️</div>
            <div class="stat-label">File Splitting</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="stat-card">
            <div class="stat-number">🛡️</div>
            <div class="stat-label">Security Features</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown("""
        <div class="stat-card">
            <div class="stat-number">⚡</div>
            <div class="stat-label">Performance</div>
        </div>
        """, unsafe_allow_html=True)

def login_page():
    """Display enhanced login and registration page"""
    st.markdown("## 🔐 Secure Authentication")
    
    # Create tabs for login and registration
    tab1, tab2 = st.tabs(["🔑 Login", "📝 Registration"])
    
    with tab1:
        st.markdown("### Sign In to Your Secure Account")
        
        with st.form("login_form"):
            username = st.text_input("👤 Username", placeholder="Enter your username")
            password = st.text_input("🔒 Password", type="password", placeholder="Enter your password")
            two_fa_token = st.text_input("🔢 2FA Token (if enabled)", placeholder="Enter 6-digit code")
            
            col1, col2 = st.columns([1, 1])
            with col1:
                login_button = st.form_submit_button("🚀 Login", type="primary", use_container_width=True)
            with col2:
                if st.form_submit_button("❓ Forgot Password?", use_container_width=True):
                    st.info("Password reset functionality coming soon!")
            
            if login_button:
                if username and password:
                    # Validate input
                    username_valid, username_msg = validate_user_input(username, 'username')
                    if not username_valid:
                        st.error(username_msg)
                        return
                    
                    # Check rate limiting
                    if not check_rate_limit(f"login_{username}"):
                        st.error("Too many login attempts. Please try again later.")
                        return
                    
                    # Authenticate user
                    success, message, user_data = secure_auth.authenticate_user(
                        username, password, two_fa_token
                    )
                    
                    if success:
                        st.session_state.authenticated = True
                        st.session_state.user_info = user_data['user']
                        st.session_state.session_token = user_data['session_token']
                        st.success("🎉 Login successful! Redirecting to dashboard...")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(message)
                else:
                    st.error("Please enter both username and password")
    
    with tab2:
        st.markdown("### Create Your Secure Account")
        
        with st.form("registration_form"):
            reg_username = st.text_input("👤 Username", placeholder="Choose a username (3-20 characters)")
            reg_email = st.text_input("📧 Email", placeholder="Enter your email address")
            reg_password = st.text_input("🔒 Password", type="password", placeholder="Create a strong password")
            reg_password_confirm = st.text_input("🔐 Confirm Password", type="password", placeholder="Confirm your password")
            enable_2fa = st.checkbox("🔢 Enable Two-Factor Authentication (Recommended)", value=True)
            
            if st.form_submit_button("🚀 Create Account", type="primary", use_container_width=True):
                if reg_username and reg_email and reg_password and reg_password_confirm:
                    # Validate inputs
                    username_valid, username_msg = validate_user_input(reg_username, 'username')
                    if not username_valid:
                        st.error(username_msg)
                        return
                    
                    if reg_password != reg_password_confirm:
                        st.error("Passwords do not match")
                        return
                    
                    password_valid, password_msg = validate_user_input(reg_password, 'password')
                    if not password_valid:
                        st.error(password_msg)
                        return
                    
                    # Register user
                    success, result = secure_auth.register_user(
                        reg_username, reg_email, reg_password, enable_2fa
                    )
                    
                    if success:
                        st.success("🎉 Registration successful!")
                        if enable_2fa and isinstance(result, dict) and 'two_fa_qr' in result:
                            st.info("🔢 2FA Setup Required")
                            st.markdown(f"**2FA Secret:** `{result['two_fa_secret']}`")
                            st.markdown(f"**QR Code URL:** {result['two_fa_qr']}")
                            st.info("Please scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)")
                    else:
                        st.error(result)
                else:
                    st.error("Please fill in all fields")

def dashboard():
    """Display enhanced main dashboard after authentication"""
    user = st.session_state.user_info
    
    # Enhanced sidebar navigation
    with st.sidebar:
        st.markdown(f"## 👤 Welcome, {user['username']}")
        st.markdown(f"**Role:** {user['role'].title()}")
        st.markdown(f"**2FA:** {'✅ Enabled' if user['two_fa_enabled'] else '❌ Disabled'}")
        
        st.markdown("---")
        
        # Navigation menu
        selected = option_menu(
            menu_title="Navigation",
            options=["🏠 Dashboard", "🔒 File Encryption", "🔓 File Decryption", "⚙️ Security Settings", "👤 Account Settings"],
            icons=["house", "lock", "unlock", "shield", "person"],
            menu_icon="cast",
            default_index=0,
            styles={
                "container": {"padding": "0!important", "background-color": "#fafafa"},
                "icon": {"color": "orange", "font-size": "18px"}, 
                "nav-link": {"font-size": "16px", "text-align": "left", "margin":"0px", "--hover-color": "#eee"},
                "nav-link-selected": {"background-color": "#02ab21"},
            }
        )
        
        st.markdown("---")
        
        # Quick stats
        st.markdown("### 📊 Quick Stats")
        st.metric("Files Encrypted", len(st.session_state.encrypted_files))
        st.metric("Files Uploaded", len(st.session_state.uploaded_files))
        
        # Logout button
        if st.button("🚪 Logout", type="secondary", use_container_width=True):
            st.session_state.authenticated = False
            st.session_state.user_info = None
            st.session_state.session_token = None
            st.success("Logged out successfully!")
            st.rerun()
    
    # Main content based on selection
    if selected == "🏠 Dashboard":
        show_dashboard_home()
    elif selected == "🔒 File Encryption":
        show_file_encryption()
    elif selected == "🔓 File Decryption":
        show_file_decryption()
    elif selected == "⚙️ Security Settings":
        show_security_settings()
    elif selected == "👤 Account Settings":
        show_account_settings()

def show_dashboard_home():
    """Display enhanced dashboard home page"""
    st.markdown("## 🏠 Dashboard Home")
    
    # Show system statistics
    show_stats()
    
    # Recent activity
    st.markdown("### 📈 Recent Activity")
    
    if st.session_state.encrypted_files:
        st.markdown("**Recently Encrypted Files:**")
        for file_info in st.session_state.encrypted_files[-3:]:  # Show last 3
            st.markdown(f"""
            <div class="file-info">
                📄 {file_info['filename']} | 🔐 {file_info['encryption_type']} | ⏰ {file_info['timestamp']}
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No files encrypted yet. Start by uploading and encrypting a file!")
    
    # Quick actions
    st.markdown("### ⚡ Quick Actions")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔒 Encrypt File", use_container_width=True, type="primary"):
            st.switch_page("🔒 File Encryption")
    
    with col2:
        if st.button("🔓 Decrypt File", use_container_width=True, type="secondary"):
            st.switch_page("🔓 File Decryption")
    
    with col3:
        if st.button("📁 View Files", use_container_width=True, type="secondary"):
            st.info("File browser coming soon!")

def show_file_encryption():
    """Display enhanced file encryption interface"""
    st.markdown("## 🔒 File Encryption")
    
    # Enhanced file upload area with better styling
    st.markdown("### 📁 Upload File for Encryption")
    
    # Create a more attractive upload area
    st.markdown("""
    <div class="file-upload-area">
        <h3>📤 Drag & Drop or Click to Upload</h3>
        <p>Your file will be encrypted with military-grade encryption algorithms</p>
        <p><strong>Supported:</strong> All file types | <strong>Max Size:</strong> 100MB</p>
    </div>
    """, unsafe_allow_html=True)
    
    uploaded_file = st.file_uploader(
        "Choose a file to encrypt",
        type=None,  # Allow all file types, validation happens later
        help="Select a file to encrypt with military-grade encryption",
        label_visibility="collapsed"
    )
    
    if uploaded_file is not None:
        # Display file information
        file_info = {
            "Name": uploaded_file.name,
            "Size": f"{uploaded_file.size / (1024*1024):.2f} MB",
            "Type": uploaded_file.type or "Unknown"
        }
        
        st.markdown("#### File Information")
        for key, value in file_info.items():
            st.write(f"**{key}:** {value}")
        
        # Enhanced encryption options with better styling
        st.markdown("#### 🔐 Encryption Options")
        
        # Create encryption method selector with better UI
        st.markdown("""
        <div class="encryption-selector">
            <h4>Choose Your Security Level</h4>
            <p>Select the encryption method that best fits your security needs</p>
        </div>
        """, unsafe_allow_html=True)
        
        encryption_type = st.selectbox(
            "🔐 Encryption Method",
            ["split_and_encrypt", "multi_layer", "hybrid"],
            format_func=lambda x: {
                "split_and_encrypt": "✂️ Split + Encrypt (Maximum Security) - Your Original Concept!",
                "multi_layer": "🛡️ Multi-Layer (High Security) - AES + ChaCha20 + Fernet + MultiFernet",
                "hybrid": "🔑 Hybrid (RSA + AES) - Asymmetric + Symmetric Encryption"
            }[x],
            help="Split + Encrypt splits your file into parts before encryption for maximum security"
        )
        
        # Show encryption method details
        if encryption_type == "split_and_encrypt":
            st.info("🎯 **Split + Encrypt**: Your original concept! File is split into parts, each encrypted separately. Even if someone gets a few parts, they can't reconstruct the whole file!")
        elif encryption_type == "multi_layer":
            st.info("🛡️ **Multi-Layer**: File encrypted with 4 different algorithms in sequence for maximum security!")
        elif encryption_type == "hybrid":
            st.info("🔑 **Hybrid**: Combines RSA asymmetric encryption with AES symmetric encryption for optimal security and performance!")
        
        # Enhanced encryption button with progress tracking
        st.markdown("---")
        
        col1, col2 = st.columns([1, 1])
        with col1:
            encrypt_button = st.button("🔒 Encrypt File", type="primary", use_container_width=True)
        with col2:
            if st.button("📋 View Encryption Info", type="secondary", use_container_width=True):
                st.info("""
                **🔐 Encryption Details:**
                - **AES-256-GCM**: Authenticated encryption with 256-bit keys
                - **ChaCha20-Poly1305**: High-performance stream cipher
                - **Fernet**: Symmetric encryption with built-in authentication
                - **MultiFernet**: Multiple encryption keys for enhanced security
                - **RSA-4096**: Asymmetric encryption for key exchange
                """)
        
        if encrypt_button:
            try:
                # Validate file content
                file_content = uploaded_file.read()
                validation_success, validation_msg = validate_uploaded_file(file_content, uploaded_file.name)
                
                if not validation_success:
                    st.error(f"File validation failed: {validation_msg}")
                    return
                
                # Check if it's a media file
                is_media, extension = is_media_file(uploaded_file.name)
                
                with st.spinner("Encrypting file with military-grade encryption..."):
                    # Encrypt file
                    encrypted_content, manifest = encrypt_file_enhanced(
                        file_content, uploaded_file.name, encryption_type
                    )
                    
                    if encryption_type == 'split_and_encrypt':
                        # Handle split and encrypt - save multiple encrypted parts
                        st.markdown("""
                        <div class="status-success">
                            <h3>🎉 File Split and Encrypted Successfully!</h3>
                            <p>Your file has been split into multiple parts and each part encrypted separately for maximum security!</p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # Track in session state
                        file_info = {
                            'filename': uploaded_file.name,
                            'encryption_type': 'Split + Encrypt',
                            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'parts': len(encrypted_content)
                        }
                        st.session_state.encrypted_files.append(file_info)
                        
                        # Save each encrypted part
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
                        
                        with open(manifest_path, 'w') as f:
                            json.dump(manifest, f, indent=2)
                        
                        # Display encryption details in a collapsible section
                        with st.expander("🔍 View Encryption Details", expanded=False):
                            st.json(manifest)
                        
                        # Enhanced download section
                        st.markdown("### 📥 Download Your Encrypted Files")
                        
                        # Create columns for better layout
                        cols = st.columns(min(3, len(part_files)))
                        for i, part_path in enumerate(part_files):
                            col_idx = i % len(cols)
                            with cols[col_idx]:
                                with open(part_path, 'rb') as f:
                                    st.download_button(
                                        label=f"📦 Part {i+1}",
                                        data=f.read(),
                                        file_name=os.path.basename(part_path),
                                        mime="application/octet-stream",
                                        use_container_width=True
                                    )
                        
                        # Download manifest
                        st.markdown("#### 📋 Download Manifest")
                        with open(manifest_path, 'r') as f:
                            st.download_button(
                                label="📥 Download Manifest",
                                data=f.read(),
                                file_name=f"{uploaded_file.name}_split_manifest.json",
                                mime="application/json",
                                use_container_width=True
                            )
                        
                        st.info(f"🔒 File split into {len(encrypted_content)} parts. Each part is individually encrypted.")
                        st.warning("⚠️ You need ALL parts AND the manifest to reconstruct the file!")
                        
                    else:
                        # Handle regular encryption
                        # Track in session state
                        file_info = {
                            'filename': uploaded_file.name,
                            'encryption_type': encryption_type.replace('_', ' ').title(),
                            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'parts': 1
                        }
                        st.session_state.encrypted_files.append(file_info)
                        
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
                        
                        st.markdown("""
                        <div class="status-success">
                            <h3>🎉 File Encrypted Successfully!</h3>
                            <p>Your file has been encrypted with military-grade encryption algorithms!</p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # Display encryption details in a collapsible section
                        with st.expander("🔍 View Encryption Details", expanded=False):
                            st.json(manifest)
                        
                        # Download options
                        st.markdown("### 📥 Download Your Encrypted File")
                        with open(encrypted_file_path, 'rb') as f:
                            st.download_button(
                                label="📥 Download Encrypted File",
                                data=f.read(),
                                file_name=f"{uploaded_file.name}_encrypted.bin",
                                mime="application/octet-stream",
                                use_container_width=True
                            )
                    
                    # Clean up
                    uploaded_file.seek(0)  # Reset file pointer
                    
            except Exception as e:
                st.error(f"Encryption failed: {str(e)}")
                logging.error(f"Encryption error: {e}")

def show_file_decryption():
    """Display file decryption interface"""
    st.markdown("## 🔓 File Decryption")
    
    st.markdown("### Upload Encrypted File for Decryption")
    
    # File upload for decryption
    st.markdown("#### Option 1: Single Encrypted File")
    encrypted_file = st.file_uploader(
        "Choose encrypted file (.bin)",
        type=['bin'],
        help="Select an encrypted file to decrypt"
    )
    
    # Key file upload
    key_file = st.file_uploader(
        "Choose encryption key file (.json)",
        type=['json'],
        help="Select the corresponding encryption key file"
    )
    
    st.markdown("---")
    st.markdown("#### Option 2: Split & Encrypted Files")
    
    # For split-and-encrypt files
    split_manifest = st.file_uploader(
        "Choose split manifest file (.json)",
        type=['json'],
        help="Select the split manifest file for split-and-encrypt files"
    )
    
    if split_manifest:
        st.info("📋 Split manifest detected. Please upload all encrypted part files.")
        
        # Get manifest info to know how many parts to expect
        try:
            manifest_data = json.loads(split_manifest.getvalue().decode())
            total_parts = manifest_data.get('total_parts', 0)
            
            if total_parts > 0:
                st.write(f"**Expected parts:** {total_parts}")
                
                # Upload encrypted parts
                uploaded_parts = []
                for i in range(total_parts):
                    part_file = st.file_uploader(
                        f"Upload encrypted part {i+1}",
                        type=['bin'],
                        key=f"part_{i+1}",
                        help=f"Upload encrypted part {i+1} of {total_parts}"
                    )
                    if part_file:
                        uploaded_parts.append(part_file)
                
                if len(uploaded_parts) == total_parts:
                    st.success(f"✅ All {total_parts} parts uploaded successfully!")
                else:
                    st.warning(f"⚠️ Uploaded {len(uploaded_parts)} of {total_parts} parts")
                    
        except Exception as e:
            st.error(f"Error reading manifest: {str(e)}")
    
    if encrypted_file and key_file:
        st.success("✅ Both encrypted file and key file uploaded")
        
        # Display file information
        col1, col2 = st.columns(2)
        with col1:
            st.write(f"**Encrypted File:** {encrypted_file.name}")
            st.write(f"**Size:** {len(encrypted_file.getvalue())} bytes")
        
        with col2:
            st.write(f"**Key File:** {key_file.name}")
            st.write(f"**Type:** Encryption Keys")
        
        # Decryption options
        st.markdown("#### Decryption Options")
        
        # Create temporary files for processing
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as temp_encrypted:
            temp_encrypted.write(encrypted_file.getvalue())
            temp_encrypted_path = temp_encrypted.name
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as temp_key:
            temp_key.write(key_file.getvalue())
            temp_key_path = temp_key.name
        
        # Decrypt button
        if st.button("🔓 Decrypt File", type="primary"):
            try:
                with st.spinner("Decrypting file with military-grade decryption..."):
                    # Perform decryption
                    decrypted_content, manifest = decrypt_file_enhanced(
                        temp_encrypted_path, 
                        temp_key_path
                    )
                    
                    st.success("✅ File decrypted successfully!")
                    
                    # Display decryption details
                    st.markdown("#### Decryption Details")
                    st.json(manifest)
                    
                    # Determine original filename
                    original_filename = encrypted_file.name.replace('_encrypted.bin', '')
                    
                    # Download decrypted file
                    st.markdown("#### Download Decrypted File")
                    st.download_button(
                        label="📥 Download Decrypted File",
                        data=decrypted_content,
                        file_name=original_filename,
                        mime="application/octet-stream"
                    )
                    
                    # Clean up temporary files
                    os.unlink(temp_encrypted_path)
                    os.unlink(temp_key_path)
                    
            except Exception as e:
                st.error(f"Decryption failed: {str(e)}")
                logging.error(f"Decryption error: {e}")
                
                # Clean up temporary files on error
                try:
                    os.unlink(temp_encrypted_path)
                    os.unlink(temp_key_path)
                except:
                    pass
    
    # Handle split-and-encrypt decryption
    if split_manifest and 'uploaded_parts' in locals() and len(uploaded_parts) == total_parts:
        st.markdown("---")
        st.markdown("#### Split & Encrypt Decryption")
        
        if st.button("🔓 Decrypt Split & Encrypted File", type="primary"):
            try:
                with st.spinner("Decrypting split-and-encrypted file..."):
                    # Create temporary files for all parts
                    temp_files = []
                    
                    try:
                        # Create temporary directory
                        with tempfile.TemporaryDirectory() as temp_dir:
                            # Save all parts to temporary files
                            for i, part_file in enumerate(uploaded_parts):
                                temp_part_path = os.path.join(temp_dir, f"part_{i+1:03d}_encrypted.bin")
                                with open(temp_part_path, 'wb') as f:
                                    f.write(part_file.getvalue())
                                temp_files.append(temp_part_path)
                            
                            # Save manifest to temporary file
                            temp_manifest_path = os.path.join(temp_dir, "manifest.json")
                            with open(temp_manifest_path, 'w') as f:
                                f.write(split_manifest.getvalue().decode())
                            
                            # Save keys to temporary file (assuming we have them)
                            # For now, we'll need the user to provide keys
                            st.info("🔑 Please provide the encryption keys for decryption")
                            
                            # This would need to be implemented based on how keys are stored
                            # For now, we'll show a placeholder
                            st.warning("Key management for split-and-encrypt files needs to be implemented")
                            
                    finally:
                        # Clean up temporary files
                        for temp_file in temp_files:
                            try:
                                os.unlink(temp_file)
                            except:
                                pass
                        
            except Exception as e:
                st.error(f"Split-and-encrypt decryption failed: {str(e)}")
                logging.error(f"Split-and-encrypt decryption error: {e}")

def show_security_settings():
    """Display security settings"""
    st.markdown("## 🛡️ Security Settings")
    
    user = st.session_state.user_info
    
    # 2FA Management
    st.markdown("### Two-Factor Authentication")
    
    if user['two_fa_enabled']:
        st.success("✅ 2FA is currently enabled")
        if st.button("Disable 2FA"):
            st.warning("2FA disable functionality coming soon!")
    else:
        st.warning("❌ 2FA is currently disabled")
        if st.button("Enable 2FA"):
            st.info("2FA enable functionality coming soon!")
    
    # Password Management
    st.markdown("### Password Management")
    
    with st.expander("Change Password"):
        with st.form("change_password_form"):
            current_password = st.text_input("Current Password", type="password")
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm New Password", type="password")
            
            if st.form_submit_button("Change Password"):
                if new_password == confirm_password:
                    success, message = secure_auth.change_password(
                        user['username'], current_password, new_password
                    )
                    if success:
                        st.success(message)
                    else:
                        st.error(message)
                else:
                    st.error("New passwords do not match")
    
    # Security Logs
    st.markdown("### Security Logs")
    st.info("Security logs and audit trails will be available in the next version")

def show_account_settings():
    """Display account settings"""
    st.markdown("## 👤 Account Settings")
    
    user = st.session_state.user_info
    
    # Account Information
    st.markdown("### Account Information")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write(f"**Username:** {user['username']}")
        st.write(f"**Role:** {user['role'].title()}")
    
    with col2:
        st.write(f"**Email:** {user.get('email', 'Not provided')}")
        st.write(f"**Account Status:** {user.get('account_status', 'Active')}")
    
    # Account Actions
    st.markdown("### Account Actions")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Export Account Data"):
            st.info("Account data export functionality coming soon!")
    
    with col2:
        if st.button("Delete Account"):
            st.error("Account deletion functionality coming soon!")

def main():
    """Main application function"""
    main_header()
    
    # Check authentication status
    if not st.session_state.authenticated:
        login_page()
    else:
        # Validate session
        if st.session_state.session_token:
            user_info = secure_auth.validate_session(st.session_state.session_token)
            if user_info:
                st.session_state.user_info = user_info
                dashboard()
            else:
                st.session_state.authenticated = False
                st.session_state.user_info = None
                st.session_state.session_token = None
                st.error("Session expired. Please login again.")
                st.rerun()
        else:
            st.session_state.authenticated = False
            st.rerun()

if __name__ == "__main__":
    main()
