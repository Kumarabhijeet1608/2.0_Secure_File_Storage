# Secure File Storage Using Hybrid Cryptography

## Project Overview

This project is a secure file storage system designed to ensure data confidentiality in various settings, including corporate networks, government systems, and personal privacy. The system employs hybrid cryptography, combining symmetric and asymmetric encryption techniques, and integrates with Amazon S3 cloud storage for robust data management.

## Key Features
- **Hybrid Cryptography**: Utilizes symmetric (AES-GCM, ChaCha20Poly1305) and asymmetric (Fernet, MultiFernet) encryption to ensure data security.
- **Web UI**: Implemented using Python's Streamlit for a user-friendly interface.
- **Cloud Integration**: Integrates with Amazon S3 for storage, managed via AWS Key Management System (KMS).
- **Secure Communication**: Ensures secure data transmission with SSL/TLS protocols.
- **User Access Control**: Implements password hashing and two-factor authentication for secure user access.
- **Unit Testing**: Conducted comprehensive unit testing to ensure system robustness.

## Project Structure
The project consists of the following key files:

- **aws_config.py**: Configures and manages AWS settings.
- **config.py**: Contains general configuration settings.
- **decrypt.py**: Handles decryption processes.
- **encrypt.py**: Manages encryption processes.
- **file.py**: Manages file operations and interactions.
- **file_checker.py**: Checks and validates files.
- **keys.py**: Handles key generation and management.
- **main.py**: The main entry point for the application.
- **processing.py**: Manages data processing tasks.
- **test.py**: Contains unit tests for the application.
- **threads.py**: Manages threading for concurrent operations.

## Getting Started

### Prerequisites
- Python 3.x
- AWS Account with access to S3 and KMS
- Streamlit
- Boto3 (AWS SDK for Python)
- Cryptography library for Python

### Installation

1. **Clone the Repository**
    ```bash
    git clone https://github.com/yourusername/secure-file-storage.git
    cd secure-file-storage
    ```

2. **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

3. **Configure AWS**
    - Set up your AWS credentials and configuration in `aws_config.py`.

4. **Set Up Configuration**
    - Update the `config.py` file with your specific settings, such as encryption keys, storage paths, and authentication details.

### Running the Application

1. **Start the Web UI**
    ```bash
    streamlit run main.py
    ```

2. **Access the Application**
    - Open your web browser and navigate to `http://localhost:8501` to access the application.

## How It Works

### Encryption and Decryption
- **Encryption (encrypt.py)**: 
  - Uses AES-GCM and ChaCha20Poly1305 for symmetric encryption.
  - Utilizes Fernet and MultiFernet for asymmetric encryption.
  - Encrypts files before uploading them to S3.

- **Decryption (decrypt.py)**: 
  - Retrieves encrypted files from S3.
  - Decrypts files using the appropriate keys and algorithms.

### File Management
- **File Operations (file.py)**: Handles uploading, downloading, and deleting files.
- **File Validation (file_checker.py)**: Ensures the integrity and validity of files before processing.

### Security Features
- **SSL/TLS**: Ensures secure communication between the client and server.
- **Password Hashing**: Uses strong hashing algorithms to securely store user passwords.
- **Two-Factor Authentication**: Adds an extra layer of security for user access.

### AWS Integration
- **AWS Configuration (aws_config.py)**: Manages AWS S3 and KMS settings.
- **Key Management (keys.py)**: Handles encryption key generation and management using AWS KMS.

### Data Processing
- **Processing (processing.py)**: Manages data processing tasks such as encryption, decryption, and file handling.

### Unit Testing
- **Tests (test.py)**: Contains unit tests to ensure the functionality and robustness of the application.

### Concurrency
- **Thread Management (threads.py)**: Utilizes threading to handle concurrent file operations efficiently.

## Testing

To run the unit tests, use the following command:
```bash
python -m unittest test.py
