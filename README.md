# 🔐 Key Managment System

## Overview

This Secure Key Managment System is a comprehensive Python-based application designed to provide robust encryption, key management, and certificate handling capabilities. This system offers a wide range of cryptographic functionalities to enhance security for various applications.

## 🌟 Key Features

### Encryption Capabilities
- AES Symmetric Encryption
- RSA Asymmetric Encryption
- Diffie-Hellman Key Exchange
- Secure Key Derivation
- Message Encryption/Decryption

### Certificate Management
- Root CA Generation
- Certificate Signing Request (CSR) Creation
- Certificate Signing
- Certificate Verification
- Certificate Revocation
- Certificate Revocation List (CRL) Management

### Key Management
- Key Generation (AES, RSA, Diffie-Hellman)
- Key Storage
- Key Revocation Tracking

## 🏗️ System Architecture

### Architectural Components

1. **Cryptographic Primitives Layer**
   - Uses `cryptography` library for core cryptographic operations
   - Implements secure key generation and management
   - Supports multiple encryption algorithms and modes

2. **Key Management Subsystem**
   - Handles key generation, storage, and revocation
   - Maintains a JSON-based revoked keys registry
   - Provides secure key loading with revocation checks

3. **Certificate Management Module**
   - Supports X.509 certificate lifecycle management
   - Implements Root CA and user certificate workflows
   - Provides certificate verification and revocation mechanisms

4. **Encryption Services**
   - Symmetric Encryption (AES-CBC with PKCS7 padding)
   - Asymmetric Encryption (RSA with OAEP padding)
   - Secure key exchange (Diffie-Hellman)

5. **User Interface**
   - Interactive command-line menu
   - User-friendly cryptographic operations selection

## 🌐 Public Key Infrastructure (PKI) Implementation

### PKI Components and Workflow

#### 1. Root Certificate Authority (Root CA)
- Generates a self-signed root certificate
- Acts as the trusted anchor for the entire PKI
- Uses 2048-bit RSA key for maximum compatibility
- Certificate includes:
  - Distinguished Name (DN) information
  - Basic Constraints (CA=True)
  - 10-year validity period

#### 2. Certificate Signing Request (CSR) Generation
- Allows creation of user/entity certificates
- Includes organizational and personal details
- Supports standard X.509 certificate attributes
- Generates a unique private key for each CSR

#### 3. Certificate Signing Process
- Root CA signs user certificates
- Applies digital signature using Root CA's private key
- Implements cryptographic verification mechanisms
- Sets certificate validity (default: 1 year)

#### 4. Certificate Revocation
- Supports Certificate Revocation List (CRL) management
- Allows immediate invalidation of compromised certificates
- Provides real-time revocation status checking

### PKI Security Features
- Hierarchical trust model
- Cryptographically secure certificate signing
- Comprehensive certificate lifecycle management
- Detailed revocation tracking
- Support for multiple organizational units

## 🛠️ Dependencies

- Python 3.8+
- `cryptography` library
- `base64`
- `os`
- `datetime`
- `json`

## 📦 Installation

```bash
# Clone the repository
https://github.com/kushagr1501/ins_t2.git

# Install dependencies
pip install cryptography
```

## 🚀 Usage

Run the script and select from the interactive menu:

```bash
python crypto_toolkit.py
```

### Menu Options
1. Generate AES Key
2. Generate Diffie-Hellman Key Pair
3. Generate Shared Secret
4. Encrypt Message (AES)
5. Decrypt Message (AES)
6. Generate RSA Key Pair
7. Encrypt Message (RSA)
8. Decrypt Message (RSA)
9. Generate Root CA
10. Generate User CSR
11. Sign User Certificate
12. Verify Certificate
13. Revoke Certificate
14. Check Certificate Revocation
15. Revoke a Key
16. Check Key Revocation
17. Load a Key
18. Exit

## 🔒 Security Notes

- Always protect your private keys
- Use strong, unique passphrases
- Regularly rotate keys
- Implement additional access controls in production
- Maintain secure storage of Root CA private key

## 📄 License

[Specify your license, e.g., MIT License]

## 🤝 Contributing

Contributions are welcome! Please read the contributing guidelines before submitting pull requests.

## ⚠️ Disclaimer

This toolkit is for educational and development purposes. Always consult security professionals for critical applications.
