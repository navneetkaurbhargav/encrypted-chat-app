# 🔒 Secure Chat Application with CA Authority

A secure, encrypted chat application featuring Certificate Authority (CA) validation, RSA encryption, AES symmetric encryption, and digital signatures. Built with Python using cryptographic libraries and Tkinter GUI.

## ✨ Features

- **🏛️ Certificate Authority (CA) System**: Mock CA that issues and validates certificates
- **🔐 End-to-End Encryption**: RSA key exchange + AES-256 symmetric encryption
- **✍️ Digital Signatures**: Message authentication using PKCS#1 v1.5 signatures
- **🖥️ GUI Interface**: User-friendly Tkinter-based client and server applications
- **📋 Certificate Management**: Automatic certificate issuance, validation, and registry
- **🔍 Real-time Validation**: Live certificate and signature verification
- **💾 Persistent Storage**: Certificate registry and CA credentials saved to disk

## 🏗️ Architecture

\`\`\`
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CA Authority  │    │     Host A      │    │     Host B      │
│                 │    │                 │    │                 │
│ • Issues Certs  │◄──►│ • Validates     │◄──►│ • Validates     │
│ • Validates     │    │ • Encrypts      │    │ • Encrypts      │
│ • Signs         │    │ • Signs Msgs    │    │ • Signs Msgs    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
\`\`\`

### Security Flow

1. **Certificate Issuance**: CA generates and signs certificates for server and clients
2. **Certificate Exchange**: Server and client exchange certificates during handshake
3. **Certificate Validation**: Both parties validate certificates against CA
4. **Key Exchange**: RSA public key exchange for AES key distribution
5. **Secure Communication**: AES-encrypted messages with RSA digital signatures

## 🚀 Quick Start

### Prerequisites

- Python 3.7+
- Virtual environment (recommended)

### Installation

1. **Clone and setup**:
   \`\`\`bash
   git clone <repository-url>
   cd secure-chat-app
   chmod +x setup.sh
   ./setup.sh
   \`\`\`

2. **Activate virtual environment**:
   \`\`\`bash
   source venv/bin/activate
   \`\`\`

### Running the Application

1. **Start the Server**:
   \`\`\`bash
   python hostA.py
   \`\`\`
   - Click "Start Host A" in the GUI
   - Default: `127.0.0.1:12000`

2. **Start the Client**:
   \`\`\`bash
   python hostB.py
   \`\`\`
   - Enter username
   - Click "Connect"
   - Start chatting securely!

## 📁 Project Structure

\`\`\`
secure-chat-app/
├── README.md              # This file
├── setup.sh               # Setup script
├── requirements.txt       # Python dependencies
├── hostA.py               # host A application
├── hostB.py               # host B application
├── cert_utils.py          # CA Authority implementation
├── certs/                 # Certificate storage (auto-created)
│   ├── ca_cert.pem        # CA certificate
│   ├── ca_private_key.pem # CA private key
│   ├── cert_registry.json # Certificate registry
│   └── *.pem              # Issued certificates
└── venv/                  # Virtual environment (auto-created)
\`\`\`

## 🔧 Technical Details

### Cryptographic Components

| Component | Algorithm | Key Size | Purpose |
|-----------|-----------|----------|---------|
| **CA Certificate** | RSA | 2048-bit | Certificate signing |
| **Entity Certificates** | RSA | 2048-bit | Identity verification |
| **Key Exchange** | RSA-OAEP | 2048-bit | AES key distribution |
| **Message Encryption** | AES-CBC | 256-bit | Bulk data encryption |
| **Digital Signatures** | PKCS#1 v1.5 | SHA-256 | Message authentication |

### Libraries Used

- **cryptography**: Certificate management and X.509 operations
- **pycryptodome**: RSA encryption/decryption and digital signatures
- **tkinter**: GUI framework
- **json**: Certificate registry storage

### Security Features

- ✅ **Certificate Validation**: All certificates validated against CA
- ✅ **Signature Verification**: Every message digitally signed and verified
- ✅ **Forward Secrecy**: New AES keys for each session
- ✅ **Integrity Protection**: Messages cannot be tampered with
- ✅ **Authentication**: Identity verification through certificates
- ✅ **Encryption**: All communication encrypted end-to-end

## 🎯 Usage Examples

### host A Operations

```python
# Server automatically:
# 1. Gets certificate from CA
# 2. Starts listening for connections
# 3. Validates host B certificates
# 4. Establishes encrypted channels
# 5. Verifies message signatures

### **Simmilary host B start listening to the connection and communicate as mentioned above **
