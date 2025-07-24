from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import datetime
import os
from cryptography.hazmat.backends import default_backend
import json

class CA_Authority:
    """Mock Certificate Authority for validating certificates and signatures"""
    
    def __init__(self):
        self.ca_private_key = None
        self.ca_cert = None
        self.issued_certificates = {}  # Track issued certificates
        self.setup_ca()
    
    def setup_ca(self):
        """Initialize the Certificate Authority"""
        ca_cert_path = 'certs/ca_cert.pem'
        ca_key_path = 'certs/ca_private_key.pem'
        registry_path = 'certs/cert_registry.json'

        # Load existing CA or create new one
        if os.path.exists(ca_cert_path) and os.path.exists(ca_key_path):
            self.load_ca_from_files(ca_cert_path, ca_key_path)
            print("✓ CA Authority loaded from existing files")
        else:
            self.generate_ca_certificate()
            self.save_ca_to_files(ca_cert_path, ca_key_path)
            print("✓ CA Authority created and saved")
        
        # Load certificate registry

        self.load_certificate_registry(registry_path)
        # Verify CA is properly initialized
        if self.ca_cert is None or self.ca_private_key is None:
            raise Exception("Failed to initialize CA Authority - certificate or private key is None")
    

    def generate_ca_certificate(self):
        """Generate CA certificate and private key"""
        # Generate CA private key
        self.ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048, backend = default_backend()
        )
        
        # Create CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Secure Chat CA Authority"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Chat Inc"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ])
        
        self.ca_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.ca_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True,
        ).add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ), critical=True,
        ).sign(self.ca_private_key, hashes.SHA256(), default_backend())
    
    def issue_certificate(self, common_name, cert_type="client"):
        """Issue a certificate signed by the CA"""
        # Generate private key for the certificate
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048, backend = default_backend()
        )
        
        # Create subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"Secure Chat {cert_type.title()}"),
        ])
        
        # Create certificate signed by CA
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_cert.subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=30)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        ).add_extension(
            x509.KeyUsage(
                key_cert_sign=False,
                crl_sign=False,
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ), critical=True,
        ).sign(self.ca_private_key, hashes.SHA256(), default_backend())
        
        # Store issued certificate
        serial_number = str(cert.serial_number)
        self.issued_certificates[serial_number] = {
            'common_name': common_name,
            'type': cert_type,
            'issued_at': datetime.datetime.utcnow().isoformat(),
            'expires_at': (datetime.datetime.utcnow() + datetime.timedelta(days=30)).isoformat(),
            'cert_file': f"{cert_type}_{common_name.replace(' ', '_').replace('-', '_')}_{serial_number}.pem"
        }
   
        
        # Save certificate to file
        cert_filename = f"certs/{self.issued_certificates[serial_number]['cert_file']}"
        try:
            with open(cert_filename, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
        except Exception as e:
            print(f"Warning: Could not save certificate to file: {e}")
        
        # Update registry
        self.save_certificate_registry('certs/cert_registry.json')
        
        print(f"✓ CA Authority issued certificate for: {common_name}")
        return cert, private_key
    
    def validate_certificate(self, cert):
        """Validate certificate against CA"""
        try:
            
            # Check if CA is properly initialized
            if self.ca_cert is None:
                return False, "CA certificate not initialized"            
            if cert is None:
                return False, "Certificate is None"

            # Check if certificate was issued by this CA
            if cert.issuer != self.ca_cert.subject:
                return False, "Certificate not issued by trusted CA"
            
            # Check expiration
            now = datetime.datetime.utcnow()
            if now < cert.not_valid_before:
                return False, "Certificate not yet valid"
            if now > cert.not_valid_after:
                return False, "Certificate expired"
            
            # Verify the certificate's signature using the CA's public key
            try:
                public_key = self.ca_cert.public_key()
                public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm
                )
                return True, "Certificate valid"
            except Exception as e:
                return False, f"Certificate signature verification failed: {e}"
                
        except Exception as e:
            return False, f"Validation error: {e}"
    
    def validate_signature(self, cert, message, signature):
        """Validate message signature using certificate"""
        try:
            # First validate the certificate
            is_valid, msg = self.validate_certificate(cert)
            if not is_valid:
                return False, f"Invalid certificate: {msg}"
            
            # Extract public key from certificate
            public_key = cert.public_key()
            
            try:
                public_key.verify(
                    signature,
                    message.encode(),
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                return True, "Signature valid"
            except Exception as e:
                return False, f"Signature verification failed: {e}"
                
        except Exception as e:
            return False, f"Signature validation error: {e}"
    
    def get_ca_certificate(self):
        """Get CA certificate for distribution"""
        return self.ca_cert
    
    def get_cert_info(self, cert):
        """Get certificate information"""
        try:
            common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            serial_number = cert.serial_number
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after
            
            # Check if certificate is in our registry
            is_registered = str(serial_number) in self.issued_certificates
            return {
                'common_name': common_name,
                'serial_number': serial_number,
                'valid_from': not_before,
                'valid_until': not_after,
                'is_ca_issued': is_registered
            }
        except:
            return {'common_name': 'Unknown', 'serial_number': 0, 'is_ca_issued': False}
    
    def save_ca_to_files(self, cert_path, key_path):
        """Save CA certificate and private key to files"""
        os.makedirs(os.path.dirname(cert_path), exist_ok=True)
        
        # Save certificate
        with open(cert_path, 'wb') as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))
        
        # Save private key
        with open(key_path, 'wb') as f:
            f.write(self.ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
    
    def load_ca_from_files(self, cert_path, key_path):
        """Load CA certificate and private key from files"""
        try:
            # Load certificate
            with open(cert_path, 'rb') as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            # Load private key
            with open(key_path, 'rb') as f:
                self.ca_private_key = serialization.load_pem_private_key(
                    f.read(), password=None,
                    backend=default_backend()
                )
            
            return True
        except Exception as e:
            print(f"Error loading CA from files: {e}")
            return False

    def save_certificate_registry(self, registry_path):

        """Save certificate registry to file"""
        try:
            # Only save JSON-serializable data
            registry_data = {}
            for serial, cert_info in self.issued_certificates.items():
                registry_data[serial] = {
                    'common_name': cert_info['common_name'],
                    'type': cert_info['type'],
                    'issued_at': cert_info['issued_at'],
                    'expires_at': cert_info['expires_at'],
                    'cert_file': cert_info.get('cert_file', '')
                }
            with open(registry_path, 'w') as f:
                json.dump(registry_data, f, indent=2)
            return True            
        except Exception as e:
            print(f"Error saving certificate registry: {e}")
            return False

    def load_certificate_registry(self, registry_path):

        """Load certificate registry from file"""
        try:
            if os.path.exists(registry_path):
                with open(registry_path, 'r') as f:
                    self.issued_certificates = json.load(f)
                print(f"✓ Loaded {len(self.issued_certificates)} certificates from registry")
            else:
                self.issued_certificates = {}
            return True
        except Exception as e:
            print(f"Error loading certificate registry: {e}")
            self.issued_certificates = {}
            return False

# Global CA Authority instance
ca_authority = CA_Authority()
