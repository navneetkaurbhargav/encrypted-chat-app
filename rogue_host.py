from socket import *
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import threading
import json
import tkinter as tk
from tkinter import scrolledtext, messagebox
import datetime
from cryptography.hazmat.backends import default_backend

class RogueClient:
    """Malicious client that tries to connect with fake/invalid certificates"""
    
    def __init__(self):
        self.client_socket = None
        self.aes_key = None
        self.server_public_key = None
        self.client_private_key = None
        self.client_public_key = None
        self.username = None
        self.connected = False
        
        # Certificate management
        self.fake_cert = None
        self.fake_cert_private_key = None
        self.server_cert = None
        self.ca_cert = None
        
        # Generate client keys
        self.generate_client_keys()
        
        # Setup GUI
        self.setup_gui()
    
    def generate_client_keys(self):
        """Generate client RSA keys for encryption"""
        key = RSA.generate(2048)
        self.client_private_key = key
        self.client_public_key = key.publickey()
    
    def create_fake_certificate(self, attack_type="self_signed"):
        """Create different types of fake certificates for demo"""
        
        # Generate private key for the fake certificate
        self.fake_cert_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048, backend = default_backend()
        )
        
        if attack_type == "self_signed":
            # Create self-signed certificate (not signed by CA)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, f"FAKE-{self.username}"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Malicious Org"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
            ])
            
            self.fake_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer  # Self-signed!
            ).public_key(
                self.fake_cert_private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=30)
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True,
            ).sign(self.fake_cert_private_key, hashes.SHA256(), default_backend())  # Self-signed!
            
            self.add_to_chat("Created SELF-SIGNED certificate (will be rejected)")
            
        elif attack_type == "expired":
            # Create expired certificate
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, f"EXPIRED-{self.username}"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Expired Cert Org"),
            ])
            
            # Make it look like it was issued by CA but expired
            issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "Secure Chat CA Authority"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Chat Inc"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            ])
            
            self.fake_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                self.fake_cert_private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow() - datetime.timedelta(days=60)  # Started 60 days ago
            ).not_valid_after(
                datetime.datetime.utcnow() - datetime.timedelta(days=30)  # Expired 30 days ago
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True,
            ).sign(self.fake_cert_private_key, hashes.SHA256(), default_backend())
            
            self.add_to_chat("Created EXPIRED certificate (will be rejected)")
            
        elif attack_type == "wrong_issuer":
            # Create certificate with wrong issuer name
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, f"FAKE-CA-{self.username}"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fake CA Org"),
            ])
            
            # Wrong issuer name
            issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "FAKE CA Authority"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Malicious CA Inc"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
            ])
            
            self.fake_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer  # Wrong issuer!
            ).public_key(
                self.fake_cert_private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=30)
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True,
            ).sign(self.fake_cert_private_key, hashes.SHA256(), default_backend())
            
            self.add_to_chat("Created certificate with WRONG ISSUER (will be rejected)")
    
    def setup_gui(self):
        self.root = tk.Tk()
        self.root.title("ROGUE Host - Certificate Attack Demo")
        self.root.geometry("700x600")
        self.root.configure(bg="#ffeeee")  # Light red background
        
        # Warning banner
        warning_frame = tk.Frame(self.root, bg="#ff4444")
        warning_frame.pack(fill=tk.X, pady=2)
        tk.Label(warning_frame, text="MALICIOUS host - FOR DEMO PURPOSES ONLY ⚠️", 
                font=("Arial", 12, "bold"), fg="white", bg="#ff4444").pack(pady=5)
        
        # Connection frame
        conn_frame = tk.Frame(self.root, bg="#ffeeee")
        conn_frame.pack(pady=10)
        
        tk.Label(conn_frame, text="Host:", font=("Arial", 10), bg="#ffeeee").pack(side=tk.LEFT)
        self.server_ip_entry = tk.Entry(conn_frame, width=15)
        self.server_ip_entry.insert(0, "127.0.0.1")
        self.server_ip_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(conn_frame, text="Port:", font=("Arial", 10), bg="#ffeeee").pack(side=tk.LEFT)
        self.server_port_entry = tk.Entry(conn_frame, width=8)
        self.server_port_entry.insert(0, "12000")
        self.server_port_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(conn_frame, text="Fake Username:", font=("Arial", 10), bg="#ffeeee").pack(side=tk.LEFT)
        self.username_entry = tk.Entry(conn_frame, width=12)
        self.username_entry.insert(0, "hacker")
        self.username_entry.pack(side=tk.LEFT, padx=5)
        
        # Attack type selection
        attack_frame = tk.Frame(self.root, bg="#ffeeee")
        attack_frame.pack(pady=10)
        
        tk.Label(attack_frame, text="Attack Type:", font=("Arial", 10, "bold"), bg="#ffeeee").pack(side=tk.LEFT)
        
        self.attack_type = tk.StringVar(value="self_signed")
        
        tk.Radiobutton(attack_frame, text="Self-Signed Cert", variable=self.attack_type, 
                      value="self_signed", bg="#ffeeee").pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(attack_frame, text="Expired Cert", variable=self.attack_type, 
                      value="expired", bg="#ffeeee").pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(attack_frame, text="Wrong Issuer", variable=self.attack_type, 
                      value="wrong_issuer", bg="#ffeeee").pack(side=tk.LEFT, padx=5)
        
        # Control buttons
        btn_frame = tk.Frame(self.root, bg="#ffeeee")
        btn_frame.pack(pady=10)
        
        self.attack_btn = tk.Button(btn_frame, text="Launch Attack", command=self.launch_attack,
                                   bg="#ff6666", fg="white", font=("Arial", 10, "bold"))
        self.attack_btn.pack(side=tk.LEFT, padx=5)
        
        self.disconnect_btn = tk.Button(btn_frame, text="Disconnect", command=self.disconnect,
                                       state=tk.DISABLED, bg="#666666", fg="white")
        self.disconnect_btn.pack(side=tk.LEFT, padx=2)
        
        # Status
        self.status_label = tk.Label(self.root, text="Status: Ready to Attack", 
                                    fg="red", font=("Arial", 10, "bold"), bg="#ffeeee")
        self.status_label.pack(pady=5)
        
        # Attack log
        tk.Label(self.root, text="Attack Log:", font=("Arial", 10, "bold"), bg="#ffeeee").pack(anchor="w", padx=5)
        self.chat_display = scrolledtext.ScrolledText(self.root, height=25, state=tk.DISABLED, bg="#fff5f5")
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Initial message
        self.add_to_chat("Rogue Client Ready - Select attack type and target server")
        self.add_to_chat("This client will attempt to connect with invalid certificates")
        self.add_to_chat("Server should REJECT the connection and show validation errors")
    
    def launch_attack(self):
        try:
            server_ip = self.server_ip_entry.get()
            server_port = int(self.server_port_entry.get())
            self.username = self.username_entry.get().strip()
            attack_type = self.attack_type.get()
            
            if not self.username:
                messagebox.showwarning("Error", "Please enter a fake username!")
                return
            
            self.add_to_chat(f"Starting {attack_type} attack against {server_ip}:{server_port}")
            
            # Create fake certificate based on attack type
            self.create_fake_certificate(attack_type)
            
            # Create socket and connect
            self.client_socket = socket(AF_INET, SOCK_STREAM)
            self.client_socket.connect((server_ip, server_port))
            
            self.add_to_chat(f"Connected to server, preparing to send fake certificate...")
            
            # Receive server certificate (we'll ignore validation)
            cert_length = int.from_bytes(self.client_socket.recv(4), 'big')
            server_cert_pem = self.client_socket.recv(cert_length)
            self.server_cert = x509.load_pem_x509_certificate(server_cert_pem, default_backend())
            
            # Receive CA certificate
            ca_cert_length = int.from_bytes(self.client_socket.recv(4), 'big')
            ca_cert_pem = self.client_socket.recv(ca_cert_length)
            self.ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())
            
            self.add_to_chat("📨 Received server and CA certificates")
            
            # Send our FAKE certificate
            fake_cert_pem = self.fake_cert.public_bytes(serialization.Encoding.PEM)
            self.client_socket.send(len(fake_cert_pem).to_bytes(4, 'big'))
            self.client_socket.send(fake_cert_pem)
            
            self.add_to_chat(f"Sent FAKE certificate to server ({attack_type})")
            self.add_to_chat("Waiting for server response...")
            
            # Try to continue with the handshake (this should fail)
            try:
                # Server should close connection, but let's try to receive RSA key
                server_public_key_data = self.client_socket.recv(2048)
                if server_public_key_data:
                    self.add_to_chat("SECURITY BREACH: Server accepted fake certificate!")
                else:
                    self.add_to_chat("SUCCESS: Server rejected fake certificate (connection closed)")
            except:
                self.add_to_chat("SUCCESS: Server rejected fake certificate (connection closed)")
            
            self.attack_btn.config(state=tk.NORMAL)
            self.disconnect_btn.config(state=tk.DISABLED)
            self.status_label.config(text="Status: Attack Completed")
            
        except Exception as e:
            self.add_to_chat(f"Attack failed due to network error: {e}")
            self.add_to_chat("This might mean server rejected connection immediately")
            if hasattr(self, 'client_socket') and self.client_socket:
                self.client_socket.close()
    
    def disconnect(self):
        self.connected = False
        if self.client_socket:
            self.client_socket.close()
        
        self.attack_btn.config(state=tk.NORMAL)
        self.disconnect_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Disconnected")
        self.add_to_chat("Disconnected from server")
    
    def add_to_chat(self, message):
        """Add message to attack log"""
        try:
            def update_text():
                try:
                    self.chat_display.config(state=tk.NORMAL)
                    self.chat_display.insert(tk.END, message + "\n")
                    self.chat_display.see(tk.END)
                    self.chat_display.config(state=tk.DISABLED)
                except Exception as e:
                    print(f"Error updating chat display: {e}")
            
            self.root.after(0, update_text)
        except Exception as e:
            print(f"Failed to add message to chat: {e}")
    
    def on_closing(self):
        if self.connected:
            self.disconnect()
        self.root.destroy()
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    print("Starting Rogue host for Certificate Attack Demo...")
    print("This is for educational/demo purposes only!")
    rogue_client = RogueClient()
    rogue_client.run()
