from socket import *
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import serialization
from cryptography import x509
import threading
import json
import tkinter as tk
from tkinter import scrolledtext, messagebox
from cert_utils import ca_authority
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class SecureChatClient:
    def __init__(self):
        self.client_socket = None
        self.aes_key = None
        self.server_public_key = None
        self.client_private_key = None
        self.client_public_key = None
        self.username = None
        self.connected = False
        
        # Certificate management
        self.client_cert = None
        self.client_cert_private_key = None
        self.server_cert = None
        self.ca_cert = None
        
        # Generate Host B keys
        self.generate_client_keys()
        
        # Setup GUI
        self.setup_gui()
    
    def generate_client_keys(self):
        """Generate Host B RSA keys for encryption"""
        key = RSA.generate(2048)
        self.client_private_key = key
        self.client_public_key = key.publickey()
    
    def setup_gui(self):
        self.root = tk.Tk()
        self.root.title("Secure Chat Host B - CA Validated")
        self.root.geometry("550x450")
        
        # Connection frame
        conn_frame = tk.Frame(self.root)
        conn_frame.pack(pady=10)
        
        tk.Label(conn_frame, text="Host A:", font=("Arial", 10)).pack(side=tk.LEFT)
        self.server_ip_entry = tk.Entry(conn_frame, width=15)
        self.server_ip_entry.insert(0, "127.0.0.1")
        self.server_ip_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(conn_frame, text="Port:", font=("Arial", 10)).pack(side=tk.LEFT)
        self.server_port_entry = tk.Entry(conn_frame, width=8)
        self.server_port_entry.insert(0, "12000")
        self.server_port_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(conn_frame, text="Username:", font=("Arial", 8)).pack(side=tk.LEFT)
        self.username_entry = tk.Entry(conn_frame, width=12)
        self.username_entry.pack(side=tk.LEFT, padx=5)
        
        self.connect_btn = tk.Button(conn_frame, text="Connect", command=self.connect_to_server,
                                    bg="green", fg="white")
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        
        self.disconnect_btn = tk.Button(conn_frame, text="Disconnect", command=self.disconnect,
                                       state=tk.DISABLED, bg="red", fg="white")
        self.disconnect_btn.pack(side=tk.LEFT, padx=2)
        
        # Certificate info frame
        self.cert_frame = tk.Frame(self.root)
        self.cert_frame.pack(pady=5)
        
        self.cert_info_label = tk.Label(self.cert_frame, text="No certificate issued", 
                                       font=("Arial", 7), fg="gray")
        self.cert_info_label.pack()
        
        # Status
        self.status_label = tk.Label(self.root, text="Status: Not Connected", 
                                    fg="red", font=("Arial", 7, "bold"))
        self.status_label.pack(pady=5)
        
        # Chat display
        tk.Label(self.root, text="Chat Messages:", font=("Arial", 8, "bold")).pack(anchor="w", padx=5)
        self.chat_display = scrolledtext.ScrolledText(self.root, height=20, state=tk.DISABLED)
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Message input
        input_frame = tk.Frame(self.root)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(input_frame, text="Message:").pack(side=tk.LEFT)
        self.message_entry = tk.Entry(input_frame, state=tk.NORMAL)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.message_entry.bind('<Return>', self.send_message)
        
        self.send_btn = tk.Button(input_frame, text="Send", command=self.send_message,
                                 state=tk.DISABLED, bg="blue", fg="white")
        self.send_btn.pack(side=tk.RIGHT)
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def connect_to_server(self):
        try:
            server_ip = self.server_ip_entry.get()
            server_port = int(self.server_port_entry.get())
            self.username = self.username_entry.get().strip()
            
            if not self.username:
                messagebox.showwarning("Error", "Please enter a username!")
                return
            
            # Get certificate from CA Authority
            self.client_cert, self.client_cert_private_key = ca_authority.issue_certificate(
                f"client-{self.username}", "client"
            )
            
            cert_info = ca_authority.get_cert_info(self.client_cert)
            self.cert_info_label.config(
                text=f"Certificate: {cert_info['common_name']} (Serial: {cert_info['serial_number']})",
                fg="green"
            )
            
            self.add_to_chat(f"Certificate issued by CA Authority for: {self.username}")
            
            # Create socket and connect
            self.client_socket = socket(AF_INET, SOCK_STREAM)
            self.client_socket.connect((server_ip, server_port))
            
            # Receive Host A certificate
            cert_length = int.from_bytes(self.client_socket.recv(4), 'big')
            server_cert_pem = self.client_socket.recv(cert_length)
            self.server_cert = x509.load_pem_x509_certificate(server_cert_pem, default_backend())
            
            # Receive CA certificate
            ca_cert_length = int.from_bytes(self.client_socket.recv(4), 'big')
            ca_cert_pem = self.client_socket.recv(ca_cert_length)
            self.ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())
            
            # Validate Host A certificate with CA Authority
            is_valid, msg = ca_authority.validate_certificate(self.server_cert)
            if not is_valid:
                messagebox.showerror("Error", f"Host A certificate validation failed: {msg}")
                self.client_socket.close()
                return
            
            server_info = ca_authority.get_cert_info(self.server_cert)
            self.add_to_chat(f"Host A certificate validated by CA: {server_info['common_name']}")
            
            # Send client certificate
            client_cert_pem = self.client_cert.public_bytes(serialization.Encoding.PEM)
            self.client_socket.send(len(client_cert_pem).to_bytes(4, 'big'))
            self.client_socket.send(client_cert_pem)
            
            # Receive Host A's RSA public key
            server_public_key_data = self.client_socket.recv(2048)
            self.server_public_key = RSA.import_key(server_public_key_data)
            
            # Generate and send AES key
            self.aes_key = get_random_bytes(16)
            encrypted_key = self.rsa_encrypt(self.server_public_key, self.aes_key)
            self.client_socket.send(encrypted_key)
            
            # Send username
            encrypted_username = self.aes_encrypt(self.username, self.aes_key)
            self.client_socket.send(encrypted_username)
            
            self.connected = True
            self.connect_btn.config(state=tk.DISABLED)
            self.disconnect_btn.config(state=tk.NORMAL)
            self.send_btn.config(state=tk.NORMAL)
            self.status_label.config(text=f"Status: Connected as {self.username}", fg="green")
            
            threading.Thread(target=self.listen_for_messages, daemon=True).start()
            
            self.add_to_chat("Connected with CA Authority certificate validation")
            self.add_to_chat("Secure communication established")
            
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")
            if hasattr(self, 'client_socket') and self.client_socket:
                self.client_socket.close()
    
    def disconnect(self):
        self.connected = False
        if self.client_socket:
            self.client_socket.close()
        
        self.connect_btn.config(state=tk.NORMAL)
        self.disconnect_btn.config(state=tk.DISABLED)
        self.send_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Not Connected", fg="red")
        self.cert_info_label.config(text="No certificate issued", fg="gray")
        self.add_to_chat("Disconnected from Host A")
    
    def listen_for_messages(self):
        while self.connected:
            try:
                encrypted_message = self.client_socket.recv(4096)
                if not encrypted_message:
                    break
                
                decrypted_package = self.aes_decrypt(encrypted_message, self.aes_key)
                msg_package = json.loads(decrypted_package)
                
                message = msg_package['message']
                signature = bytes.fromhex(msg_package['signature'])
                
                # Validate server's signature using CA Authority
                is_valid, msg = ca_authority.validate_signature(self.server_cert, message, signature)
                if is_valid:
                    self.add_to_chat(f"Host A: {message}")
                else:
                    self.add_to_chat(f"Unverified Host A message: {message} ({msg})")
                    
            except Exception as e:
                if self.connected:
                    self.add_to_chat(f"Receive error: {e}")
                break
        
        if self.connected:
            self.disconnect()
    
    def send_message(self, event=None):
        if not self.connected:
            return
        
        message = self.message_entry.get().strip()
        if not message:
            return
        
        try:
            # Sign message using client certificate private key
            signature = self.client_cert_private_key.sign(
                message.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            msg_package = {
                'message': message,
                'signature': signature.hex()
            }
            
            encrypted_package = self.aes_encrypt(json.dumps(msg_package), self.aes_key)
            self.client_socket.send(encrypted_package)
            
            self.add_to_chat(f"{self.username}: {message}")
            self.message_entry.delete(0, tk.END)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {e}")
    
    def add_to_chat(self, message):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)
    
    def on_closing(self):
        if self.connected:
            self.disconnect()
        self.root.destroy()
    
    # Crypto utilities
    def rsa_encrypt(self, public_key, data):
        cipher = PKCS1_OAEP.new(public_key)
        return cipher.encrypt(data)
    
    def aes_encrypt(self, plaintext, key):
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        return cipher.iv + ct_bytes
    
    def aes_decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        ct = ciphertext[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ct), AES.block_size)
        return decrypted.decode()
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    print("Starting Secure Chat Host B with CA Authority...")
    client = SecureChatClient()
    client.run()
