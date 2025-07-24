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

class SecureChatServer:
    def __init__(self):
        self.server_socket = None
        self.client_socket = None
        self.aes_key = None
        self.server_private_key = None
        self.server_public_key = None
        self.client_name = None
        self.server_running = False
        self.client_connected = False
        
        # Certificate management
        self.server_cert = None
        self.server_cert_private_key = None
        self.client_cert = None
        
        # Generate server keys and certificate
        self.generate_server_credentials()
        
        # Setup GUI
        self.setup_gui()
    
    def generate_server_credentials(self):
        """Generate Host A RSA keys and get certificate from CA"""
        # Generate RSA keys for encryption
        key = RSA.generate(2048)
        self.server_private_key = key
        self.server_public_key = key.publickey()
        
        # Get certificate from CA Authority
        self.server_cert, self.server_cert_private_key = ca_authority.issue_certificate(
            "secure-chat-server", "server"
        )
    
    def setup_gui(self):
        self.root = tk.Tk()
        self.root.geometry("600x500")
        
        # Host A info frame
        info_frame = tk.Frame(self.root)
        info_frame.pack(pady=5)
        
        cert_info = ca_authority.get_cert_info(self.server_cert)
        tk.Label(info_frame, text=f"Host A Certificate: {cert_info['common_name']}", 
                font=("Arial", 8, "bold")).pack()
        tk.Label(info_frame, text=f"Serial: {cert_info['serial_number']}", 
                font=("Arial", 8)).pack()
        
        # Control frame
        control_frame = tk.Frame(self.root)
        control_frame.pack(pady=5)
        
        tk.Label(control_frame, text="IP:").pack(side=tk.LEFT)
        self.server_ip_entry = tk.Entry(control_frame, width=12)
        self.server_ip_entry.insert(0, "127.0.0.1")
        self.server_ip_entry.pack(side=tk.LEFT, padx=2)
        
        tk.Label(control_frame, text="Port:").pack(side=tk.LEFT)
        self.server_port_entry = tk.Entry(control_frame, width=6)
        self.server_port_entry.insert(0, "12000")
        self.server_port_entry.pack(side=tk.LEFT, padx=2)
        
        self.start_btn = tk.Button(control_frame, text="Start Host A", 
                                  command=self.start_server, bg="green", fg="white")
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(control_frame, text="Stop Host A", 
                                 command=self.stop_server, state=tk.DISABLED, bg="red", fg="white")
        self.stop_btn.pack(side=tk.LEFT, padx=2)
        
        # Status
        self.status_label = tk.Label(self.root, text="Status: Stopped", fg="red", font=("Arial", 7, "bold"))
        self.status_label.pack(pady=2)
        
        # Chat display
        tk.Label(self.root, text="Chat Messages:", font=("Arial", 10, "bold")).pack(anchor="w", padx=5)
        self.chat_display = scrolledtext.ScrolledText(self.root, height=20, state=tk.DISABLED)
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Message input
        input_frame = tk.Frame(self.root)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(input_frame, text="Message:").pack(side=tk.LEFT)
        self.message_entry = tk.Entry(input_frame)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.message_entry.bind('<Return>', self.send_message)
        
        self.send_btn = tk.Button(input_frame, text="Send", command=self.send_message, 
                                 state=tk.DISABLED, bg="blue", fg="white")
        self.send_btn.pack(side=tk.RIGHT)
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def start_server(self):
        try:
            server_ip = self.server_ip_entry.get()
            server_port = int(self.server_port_entry.get())
            
            self.server_socket = socket(AF_INET, SOCK_STREAM)
            self.server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            self.server_socket.bind((server_ip, server_port))
            self.server_socket.listen(1)
            
            self.server_running = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.status_label.config(text=f"Status: Running on {server_ip}:{server_port}", fg="green")
            
            self.add_to_chat("Secure Chat Host A started with CA Authority validation")
            self.add_to_chat("Host A certificate validated by CA Authority")
            
            threading.Thread(target=self.accept_client, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start Host A: {e}")
    
    def stop_server(self):
        self.server_running = False
        self.client_connected = False
        
        if self.client_socket:
            self.client_socket.close()
        if self.server_socket:
            self.server_socket.close()
        
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.send_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Stopped", fg="red")
        
        self.add_to_chat("Host A stopped")
    
    def accept_client(self):
        try:
            while self.server_running:
                self.client_socket, addr = self.server_socket.accept()
                self.add_to_chat(f"Host B connected from: {addr[0]}")
                self.handle_client()
        except:
            pass
    
    def handle_client(self):
        try:
            # Send Host A certificate
            server_cert_pem = self.server_cert.public_bytes(serialization.Encoding.PEM)
            self.client_socket.send(len(server_cert_pem).to_bytes(4, 'big'))
            self.client_socket.send(server_cert_pem)
            
            # Send CA certificate
            ca_cert = ca_authority.get_ca_certificate()
            ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
            self.client_socket.send(len(ca_cert_pem).to_bytes(4, 'big'))
            self.client_socket.send(ca_cert_pem)
            
            # Receive Host B certificate
            cert_length = int.from_bytes(self.client_socket.recv(4), 'big')
            client_cert_pem = self.client_socket.recv(cert_length)
            self.client_cert = x509.load_pem_x509_certificate(client_cert_pem, default_backend())
            
            # Validate Host B certificate with CA Authority
            is_valid, msg = ca_authority.validate_certificate(self.client_cert)
            if not is_valid:
                self.add_to_chat(f"Host B certificate validation failed: {msg}")
                self.client_socket.close()
                return
            
            cert_info = ca_authority.get_cert_info(self.client_cert)
            self.add_to_chat(f"Host B certificate validated by CA: {cert_info['common_name']}")
            
            # Continue with RSA key exchange
            self.client_socket.send(self.server_public_key.export_key())
            
            encrypted_key = self.client_socket.recv(2048)
            self.aes_key = self.rsa_decrypt(self.server_private_key, encrypted_key)
            
            encrypted_name = self.client_socket.recv(1024)
            self.client_name = self.aes_decrypt(encrypted_name, self.aes_key)
            
            self.client_connected = True
            self.send_btn.config(state=tk.NORMAL)
            
            self.add_to_chat(f"{self.client_name} authenticated successfully with CA validation")
            
            # Listen for messages
            while self.client_connected and self.server_running:
                data = self.client_socket.recv(4096)
                if not data:
                    break
                
                decrypted_package = self.aes_decrypt(data, self.aes_key)
                msg_package = json.loads(decrypted_package)
                
                message = msg_package['message']
                signature = bytes.fromhex(msg_package['signature'])
                
                # Validate signature using CA Authority
                is_valid, msg = ca_authority.validate_signature(self.client_cert, message, signature)
                if is_valid:
                    self.add_to_chat(f"{self.client_name}: {message}")
                else:
                    self.add_to_chat(f"Invalid signature from {self.client_name}")
                    
        except Exception as e:
            if self.client_connected:
                self.add_to_chat(f"Host B error!")
        finally:
            self.client_connected = False
            self.send_btn.config(state=tk.DISABLED)
            if self.client_socket:
                self.client_socket.close()
            self.add_to_chat(f"Host B {self.client_name or 'Unknown'} disconnected")
    
    def send_message(self, event=None):
        if not self.client_connected:
            return
        
        message = self.message_entry.get().strip()
        if not message:
            return
        
        try:
            # Sign message using Host A certificate private key
            signature = self.server_cert_private_key.sign(
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
            
            self.add_to_chat(f"Host A: {message}")
            self.message_entry.delete(0, tk.END)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {e}")
    
    def add_to_chat(self, message):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)
    
    def on_closing(self):
        if self.server_running:
            self.stop_server()
        self.root.destroy()
    
    # Crypto utilities
    def rsa_decrypt(self, private_key, data):
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(data)
    
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
    print("Starting Secure Chat Host A with CA Authority...")
    server = SecureChatServer()
    server.run()
