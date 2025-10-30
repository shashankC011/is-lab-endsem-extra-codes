'''RSA + AES + SHA-256 + Signature (Hybrid Secure Messaging System)
Create a Client–Server Secure Messaging System.
* The client encrypts messages using AES, and the AES key is encrypted using RSA.
* A SHA-256 hash of the message is generated and digitally signed (RSA) before sending.
* The server verifies the signature, decrypts the key, decrypts the message, and validates integrity. menu driven in python'''
import socket
import json
import threading
import hashlib
import base64
from datetime import datetime
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# ==================== CRYPTOGRAPHIC UTILITIES ====================
class CryptoManager:
    def __init__(self):
        self.rsa_key = RSA.generate(2048)
        self.public_key = self.rsa_key.publickey()
    
    def generate_aes_key(self):
        """Generate a random 256-bit AES key"""
        return get_random_bytes(32)
    
    def encrypt_message_aes(self, message, aes_key):
        """Encrypt message using AES-256 in CBC mode"""
        cipher = AES.new(aes_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return iv, ct
    
    def decrypt_message_aes(self, iv, ciphertext, aes_key):
        """Decrypt message using AES-256"""
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ciphertext)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    
    def encrypt_aes_key_rsa(self, aes_key, recipient_public_key):
        """Encrypt AES key using RSA public key"""
        cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
        encrypted_key = cipher_rsa.encrypt(aes_key)
        return base64.b64encode(encrypted_key).decode('utf-8')
    
    def decrypt_aes_key_rsa(self, encrypted_key):
        """Decrypt AES key using RSA private key"""
        encrypted_key = base64.b64decode(encrypted_key)
        cipher_rsa = PKCS1_OAEP.new(self.rsa_key)
        aes_key = cipher_rsa.decrypt(encrypted_key)
        return aes_key
    
    def hash_message(self, message):
        """Generate SHA-256 hash of message"""
        return hashlib.sha256(message.encode('utf-8')).hexdigest()
    
    def sign_hash(self, message_hash):
        """Sign the message hash using RSA private key"""
        h = SHA256.new(message_hash.encode('utf-8'))
        signature = pkcs1_15.new(self.rsa_key).sign(h)
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, message_hash, signature, sender_public_key):
        """Verify RSA signature"""
        try:
            h = SHA256.new(message_hash.encode('utf-8'))
            signature = base64.b64decode(signature)
            pkcs1_15.new(sender_public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
    
    def export_public_key(self):
        """Export public key in PEM format"""
        return self.public_key.export_key().decode('utf-8')
    
    @staticmethod
    def import_public_key(pem_key):
        """Import public key from PEM format"""
        return RSA.import_key(pem_key.encode('utf-8'))

# ==================== SERVER IMPLEMENTATION ====================
class SecureMessagingServer:
    def __init__(self, host='127.0.0.1', port=5556):
        self.host = host
        self.port = port
        self.crypto = CryptoManager()
        self.received_messages = []
        self.clients = {}
        
    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        print("="*80)
        print("SECURE MESSAGING SERVER")
        print("="*80)
        print(f"[SERVER] Started on {self.host}:{self.port}")
        print(f"[SERVER] RSA Public Key Generated (2048-bit)")
        print("\n[SERVER] Waiting for client connections...\n")
        
        try:
            while True:
                client_socket, address = server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(client_socket, address)
                )
                client_thread.start()
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down...")
            server_socket.close()
    
    def handle_client(self, client_socket, address):
        print(f"[SERVER] Connection from {address}")
        
        try:
            # Send server's public key to client
            public_key_pem = self.crypto.export_public_key()
            client_socket.send(json.dumps({'public_key': public_key_pem}).encode())
            
            # Receive client's public key
            client_data = json.loads(client_socket.recv(4096).decode())
            client_public_key = CryptoManager.import_public_key(client_data['public_key'])
            client_id = client_data['client_id']
            self.clients[client_id] = client_public_key
            
            print(f"[SERVER] Registered client: {client_id}")
            
            # Receive encrypted message
            message_data = json.loads(client_socket.recv(8192).decode())
            
            print(f"\n[SERVER] Processing message from {client_id}...")
            print("-" * 80)
            
            # Step 1: Verify digital signature
            print("[1] Verifying digital signature...")
            is_valid = self.crypto.verify_signature(
                message_data['message_hash'],
                message_data['signature'],
                client_public_key
            )
            
            if not is_valid:
                print("    ✗ SIGNATURE VERIFICATION FAILED!")
                response = {
                    'status': 'error',
                    'message': 'Signature verification failed'
                }
                client_socket.send(json.dumps(response).encode())
                return
            
            print("    ✓ Signature verified successfully")
            
            # Step 2: Decrypt AES key using server's RSA private key
            print("[2] Decrypting AES key with RSA private key...")
            aes_key = self.crypto.decrypt_aes_key_rsa(message_data['encrypted_aes_key'])
            print(f"    ✓ AES key decrypted: {base64.b64encode(aes_key).decode()[:32]}...")
            
            # Step 3: Decrypt message using AES key
            print("[3] Decrypting message with AES key...")
            decrypted_message = self.crypto.decrypt_message_aes(
                message_data['iv'],
                message_data['encrypted_message'],
                aes_key
            )
            print(f"    ✓ Message decrypted successfully")
            
            # Step 4: Validate integrity by computing hash
            print("[4] Validating message integrity (SHA-256)...")
            computed_hash = self.crypto.hash_message(decrypted_message)
            
            if computed_hash != message_data['message_hash']:
                print("    ✗ HASH MISMATCH! Message integrity compromised!")
                response = {
                    'status': 'error',
                    'message': 'Message integrity check failed'
                }
                client_socket.send(json.dumps(response).encode())
                return
            
            print(f"    ✓ Hash verified: {computed_hash[:32]}...")
            print(f"    ✓ Message integrity confirmed")
            
            # Store the message
            message_record = {
                'client_id': client_id,
                'message': decrypted_message,
                'timestamp': message_data['timestamp'],
                'hash': computed_hash,
                'verified': True
            }
            self.received_messages.append(message_record)
            
            print("-" * 80)
            print(f"[SERVER] DECRYPTED MESSAGE: {decrypted_message}")
            print(f"[SERVER] From: {client_id}")
            print(f"[SERVER] Time: {message_data['timestamp']}")
            print("="*80 + "\n")
            
            # Send success response
            response = {
                'status': 'success',
                'message': 'Message received, verified, and decrypted successfully',
                'message_hash': computed_hash
            }
            client_socket.send(json.dumps(response).encode())
            
        except Exception as e:
            print(f"[SERVER] Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            client_socket.close()
    
    def display_messages(self):
        """Display all received messages"""
        if not self.received_messages:
            print("\n[SERVER] No messages received yet.\n")
            return
        
        print("\n" + "="*80)
        print("RECEIVED MESSAGES")
        print("="*80)
        
        for i, msg in enumerate(self.received_messages, 1):
            print(f"\nMessage {i}:")
            print(f"  From: {msg['client_id']}")
            print(f"  Time: {msg['timestamp']}")
            print(f"  Content: {msg['message']}")
            print(f"  SHA-256: {msg['hash'][:64]}...")
            print(f"  Verified: {'✓ Yes' if msg['verified'] else '✗ No'}")
            print("-" * 80)
        
        print("="*80 + "\n")

# ==================== CLIENT IMPLEMENTATION ====================
class SecureMessagingClient:
    def __init__(self, client_id, host='127.0.0.1', port=5556):
        self.client_id = client_id
        self.host = host
        self.port = port
        self.crypto = CryptoManager()
        self.server_public_key = None
    
    def send_message(self, message):
        try:
            # Connect to server
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.host, self.port))
            
            print(f"\n[{self.client_id}] Connected to server")
            print("-" * 80)
            
            # Receive server's public key
            server_data = json.loads(client_socket.recv(4096).decode())
            self.server_public_key = CryptoManager.import_public_key(server_data['public_key'])
            print(f"[{self.client_id}] Received server's RSA public key")
            
            # Send client's public key
            client_data = {
                'client_id': self.client_id,
                'public_key': self.crypto.export_public_key()
            }
            client_socket.send(json.dumps(client_data).encode())
            print(f"[{self.client_id}] Sent client's RSA public key")
            
            print(f"\n[{self.client_id}] Encrypting message: '{message}'")
            print("-" * 80)
            
            # Step 1: Generate SHA-256 hash of the message
            print("[1] Generating SHA-256 hash of message...")
            message_hash = self.crypto.hash_message(message)
            print(f"    Hash: {message_hash[:64]}...")
            
            # Step 2: Sign the hash with client's RSA private key
            print("[2] Signing hash with RSA private key...")
            signature = self.crypto.sign_hash(message_hash)
            print(f"    Signature: {signature[:64]}...")
            
            # Step 3: Generate random AES key
            print("[3] Generating random AES-256 key...")
            aes_key = self.crypto.generate_aes_key()
            print(f"    AES Key: {base64.b64encode(aes_key).decode()[:32]}...")
            
            # Step 4: Encrypt message with AES
            print("[4] Encrypting message with AES-256 (CBC mode)...")
            iv, encrypted_message = self.crypto.encrypt_message_aes(message, aes_key)
            print(f"    IV: {iv[:32]}...")
            print(f"    Ciphertext: {encrypted_message[:64]}...")
            
            # Step 5: Encrypt AES key with server's RSA public key
            print("[5] Encrypting AES key with server's RSA public key...")
            encrypted_aes_key = self.crypto.encrypt_aes_key_rsa(aes_key, self.server_public_key)
            print(f"    Encrypted AES Key: {encrypted_aes_key[:64]}...")
            
            # Prepare the complete message package
            message_package = {
                'client_id': self.client_id,
                'encrypted_message': encrypted_message,
                'iv': iv,
                'encrypted_aes_key': encrypted_aes_key,
                'message_hash': message_hash,
                'signature': signature,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Send encrypted message to server
            print("\n[6] Sending encrypted package to server...")
            client_socket.send(json.dumps(message_package).encode())
            
            # Receive server response
            response = json.loads(client_socket.recv(4096).decode())
            
            print("-" * 80)
            if response['status'] == 'success':
                print(f"[{self.client_id}] ✓ {response['message']}")
            else:
                print(f"[{self.client_id}] ✗ {response['message']}")
            print("="*80 + "\n")
            
            client_socket.close()
            return True
            
        except Exception as e:
            print(f"[{self.client_id}] Error: {e}")
            import traceback
            traceback.print_exc()
            return False

# ==================== MENU-DRIVEN INTERFACE ====================
def client_menu():
    print("\n" + "="*80)
    print("CLIENT (SENDER) MENU")
    print("="*80)
    print("1. Send Secure Message")
    print("2. Send Multiple Messages")
    print("3. Exit")
    print("="*80)
    
    while True:
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            client_id = input("Enter your Client ID: ").strip()
            message = input("Enter message to send: ").strip()
            
            if message:
                client = SecureMessagingClient(client_id)
                client.send_message(message)
            else:
                print("Message cannot be empty!")
        
        elif choice == '2':
            client_id = input("Enter your Client ID: ").strip()
            try:
                num_messages = int(input("How many messages to send? ").strip())
                for i in range(num_messages):
                    print(f"\n--- Message {i+1} ---")
                    message = input("Enter message: ").strip()
                    if message:
                        client = SecureMessagingClient(client_id)
                        client.send_message(message)
                        import time
                        time.sleep(1)
            except ValueError:
                print("Invalid number!")
        
        elif choice == '3':
            print("Exiting client menu...")
            break
        
        else:
            print("Invalid choice. Please select 1-3.")

def server_menu(server):
    print("\n" + "="*80)
    print("SERVER MENU")
    print("="*80)
    print("1. View All Received Messages")
    print("2. View Statistics")
    print("3. Exit Server")
    print("="*80)
    
    while True:
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            server.display_messages()
        
        elif choice == '2':
            print(f"\n[SERVER] Statistics:")
            print(f"  Total Messages Received: {len(server.received_messages)}")
            print(f"  Registered Clients: {len(server.clients)}")
            if server.clients:
                print(f"  Client IDs: {', '.join(server.clients.keys())}")
            print()
        
        elif choice == '3':
            print("\nShutting down server...")
            break
        
        else:
            print("Invalid choice. Please select 1-3.")

# ==================== MAIN PROGRAM ====================
def main():
    print("="*80)
    print("CLIENT-SERVER SECURE MESSAGING SYSTEM")
    print("AES Encryption + RSA Key Exchange + Digital Signature")
    print("="*80)
    print("\nSelect Mode:")
    print("1. Start Server")
    print("2. Start Client")
    print("3. Run Demo (Automated)")
    print("="*80)
    
    choice = input("\nEnter your choice (1-3): ").strip()
    
    if choice == '1':
        server = SecureMessagingServer()
        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()
        
        import time
        time.sleep(1)
        
        server_menu(server)
    
    elif choice == '2':
        client_menu()
    
    elif choice == '3':
        print("\n[DEMO] Starting automated demo...\n")
        server = SecureMessagingServer()
        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()
        
        import time
        time.sleep(2)
        
        # Demo messages
        demo_messages = [
            ("Alice", "Hello Server! This is a secure message from Alice."),
            ("Bob", "Confidential data: Project X budget is $50,000."),
            ("Charlie", "Meeting scheduled for tomorrow at 3 PM."),
            ("Diana", "The encryption is working perfectly!"),
        ]
        
        print("[DEMO] Sending secure messages from multiple clients...\n")
        for client_id, message in demo_messages:
            client = SecureMessagingClient(client_id)
            client.send_message(message)
            time.sleep(2)
        
        time.sleep(1)
        print("\n[DEMO] Displaying all received messages on server...\n")
        server.display_messages()
        
        input("Press Enter to exit demo...")
    
    else:
        print("Invalid choice. Exiting...")

if __name__ == "__main__":
    main()