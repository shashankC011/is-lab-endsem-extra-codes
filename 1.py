import socket
import json
import hashlib
import threading
from datetime import datetime
from phe import paillier
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
'''
Paillier + RSA + SHA-256 + Signature
Develop a Client–Server Transaction System simulating interactions between multiple sellers and a payment gateway.

Each seller (client) performs transactions with Paillier encryption on the transaction amount.

The server computes total encrypted amounts homomorphically and decrypts them.

The complete summary is hashed using SHA-256 and signed using RSA digital signature.

The server verifies the signature and displays all transaction details.'''
# ==================== PAILLIER ENCRYPTION UTILITIES ====================
class PaillierSystem:
    def __init__(self):
        self.public_key, self.private_key = paillier.generate_paillier_keypair()
    
    def encrypt(self, amount):
        return self.public_key.encrypt(amount)
    
    def decrypt(self, encrypted_amount):
        return self.private_key.decrypt(encrypted_amount)
    
    def get_public_key(self):
        return self.public_key

# ==================== RSA SIGNATURE UTILITIES ====================
class RSASignature:
    def __init__(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
    
    def sign(self, message):
        h = SHA256.new(message.encode())
        signature = pkcs1_15.new(self.key).sign(h)
        return signature
    
    def verify(self, message, signature, public_key):
        h = SHA256.new(message.encode())
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
    
    def get_public_key(self):
        return self.public_key

# ==================== SERVER IMPLEMENTATION ====================
class PaymentGatewayServer:
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.paillier = PaillierSystem()
        self.rsa = RSASignature()
        self.transactions = []
        self.encrypted_total = None
        
    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        print(f"[SERVER] Payment Gateway started on {self.host}:{self.port}")
        print(f"[SERVER] Paillier Public Key: n={self.paillier.public_key.n}")
        print(f"[SERVER] RSA Public Key generated")
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
            # Send Paillier public key to client
            pub_key_data = {
                'n': self.paillier.public_key.n,
                'g': self.paillier.public_key.g
            }
            client_socket.send(json.dumps(pub_key_data).encode())
            
            # Receive transaction data
            data = client_socket.recv(4096).decode()
            transaction = json.loads(data)
            
            print(f"[SERVER] Received transaction from {transaction['seller_id']}")
            print(f"          Amount (encrypted): {transaction['encrypted_amount']}")
            
            # Store transaction
            self.transactions.append(transaction)
            
            # Compute homomorphic sum
            self.compute_encrypted_total()
            
            # Send acknowledgment
            response = {'status': 'success', 'message': 'Transaction received'}
            client_socket.send(json.dumps(response).encode())
            
        except Exception as e:
            print(f"[SERVER] Error handling client: {e}")
        finally:
            client_socket.close()
    
    def compute_encrypted_total(self):
        """Homomorphically add all encrypted amounts"""
        if not self.transactions:
            return
        
        # Initialize with first encrypted amount
        encrypted_amounts = [int(t['encrypted_amount']) for t in self.transactions]
        self.encrypted_total = self.paillier.public_key.encrypt(0)
        
        for enc_amt in encrypted_amounts:
            # Reconstruct EncryptedNumber from integer
            enc_num = paillier.EncryptedNumber(self.paillier.public_key, enc_amt)
            self.encrypted_total = self.encrypted_total + enc_num
    
    def finalize_and_sign(self):
        """Decrypt total, create summary, hash and sign it"""
        if not self.transactions:
            print("[SERVER] No transactions to finalize")
            return
        
        # Decrypt the homomorphically computed total
        decrypted_total = self.paillier.decrypt(self.encrypted_total)
        
        print("\n" + "="*70)
        print("TRANSACTION SUMMARY")
        print("="*70)
        
        # Create detailed summary
        summary_lines = []
        summary_lines.append(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        summary_lines.append(f"Total Transactions: {len(self.transactions)}")
        summary_lines.append("-" * 70)
        
        for i, txn in enumerate(self.transactions, 1):
            summary_lines.append(f"Transaction {i}:")
            summary_lines.append(f"  Seller ID: {txn['seller_id']}")
            summary_lines.append(f"  Product: {txn['product']}")
            summary_lines.append(f"  Amount: ${txn['original_amount']:.2f}")
            summary_lines.append(f"  Encrypted: {txn['encrypted_amount']}")
        
        summary_lines.append("-" * 70)
        summary_lines.append(f"TOTAL AMOUNT (Homomorphically Computed): ${decrypted_total:.2f}")
        summary_lines.append("="*70)
        
        summary_text = "\n".join(summary_lines)
        
        # Display summary
        print(summary_text)
        
        # Hash the summary using SHA-256
        summary_hash = hashlib.sha256(summary_text.encode()).hexdigest()
        print(f"\nSHA-256 Hash: {summary_hash}")
        
        # Sign the hash using RSA
        signature = self.rsa.sign(summary_text)
        print(f"RSA Signature: {signature.hex()[:64]}...")
        
        # Verify the signature
        is_valid = self.rsa.verify(summary_text, signature, self.rsa.get_public_key())
        print(f"\nSignature Verification: {'✓ VALID' if is_valid else '✗ INVALID'}")
        
        print("="*70)
        
        return {
            'summary': summary_text,
            'hash': summary_hash,
            'signature': signature.hex(),
            'total': decrypted_total,
            'verified': is_valid
        }

# ==================== CLIENT IMPLEMENTATION ====================
class SellerClient:
    def __init__(self, seller_id, host='127.0.0.1', port=5555):
        self.seller_id = seller_id
        self.host = host
        self.port = port
        self.public_key = None
    
    def send_transaction(self, product, amount):
        try:
            # Connect to server
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.host, self.port))
            
            # Receive Paillier public key
            pub_key_data = json.loads(client_socket.recv(4096).decode())
            self.public_key = paillier.PaillierPublicKey(n=int(pub_key_data['n']))
            
            # Encrypt the transaction amount
            encrypted_amount = self.public_key.encrypt(amount)
            
            # Prepare transaction data
            transaction = {
                'seller_id': self.seller_id,
                'product': product,
                'original_amount': amount,
                'encrypted_amount': int(encrypted_amount.ciphertext()),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            print(f"[{self.seller_id}] Sending transaction:")
            print(f"           Product: {product}")
            print(f"           Amount: ${amount:.2f}")
            print(f"           Encrypted: {transaction['encrypted_amount']}")
            
            # Send transaction to server
            client_socket.send(json.dumps(transaction).encode())
            
            # Receive acknowledgment
            response = json.loads(client_socket.recv(4096).decode())
            print(f"[{self.seller_id}] Server response: {response['message']}\n")
            
            client_socket.close()
            return True
            
        except Exception as e:
            print(f"[{self.seller_id}] Error: {e}")
            return False

# ==================== MENU-DRIVEN INTERFACE ====================
def client_menu():
    print("\n" + "="*70)
    print("CLIENT (SELLER) MENU")
    print("="*70)
    print("1. Send Transaction")
    print("2. Send Multiple Transactions")
    print("3. Exit")
    print("="*70)
    
    while True:
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            seller_id = input("Enter Seller ID: ").strip()
            product = input("Enter Product Name: ").strip()
            try:
                amount = float(input("Enter Transaction Amount: $").strip())
                client = SellerClient(seller_id)
                client.send_transaction(product, amount)
            except ValueError:
                print("Invalid amount. Please enter a number.")
        
        elif choice == '2':
            try:
                num_transactions = int(input("How many transactions? ").strip())
                for i in range(num_transactions):
                    print(f"\n--- Transaction {i+1} ---")
                    seller_id = input("Enter Seller ID: ").strip()
                    product = input("Enter Product Name: ").strip()
                    amount = float(input("Enter Transaction Amount: $").strip())
                    client = SellerClient(seller_id)
                    client.send_transaction(product, amount)
            except ValueError:
                print("Invalid input. Please enter valid numbers.")
        
        elif choice == '3':
            print("Exiting client menu...")
            break
        
        else:
            print("Invalid choice. Please select 1-3.")

def server_menu(server):
    print("\n" + "="*70)
    print("SERVER (PAYMENT GATEWAY) MENU")
    print("="*70)
    print("1. View Transactions")
    print("2. Finalize and Sign Summary")
    print("3. Exit Server")
    print("="*70)
    
    while True:
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            if not server.transactions:
                print("\n[SERVER] No transactions received yet.")
            else:
                print(f"\n[SERVER] Total Transactions: {len(server.transactions)}")
                for i, txn in enumerate(server.transactions, 1):
                    print(f"\nTransaction {i}:")
                    print(f"  Seller: {txn['seller_id']}")
                    print(f"  Product: {txn['product']}")
                    print(f"  Amount: ${txn['original_amount']:.2f}")
                    print(f"  Time: {txn['timestamp']}")
        
        elif choice == '2':
            server.finalize_and_sign()
        
        elif choice == '3':
            print("\nShutting down server...")
            break
        
        else:
            print("Invalid choice. Please select 1-3.")

# ==================== MAIN PROGRAM ====================
def main():
    print("="*70)
    print("CLIENT-SERVER TRANSACTION SYSTEM")
    print("With Paillier Encryption & RSA Digital Signature")
    print("="*70)
    print("\nSelect Mode:")
    print("1. Start Server (Payment Gateway)")
    print("2. Start Client (Seller)")
    print("3. Run Demo (Automated)")
    print("="*70)
    
    choice = input("\nEnter your choice (1-3): ").strip()
    
    if choice == '1':
        server = PaymentGatewayServer()
        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()
        
        import time
        time.sleep(1)  # Give server time to start
        
        server_menu(server)
    
    elif choice == '2':
        client_menu()
    
    elif choice == '3':
        print("\n[DEMO] Starting automated demo...")
        server = PaymentGatewayServer()
        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()
        
        import time
        time.sleep(2)  # Give server time to start
        
        # Simulate multiple sellers
        sellers_data = [
            ("SELLER_001", "Laptop", 1200.50),
            ("SELLER_002", "Smartphone", 899.99),
            ("SELLER_003", "Headphones", 150.75),
            ("SELLER_004", "Tablet", 450.00),
            ("SELLER_005", "Monitor", 320.25)
        ]
        
        print("\n[DEMO] Sending transactions from multiple sellers...\n")
        for seller_id, product, amount in sellers_data:
            client = SellerClient(seller_id)
            client.send_transaction(product, amount)
            time.sleep(1)
        
        time.sleep(2)
        print("\n[DEMO] Finalizing and signing summary...\n")
        server.finalize_and_sign()
        
        input("\nPress Enter to exit demo...")
    
    else:
        print("Invalid choice. Exiting...")

if __name__ == "__main__":
    main()