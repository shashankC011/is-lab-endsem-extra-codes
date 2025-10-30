'''ElGamal + RSA + SHA-256 + Signature (Role-based Transaction System)

Question:
Implement a Client–Server Multi-role System with Customer, Merchant, and Auditor roles.

Clients (Customer/Merchant) send transaction data encrypted with ElGamal.

The server stores and processes data, generating a SHA-256 hash of all transactions.

The server signs the summary using RSA digital signature, and the auditor verifies it remotely.'''
import socket
import json
import threading
import hashlib
import secrets
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

# ==================== ELGAMAL ENCRYPTION IMPLEMENTATION ====================
class ElGamal:
    """ElGamal Encryption System"""
    
    def __init__(self, key_size=256):
        self.key_size = key_size
        self.p, self.g, self.private_key, self.public_key = self.generate_keys()
    
    def generate_keys(self):
        """Generate ElGamal public and private keys"""
        # Generate a large prime p
        p = self._generate_prime(self.key_size)
        
        # Choose generator g
        g = 2
        
        # Generate private key (random number less than p)
        private_key = secrets.randbelow(p - 2) + 1
        
        # Calculate public key: h = g^private_key mod p
        public_key = pow(g, private_key, p)
        
        return p, g, private_key, public_key
    
    def _generate_prime(self, bits):
        """Generate a prime number of specified bit length"""
        while True:
            num = secrets.randbits(bits)
            if num % 2 == 0:
                num += 1
            if self._is_prime(num):
                return num
    
    def _is_prime(self, n, k=5):
        """Miller-Rabin primality test"""
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Witness loop
        for _ in range(k):
            a = secrets.randbelow(n - 3) + 2
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
    
    def encrypt(self, message, public_key_tuple):
        """Encrypt a message using ElGamal public key"""
        p, g, h = public_key_tuple
        
        # Convert message to integer
        message_bytes = message.encode('utf-8')
        message_int = int.from_bytes(message_bytes, byteorder='big')
        
        # Ensure message is smaller than p
        if message_int >= p:
            raise ValueError("Message too large for this key size")
        
        # Choose random k
        k = secrets.randbelow(p - 2) + 1
        
        # Calculate c1 = g^k mod p
        c1 = pow(g, k, p)
        
        # Calculate c2 = (message * h^k) mod p
        c2 = (message_int * pow(h, k, p)) % p
        
        return c1, c2
    
    def decrypt(self, ciphertext):
        """Decrypt a ciphertext using ElGamal private key"""
        c1, c2 = ciphertext
        
        # Calculate s = c1^private_key mod p
        s = pow(c1, self.private_key, self.p)
        
        # Calculate s_inv (modular inverse of s)
        s_inv = pow(s, self.p - 2, self.p)
        
        # Calculate message = c2 * s_inv mod p
        message_int = (c2 * s_inv) % self.p
        
        # Convert integer back to string
        message_bytes = message_int.to_bytes(
            (message_int.bit_length() + 7) // 8, 
            byteorder='big'
        )
        
        return message_bytes.decode('utf-8')
    
    def get_public_key(self):
        """Return public key components"""
        return (self.p, self.g, self.public_key)

# ==================== RSA SIGNATURE SYSTEM ====================
class RSASignature:
    """RSA Digital Signature System"""
    
    def __init__(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
    
    def sign(self, message):
        """Sign a message using RSA private key"""
        h = SHA256.new(message.encode('utf-8'))
        signature = pkcs1_15.new(self.key).sign(h)
        return base64.b64encode(signature).decode('utf-8')
    
    def verify(self, message, signature, public_key):
        """Verify RSA signature"""
        try:
            h = SHA256.new(message.encode('utf-8'))
            signature_bytes = base64.b64decode(signature)
            pkcs1_15.new(public_key).verify(h, signature_bytes)
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

# ==================== TRANSACTION SERVER ====================
class TransactionServer:
    def __init__(self, host='127.0.0.1', port=5557):
        self.host = host
        self.port = port
        self.elgamal = ElGamal(key_size=256)
        self.rsa = RSASignature()
        self.transactions = []
        self.clients = {}
        
    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(10)
        
        print("="*90)
        print("ROLE-BASED TRANSACTION SYSTEM - SERVER")
        print("="*90)
        print(f"[SERVER] Started on {self.host}:{self.port}")
        print(f"[SERVER] ElGamal Encryption System Initialized")
        print(f"[SERVER] RSA Digital Signature System Initialized")
        print("\n[SERVER] Public Key (ElGamal):")
        print(f"          p = {self.elgamal.p}")
        print(f"          g = {self.elgamal.g}")
        print(f"          h = {self.elgamal.public_key}")
        print("\n[SERVER] Waiting for connections...\n")
        
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
        try:
            # Receive role identification
            role_data = json.loads(client_socket.recv(4096).decode())
            role = role_data.get('role')
            
            if role == 'AUDITOR':
                self.handle_auditor(client_socket, role_data)
            elif role in ['CUSTOMER', 'MERCHANT']:
                self.handle_transaction(client_socket, role_data)
            else:
                print(f"[SERVER] Unknown role from {address}")
                
        except Exception as e:
            print(f"[SERVER] Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            client_socket.close()
    
    def handle_transaction(self, client_socket, role_data):
        """Handle transaction from Customer or Merchant"""
        client_id = role_data['client_id']
        role = role_data['role']
        
        print(f"\n[SERVER] Connection from {role}: {client_id}")
        print("-" * 90)
        
        # Send ElGamal public key
        public_key = {
            'p': self.elgamal.p,
            'g': self.elgamal.g,
            'h': self.elgamal.public_key
        }
        client_socket.send(json.dumps({'public_key': public_key}).encode())
        
        # Receive encrypted transaction
        transaction_data = json.loads(client_socket.recv(8192).decode())
        
        print(f"[SERVER] Received encrypted transaction from {client_id}")
        print(f"[SERVER] Ciphertext: c1={transaction_data['c1']}, c2={transaction_data['c2']}")
        
        # Decrypt transaction using ElGamal
        print(f"[SERVER] Decrypting with ElGamal private key...")
        ciphertext = (transaction_data['c1'], transaction_data['c2'])
        decrypted_data = self.elgamal.decrypt(ciphertext)
        transaction_info = json.loads(decrypted_data)
        
        print(f"[SERVER] ✓ Transaction decrypted successfully")
        print(f"[SERVER] Details:")
        print(f"          Role: {role}")
        print(f"          ID: {client_id}")
        print(f"          Type: {transaction_info['transaction_type']}")
        print(f"          Amount: ${transaction_info['amount']:.2f}")
        print(f"          Description: {transaction_info['description']}")
        
        # Store transaction
        transaction_record = {
            'role': role,
            'client_id': client_id,
            'transaction_type': transaction_info['transaction_type'],
            'amount': transaction_info['amount'],
            'description': transaction_info['description'],
            'timestamp': transaction_data['timestamp'],
            'decrypted': True
        }
        self.transactions.append(transaction_record)
        
        print("-" * 90)
        
        # Send acknowledgment
        response = {
            'status': 'success',
            'message': 'Transaction received and processed',
            'transaction_id': len(self.transactions)
        }
        client_socket.send(json.dumps(response).encode())
    
    def handle_auditor(self, client_socket, role_data):
        """Handle auditor request for transaction summary"""
        auditor_id = role_data['client_id']
        
        print(f"\n[AUDITOR] Connection from Auditor: {auditor_id}")
        print("="*90)
        
        if not self.transactions:
            response = {
                'status': 'error',
                'message': 'No transactions available for audit'
            }
            client_socket.send(json.dumps(response).encode())
            return
        
        # Generate transaction summary
        print(f"[AUDITOR] Generating transaction summary...")
        summary = self.generate_summary()
        
        # Generate SHA-256 hash of summary
        print(f"[AUDITOR] Computing SHA-256 hash...")
        summary_hash = hashlib.sha256(summary.encode('utf-8')).hexdigest()
        print(f"[AUDITOR] Hash: {summary_hash}")
        
        # Sign the hash using RSA
        print(f"[AUDITOR] Signing with RSA private key...")
        signature = self.rsa.sign(summary)
        print(f"[AUDITOR] Signature: {signature[:64]}...")
        
        # Send summary, hash, signature, and public key to auditor
        audit_package = {
            'status': 'success',
            'summary': summary,
            'hash': summary_hash,
            'signature': signature,
            'server_public_key': self.rsa.export_public_key(),
            'transaction_count': len(self.transactions)
        }
        
        print(f"[AUDITOR] Sending audit package to auditor...")
        client_socket.send(json.dumps(audit_package).encode())
        print("="*90 + "\n")
    
    def generate_summary(self):
        """Generate a comprehensive transaction summary"""
        lines = []
        lines.append("="*90)
        lines.append("TRANSACTION SUMMARY REPORT")
        lines.append("="*90)
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Total Transactions: {len(self.transactions)}")
        lines.append("-"*90)
        
        customer_total = 0
        merchant_total = 0
        
        for i, txn in enumerate(self.transactions, 1):
            lines.append(f"\nTransaction {i}:")
            lines.append(f"  Role: {txn['role']}")
            lines.append(f"  ID: {txn['client_id']}")
            lines.append(f"  Type: {txn['transaction_type']}")
            lines.append(f"  Amount: ${txn['amount']:.2f}")
            lines.append(f"  Description: {txn['description']}")
            lines.append(f"  Timestamp: {txn['timestamp']}")
            
            if txn['role'] == 'CUSTOMER':
                customer_total += txn['amount']
            elif txn['role'] == 'MERCHANT':
                merchant_total += txn['amount']
        
        lines.append("-"*90)
        lines.append(f"Customer Transactions Total: ${customer_total:.2f}")
        lines.append(f"Merchant Transactions Total: ${merchant_total:.2f}")
        lines.append(f"Grand Total: ${customer_total + merchant_total:.2f}")
        lines.append("="*90)
        
        return "\n".join(lines)
    
    def display_transactions(self):
        """Display all stored transactions"""
        if not self.transactions:
            print("\n[SERVER] No transactions recorded yet.\n")
            return
        
        print("\n" + "="*90)
        print("STORED TRANSACTIONS")
        print("="*90)
        
        for i, txn in enumerate(self.transactions, 1):
            print(f"\nTransaction {i}:")
            print(f"  Role: {txn['role']}")
            print(f"  Client ID: {txn['client_id']}")
            print(f"  Type: {txn['transaction_type']}")
            print(f"  Amount: ${txn['amount']:.2f}")
            print(f"  Description: {txn['description']}")
            print(f"  Time: {txn['timestamp']}")
            print("-" * 90)
        
        print("="*90 + "\n")

# ==================== CLIENT IMPLEMENTATIONS ====================
class CustomerClient:
    """Customer role - sends purchase transactions"""
    
    def __init__(self, customer_id, host='127.0.0.1', port=5557):
        self.customer_id = customer_id
        self.host = host
        self.port = port
        self.role = 'CUSTOMER'
    
    def send_transaction(self, transaction_type, amount, description):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.host, self.port))
            
            print(f"\n[{self.customer_id}] Connected to server")
            print("-" * 90)
            
            # Send role identification
            role_data = {
                'role': self.role,
                'client_id': self.customer_id
            }
            client_socket.send(json.dumps(role_data).encode())
            
            # Receive ElGamal public key
            pub_key_data = json.loads(client_socket.recv(4096).decode())
            public_key = (
                pub_key_data['public_key']['p'],
                pub_key_data['public_key']['g'],
                pub_key_data['public_key']['h']
            )
            
            print(f"[{self.customer_id}] Received ElGamal public key from server")
            
            # Prepare transaction data
            transaction_info = {
                'transaction_type': transaction_type,
                'amount': amount,
                'description': description
            }
            
            print(f"[{self.customer_id}] Transaction Details:")
            print(f"                    Type: {transaction_type}")
            print(f"                    Amount: ${amount:.2f}")
            print(f"                    Description: {description}")
            
            # Encrypt transaction with ElGamal
            print(f"[{self.customer_id}] Encrypting transaction with ElGamal...")
            elgamal = ElGamal()
            transaction_json = json.dumps(transaction_info)
            c1, c2 = elgamal.encrypt(transaction_json, public_key)
            
            print(f"[{self.customer_id}] ✓ Encrypted: c1={c1}, c2={c2}")
            
            # Send encrypted transaction
            transaction_package = {
                'c1': c1,
                'c2': c2,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            client_socket.send(json.dumps(transaction_package).encode())
            
            # Receive response
            response = json.loads(client_socket.recv(4096).decode())
            
            print("-" * 90)
            if response['status'] == 'success':
                print(f"[{self.customer_id}] ✓ {response['message']}")
                print(f"[{self.customer_id}] Transaction ID: {response['transaction_id']}")
            else:
                print(f"[{self.customer_id}] ✗ {response['message']}")
            print("="*90 + "\n")
            
            client_socket.close()
            return True
            
        except Exception as e:
            print(f"[{self.customer_id}] Error: {e}")
            import traceback
            traceback.print_exc()
            return False

class MerchantClient:
    """Merchant role - sends sales transactions"""
    
    def __init__(self, merchant_id, host='127.0.0.1', port=5557):
        self.merchant_id = merchant_id
        self.host = host
        self.port = port
        self.role = 'MERCHANT'
    
    def send_transaction(self, transaction_type, amount, description):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.host, self.port))
            
            print(f"\n[{self.merchant_id}] Connected to server")
            print("-" * 90)
            
            # Send role identification
            role_data = {
                'role': self.role,
                'client_id': self.merchant_id
            }
            client_socket.send(json.dumps(role_data).encode())
            
            # Receive ElGamal public key
            pub_key_data = json.loads(client_socket.recv(4096).decode())
            public_key = (
                pub_key_data['public_key']['p'],
                pub_key_data['public_key']['g'],
                pub_key_data['public_key']['h']
            )
            
            print(f"[{self.merchant_id}] Received ElGamal public key from server")
            
            # Prepare transaction data
            transaction_info = {
                'transaction_type': transaction_type,
                'amount': amount,
                'description': description
            }
            
            print(f"[{self.merchant_id}] Transaction Details:")
            print(f"                    Type: {transaction_type}")
            print(f"                    Amount: ${amount:.2f}")
            print(f"                    Description: {description}")
            
            # Encrypt transaction with ElGamal
            print(f"[{self.merchant_id}] Encrypting transaction with ElGamal...")
            elgamal = ElGamal()
            transaction_json = json.dumps(transaction_info)
            c1, c2 = elgamal.encrypt(transaction_json, public_key)
            
            print(f"[{self.merchant_id}] ✓ Encrypted: c1={c1}, c2={c2}")
            
            # Send encrypted transaction
            transaction_package = {
                'c1': c1,
                'c2': c2,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            client_socket.send(json.dumps(transaction_package).encode())
            
            # Receive response
            response = json.loads(client_socket.recv(4096).decode())
            
            print("-" * 90)
            if response['status'] == 'success':
                print(f"[{self.merchant_id}] ✓ {response['message']}")
                print(f"[{self.merchant_id}] Transaction ID: {response['transaction_id']}")
            else:
                print(f"[{self.merchant_id}] ✗ {response['message']}")
            print("="*90 + "\n")
            
            client_socket.close()
            return True
            
        except Exception as e:
            print(f"[{self.merchant_id}] Error: {e}")
            import traceback
            traceback.print_exc()
            return False

class AuditorClient:
    """Auditor role - verifies transaction summaries"""
    
    def __init__(self, auditor_id, host='127.0.0.1', port=5557):
        self.auditor_id = auditor_id
        self.host = host
        self.port = port
        self.role = 'AUDITOR'
    
    def request_audit(self):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.host, self.port))
            
            print(f"\n[{self.auditor_id}] Connected to server for audit")
            print("="*90)
            
            # Send role identification
            role_data = {
                'role': self.role,
                'client_id': self.auditor_id
            }
            client_socket.send(json.dumps(role_data).encode())
            
            # Receive audit package
            audit_data = json.loads(client_socket.recv(16384).decode())
            
            if audit_data['status'] != 'success':
                print(f"[{self.auditor_id}] ✗ {audit_data['message']}")
                return
            
            print(f"[{self.auditor_id}] Received audit package")
            print(f"[{self.auditor_id}] Transactions: {audit_data['transaction_count']}")
            print("-" * 90)
            
            # Verify SHA-256 hash
            print(f"[{self.auditor_id}] Verifying SHA-256 hash...")
            computed_hash = hashlib.sha256(audit_data['summary'].encode('utf-8')).hexdigest()
            
            if computed_hash == audit_data['hash']:
                print(f"[{self.auditor_id}] ✓ Hash verified")
                print(f"[{self.auditor_id}]   Expected: {audit_data['hash']}")
                print(f"[{self.auditor_id}]   Computed: {computed_hash}")
            else:
                print(f"[{self.auditor_id}] ✗ Hash mismatch!")
                return
            
            # Verify RSA signature
            print(f"[{self.auditor_id}] Verifying RSA digital signature...")
            server_public_key = RSASignature.import_public_key(audit_data['server_public_key'])
            rsa = RSASignature()
            
            is_valid = rsa.verify(
                audit_data['summary'],
                audit_data['signature'],
                server_public_key
            )
            
            if is_valid:
                print(f"[{self.auditor_id}] ✓ Signature verified successfully")
                print(f"[{self.auditor_id}] ✓ Transaction summary is authentic and unmodified")
            else:
                print(f"[{self.auditor_id}] ✗ Signature verification failed!")
                return
            
            print("="*90)
            print("\n[AUDIT REPORT]\n")
            print(audit_data['summary'])
            print("\n[AUDIT COMPLETE] All verifications passed ✓\n")
            
            client_socket.close()
            return True
            
        except Exception as e:
            print(f"[{self.auditor_id}] Error: {e}")
            import traceback
            traceback.print_exc()
            return False

# ==================== MENU SYSTEM ====================
def customer_menu():
    print("\n" + "="*90)
    print("CUSTOMER MENU")
    print("="*90)
    print("1. Send Purchase Transaction")
    print("2. Send Multiple Transactions")
    print("3. Exit")
    print("="*90)
    
    while True:
        choice = input("\nEnter choice (1-3): ").strip()
        
        if choice == '1':
            customer_id = input("Enter Customer ID: ").strip()
            description = input("Enter purchase description: ").strip()
            try:
                amount = float(input("Enter amount: $").strip())
                customer = CustomerClient(customer_id)
                customer.send_transaction("PURCHASE", amount, description)
            except ValueError:
                print("Invalid amount!")
        
        elif choice == '2':
            customer_id = input("Enter Customer ID: ").strip()
            try:
                num = int(input("Number of transactions: ").strip())
                for i in range(num):
                    print(f"\n--- Transaction {i+1} ---")
                    description = input("Description: ").strip()
                    amount = float(input("Amount: $").strip())
                    customer = CustomerClient(customer_id)
                    customer.send_transaction("PURCHASE", amount, description)
                    import time
                    time.sleep(1)
            except ValueError:
                print("Invalid input!")
        
        elif choice == '3':
            break
        else:
            print("Invalid choice!")

def merchant_menu():
    print("\n" + "="*90)
    print("MERCHANT MENU")
    print("="*90)
    print("1. Send Sales Transaction")
    print("2. Send Multiple Transactions")
    print("3. Exit")
    print("="*90)
    
    while True:
        choice = input("\nEnter choice (1-3): ").strip()
        
        if choice == '1':
            merchant_id = input("Enter Merchant ID: ").strip()
            description = input("Enter sale description: ").strip()
            try:
                amount = float(input("Enter amount: $").strip())
                merchant = MerchantClient(merchant_id)
                merchant.send_transaction("SALE", amount, description)
            except ValueError:
                print("Invalid amount!")
        
        elif choice == '2':
            merchant_id = input("Enter Merchant ID: ").strip()
            try:
                num = int(input("Number of transactions: ").strip())
                for i in range(num):
                    print(f"\n--- Transaction {i+1} ---")
                    description = input("Description: ").strip()
                    amount = float(input("Amount: $").strip())
                    merchant = MerchantClient(merchant_id)
                    merchant.send_transaction("SALE", amount, description)
                    import time
                    time.sleep(1)
            except ValueError:
                print("Invalid input!")
        
        elif choice == '3':
            break
        else:
            print("Invalid choice!")

def auditor_menu():
    print("\n" + "="*90)
    print("AUDITOR MENU")
    print("="*90)
    print("1. Request Transaction Audit")
    print("2. Exit")
    print("="*90)
    
    while True:
        choice = input("\nEnter choice (1-2): ").strip()
        
        if choice == '1':
            auditor_id = input("Enter Auditor ID: ").strip()
            auditor = AuditorClient(auditor_id)
            auditor.request_audit()
        
        elif choice == '2':
            break
        else:
            print("Invalid choice!")

def server_menu(server):
    print("\n" + "="*90)
    print("SERVER MENU")
    print("="*90)
    print("1. View All Transactions")
    print("2. Generate Summary")
    print("3. View Statistics")
    print("4. Exit")
    print("="*90)
    
    while True:
        choice = input("\nEnter choice (1-4): ").strip()
        
        if choice == '1':
            server.display_transactions()
        
        elif choice == '2':
            if server.transactions:
                summary = server.generate_summary()
                print("\n" + summary + "\n")
            else:
                print("\n[SERVER] No transactions to summarize.\n")
        
        elif choice == '3':
            print(f"\n[SERVER] Statistics:")
            print(f"  Total Transactions: {len(server.transactions)}")
            
            customers = sum(1 for t in server.transactions if t['role'] == 'CUSTOMER')
            merchants = sum(1 for t in server.transactions if t['role'] == 'MERCHANT')
            
            print(f"  Customer Transactions: {customers}")
            print(f"  Merchant Transactions: {merchants}")
            print()
        
        elif choice == '4':
            print("\nShutting down server...")
            break
        else:
            print("Invalid choice!")

# ==================== MAIN PROGRAM ====================
def main():
    print("="*90)
    print("ROLE-BASED TRANSACTION SYSTEM")
    print("ElGamal Encryption + RSA Digital Signature + SHA-256")
    print("="*90)
    print("\nSelect Role:")
    print("1. Start Server")
    print("2. Customer (Send Purchase)")
    print("3. Merchant (Send Sale)")
    print("4. Auditor (Verify Transactions)")
    print("5. Run Demo (Automated)")
    print("="*90)
    
    choice = input("\nEnter choice (1-5): ").strip()
    
    if choice == '1':
        server = TransactionServer()
        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()
        
        import time
        time.sleep(1)
        
        server_menu(server)
    
    elif choice == '2':
        customer_menu()
    
    elif choice == '3':
        merchant_menu()
    
    elif choice == '4':
        auditor_menu()
    
    elif choice == '5':
        print("\n[DEMO] Starting automated demo...\n")
        server = TransactionServer()
        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()
        
        import time
        time.sleep(2)
        
        # Demo transactions
        print("[DEMO] Simulating Customer and Merchant transactions...\n")
        
        # Customer transactions
        customers = [
            ("CUST_001", "Laptop Purchase", 1299.99),
            ("CUST_002", "Smartphone", 899.50),
            ("CUST_003", "Headphones", 149.99),
        ]
        
        for customer_id, description, amount in customers:
            customer = CustomerClient(customer_id)
            customer.send_transaction("PURCHASE", amount, description)
            time.sleep(1.5)
        
        # Merchant transactions
        merchants = [
            ("MERCH_001", "Electronics Sale", 2499.00),
            ("MERCH_002", "Clothing Sale", 450.75),
            ("MERCH_003", "Food & Beverage", 89.25),
        ]
        
        for merchant_id, description, amount in merchants:
            merchant = MerchantClient(merchant_id)
            merchant.send_transaction("SALE", amount, description)
            time.sleep(1.5)
        
        time.sleep(2)
        
        # Display transactions on server
        print("\n[DEMO] Server: Displaying all transactions...\n")
        server.display_transactions()
        
        time.sleep(1)
        
        # Auditor verification
        print("[DEMO] Auditor: Requesting transaction audit...\n")
        time.sleep(1)
        
        auditor = AuditorClient("AUDIT_001")
        auditor.request_audit()
        
        input("\nPress Enter to exit demo...")
    
    else:
        print("Invalid choice. Exiting...")

if __name__ == "__main__":
    main()