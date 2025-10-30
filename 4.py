'''Paillier + Diffie-Hellman + RSA (Secure Payment Gateway with Session Keys)

Question:
Develop a Client–Server Payment Gateway Simulation.

Use Diffie–Hellman to establish a shared session key between client and server.

Transaction amounts are encrypted using Paillier encryption.

The final transaction summary is signed using RSA before sending back to the client.

Topics: Paillier + Diffie–Hellman + RSA'''
# secure_payment_gateway.py
import socket
import threading
import json
import time
import random
import hashlib
import base64
from cryptography.fernet import Fernet
from typing import Dict, List, Tuple, Optional

# ==================== CRYPTOGRAPHIC IMPLEMENTATIONS ====================

class Paillier:
    def __init__(self, key_size=128):
        self.public_key, self.private_key = self.generate_keypair(key_size)
    
    @staticmethod
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a
    
    @staticmethod
    def lcm(a, b):
        return abs(a * b) // Paillier.gcd(a, b)
    
    @staticmethod
    def mod_inverse(a, m):
        """Extended Euclidean Algorithm for modular inverse"""
        m0, x0, x1 = m, 0, 1
        if m == 1:
            return 0
        
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        
        if x1 < 0:
            x1 += m0
        return x1
    
    @staticmethod
    def is_prime(n, k=5):
        """Miller-Rabin primality test"""
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        for _ in range(k):
            a = random.randrange(2, n - 1)
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
    
    @staticmethod
    def generate_prime(bits):
        while True:
            num = random.getrandbits(bits)
            num |= (1 << bits - 1) | 1
            if Paillier.is_prime(num):
                return num
    
    def generate_keypair(self, bits):
        p = self.generate_prime(bits // 2)
        q = self.generate_prime(bits // 2)
        
        while p == q:
            q = self.generate_prime(bits // 2)
        
        n = p * q
        g = n + 1
        lambda_n = self.lcm(p - 1, q - 1)
        mu = self.mod_inverse(lambda_n, n)
        
        public_key = (n, g)
        private_key = (lambda_n, mu, n)
        
        return public_key, private_key
    
    def encrypt(self, plaintext, public_key=None):
        if public_key is None:
            public_key = self.public_key
        
        n, g = public_key
        
        while True:
            r = random.randrange(1, n)
            if self.gcd(r, n) == 1:
                break
        
        n_squared = n * n
        ciphertext = (pow(g, plaintext, n_squared) * pow(r, n, n_squared)) % n_squared
        
        return ciphertext
    
    def decrypt(self, ciphertext, private_key=None):
        if private_key is None:
            private_key = self.private_key
        
        lambda_n, mu, n = private_key
        n_squared = n * n
        
        u = pow(ciphertext, lambda_n, n_squared)
        l = (u - 1) // n
        plaintext = (l * mu) % n
        
        return plaintext
    
    def add_encrypted(self, c1, c2, public_key=None):
        """Homomorphic addition of two encrypted values"""
        if public_key is None:
            public_key = self.public_key
        
        n, _ = public_key
        n_squared = n * n
        
        return (c1 * c2) % n_squared


class DiffieHellman:
    def __init__(self, prime_bits=128):
        self.p = self.generate_prime(prime_bits)
        self.g = random.randint(2, self.p - 1)
        self.private_key = random.randint(2, self.p - 2)
        self.public_key = pow(self.g, self.private_key, self.p)
    
    @staticmethod
    def is_prime(n, k=5):
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        for _ in range(k):
            a = random.randrange(2, n - 1)
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
    
    @staticmethod
    def generate_prime(bits):
        while True:
            num = random.getrandbits(bits)
            num |= (1 << bits - 1) | 1
            if DiffieHellman.is_prime(num):
                return num
    
    def compute_shared_secret(self, other_public_key):
        """Compute shared secret from other party's public key"""
        shared_secret = pow(other_public_key, self.private_key, self.p)
        
        # Derive a symmetric key from the shared secret
        key_bytes = str(shared_secret).encode()
        session_key = hashlib.sha256(key_bytes).hexdigest()
        
        return session_key


class RSA:
    def __init__(self, key_size=512):
        self.public_key, self.private_key = self.generate_keypair(key_size)
    
    @staticmethod
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a
    
    @staticmethod
    def mod_inverse(a, m):
        """Extended Euclidean Algorithm for modular inverse"""
        m0, x0, x1 = m, 0, 1
        if m == 1:
            return 0
        
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        
        if x1 < 0:
            x1 += m0
        return x1
    
    @staticmethod
    def is_prime(n, k=5):
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        for _ in range(k):
            a = random.randrange(2, n - 1)
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
    
    @staticmethod
    def generate_prime(bits):
        while True:
            num = random.getrandbits(bits)
            num |= (1 << bits - 1) | 1
            if RSA.is_prime(num):
                return num
    
    def generate_keypair(self, bits):
        max_attempts = 100
        attempts = 0
        
        while attempts < max_attempts:
            try:
                p = self.generate_prime(bits // 2)
                q = self.generate_prime(bits // 2)
                
                while p == q:
                    q = self.generate_prime(bits // 2)
                
                n = p * q
                phi = (p - 1) * (q - 1)
                
                # Choose e such that gcd(e, phi) = 1
                e = 65537
                if self.gcd(e, phi) != 1:
                    e = 3
                    while self.gcd(e, phi) != 1 and e < phi:
                        e += 2
                
                if e >= phi:
                    attempts += 1
                    continue
                
                # Compute d such that (e * d) % phi = 1
                d = self.mod_inverse(e, phi)
                
                public_key = (e, n)
                private_key = (d, n)
                
                return public_key, private_key
                
            except Exception:
                attempts += 1
                continue
        
        raise Exception("Failed to generate RSA keypair after multiple attempts")
    
    def sign(self, message):
        """Sign a message with private key"""
        # Hash the message
        message_hash = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        d, n = self.private_key
        
        # Ensure the hash is smaller than n
        message_hash = message_hash % n
        
        # Sign the hash
        signature = pow(message_hash, d, n)
        return signature
    
    def verify(self, message, signature, public_key=None):
        """Verify a signature with public key"""
        if public_key is None:
            public_key = self.public_key
        
        message_hash = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        e, n = public_key
        
        # Verify signature
        decrypted_hash = pow(signature, e, n)
        
        return decrypted_hash == (message_hash % n)


# ==================== PAYMENT GATEWAY SERVER ====================

class PaymentGatewayServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.sessions: Dict[str, dict] = {}
        self.transactions: List[dict] = []
        
        # Initialize cryptographic systems
        print("🔐 Initializing Payment Gateway Server...")
        self.paillier = Paillier(key_size=128)
        self.rsa = RSA(key_size=512)
        self.server_dh = None
        
        print("✅ Server initialized successfully!")
        print(f"📡 Server listening on {host}:{port}")
    
    def derive_symmetric_key(self, shared_secret: str) -> bytes:
        """Derive symmetric key from shared secret for session encryption"""
        key_material = shared_secret.encode() + b'payment-gateway-session'
        return base64.urlsafe_b64encode(hashlib.sha256(key_material).digest())
    
    def handle_client(self, client_socket, address):
        """Handle individual client connection"""
        print(f"\n🔗 New connection from {address}")
        session_id = None
        
        try:
            # Step 1: Diffie-Hellman Key Exchange
            print(f"🔑 Establishing secure session with {address}")
            
            # Generate server DH parameters
            self.server_dh = DiffieHellman(prime_bits=128)
            dh_params = {
                'type': 'DH_PARAMS',
                'prime': self.server_dh.p,
                'generator': self.server_dh.g,
                'server_public_key': self.server_dh.public_key
            }
            client_socket.send(json.dumps(dh_params).encode())
            
            # Receive client's public key
            client_dh_response = json.loads(client_socket.recv(4096).decode())
            client_public_key = client_dh_response['client_public_key']
            
            # Compute shared secret and session key
            shared_secret = self.server_dh.compute_shared_secret(client_public_key)
            session_key = self.derive_symmetric_key(shared_secret)
            fernet = Fernet(session_key)
            
            session_id = hashlib.sha256(shared_secret.encode()).hexdigest()[:16]
            self.sessions[session_id] = {
                'fernet': fernet,
                'client_address': address,
                'shared_secret': shared_secret
            }
            
            print(f"✅ Secure session established: {session_id}")
            
            # Send session confirmation
            confirmation = {
                'type': 'SESSION_ESTABLISHED',
                'session_id': session_id,
                'server_rsa_public_key': self.rsa.public_key
            }
            encrypted_confirmation = fernet.encrypt(json.dumps(confirmation).encode())
            client_socket.send(encrypted_confirmation)
            
            # Process client requests
            while True:
                encrypted_data = client_socket.recv(8192)
                if not encrypted_data:
                    break
                
                try:
                    # Decrypt request
                    decrypted_data = fernet.decrypt(encrypted_data)
                    request = json.loads(decrypted_data.decode())
                    
                    # Process based on request type
                    response = self.process_request(request, session_id)
                    
                    # Encrypt and send response
                    encrypted_response = fernet.encrypt(json.dumps(response).encode())
                    client_socket.send(encrypted_response)
                    
                except Exception as e:
                    error_response = {
                        'type': 'ERROR',
                        'message': f'Processing error: {str(e)}'
                    }
                    encrypted_error = fernet.encrypt(json.dumps(error_response).encode())
                    client_socket.send(encrypted_error)
        
        except Exception as e:
            print(f"❌ Error handling client {address}: {str(e)}")
        finally:
            if session_id and session_id in self.sessions:
                del self.sessions[session_id]
            client_socket.close()
            print(f"🔌 Connection closed with {address}")
    
    def process_request(self, request: dict, session_id: str) -> dict:
        """Process client requests based on type"""
        request_type = request.get('type')
        
        if request_type == 'PROCESS_TRANSACTION':
            return self.process_transaction(request, session_id)
        elif request_type == 'GET_TOTAL':
            return self.calculate_total(request, session_id)
        elif request_type == 'GET_SUMMARY':
            return self.generate_summary(request, session_id)
        elif request_type == 'GET_TRANSACTIONS':
            return self.get_transactions(request, session_id)
        else:
            return {'type': 'ERROR', 'message': 'Unknown request type'}
    
    def process_transaction(self, request: dict, session_id: str) -> dict:
        """Process a transaction with Paillier encryption"""
        print(f"\n💳 Processing transaction for session {session_id}")
        
        encrypted_amount = request['encrypted_amount']
        description = request['description']
        
        # Store encrypted transaction
        transaction = {
            'id': len(self.transactions) + 1,
            'session_id': session_id,
            'description': description,
            'encrypted_amount': encrypted_amount,
            'timestamp': request.get('timestamp')
        }
        self.transactions.append(transaction)
        
        print(f"✅ Transaction #{transaction['id']} processed: {description}")
        
        return {
            'type': 'TRANSACTION_PROCESSED',
            'transaction_id': transaction['id'],
            'message': 'Transaction processed successfully'
        }
    
    def calculate_total(self, request: dict, session_id: str) -> dict:
        """Calculate total using homomorphic addition"""
        print(f"\n🧮 Calculating total for session {session_id}")
        
        # Get transactions for this session
        session_transactions = [t for t in self.transactions if t['session_id'] == session_id]
        
        if not session_transactions:
            return {
                'type': 'TOTAL_CALCULATED',
                'total_amount': 0,
                'transaction_count': 0
            }
        
        # Homomorphically add encrypted amounts
        encrypted_total = session_transactions[0]['encrypted_amount']
        for i in range(1, len(session_transactions)):
            encrypted_total = self.paillier.add_encrypted(
                encrypted_total,
                session_transactions[i]['encrypted_amount']
            )
        
        # Decrypt total
        total_cents = self.paillier.decrypt(encrypted_total)
        total_amount = total_cents / 100.0
        
        print(f"💰 Total calculated: ${total_amount:.2f}")
        
        return {
            'type': 'TOTAL_CALCULATED',
            'total_amount': total_amount,
            'encrypted_total': encrypted_total,
            'transaction_count': len(session_transactions)
        }
    
    def generate_summary(self, request: dict, session_id: str) -> dict:
        """Generate and sign transaction summary"""
        print(f"\n📋 Generating signed summary for session {session_id}")
        
        # Get transactions and calculate total
        session_transactions = [t for t in self.transactions if t['session_id'] == session_id]
        total_response = self.calculate_total({'type': 'GET_TOTAL'}, session_id)
        
        # Create summary
        summary = {
            'session_id': session_id,
            'transaction_count': len(session_transactions),
            'total_amount': total_response['total_amount'],
            'transactions': [
                {
                    'id': t['id'],
                    'description': t['description'],
                    'timestamp': t.get('timestamp')
                }
                for t in session_transactions
            ]
        }
        
        # Sign summary
        summary_str = json.dumps(summary, sort_keys=True)
        signature = self.rsa.sign(summary_str)
        
        # Verify signature
        is_valid = self.rsa.verify(summary_str, signature)
        
        print(f"✍️  Summary signed and verified: {is_valid}")
        
        return {
            'type': 'SUMMARY_GENERATED',
            'summary': summary,
            'signature': signature,
            'verified': is_valid,
            'server_rsa_public_key': self.rsa.public_key
        }
    
    def get_transactions(self, request: dict, session_id: str) -> dict:
        """Get all transactions for the session"""
        session_transactions = [t for t in self.transactions if t['session_id'] == session_id]
        
        return {
            'type': 'TRANSACTIONS_LIST',
            'transactions': [
                {
                    'id': t['id'],
                    'description': t['description'],
                    'timestamp': t.get('timestamp')
                }
                for t in session_transactions
            ],
            'count': len(session_transactions)
        }
    
    def start_server(self):
        """Start the payment gateway server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            print(f"🚀 Payment Gateway Server running on {self.host}:{self.port}")
            print("Press Ctrl+C to stop the server\n")
            
            while True:
                client_socket, address = server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\n🛑 Server shutdown requested")
        except Exception as e:
            print(f"❌ Server error: {str(e)}")
        finally:
            server_socket.close()
            print("🔴 Server stopped")


# ==================== PAYMENT GATEWAY CLIENT ====================

class PaymentClient:
    def __init__(self, server_host='localhost', server_port=12345):
        self.server_host = server_host
        self.server_port = server_port
        self.session_id = None
        self.fernet = None
        self.client_dh = None
        self.paillier = Paillier(key_size=128)
        self.rsa = RSA(key_size=512)
        self.server_rsa_public_key = None
        
    def connect(self):
        """Connect to server and establish secure session"""
        print("🔗 Connecting to Payment Gateway Server...")
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            
            # Step 1: Diffie-Hellman Key Exchange
            print("🔑 Performing Diffie-Hellman key exchange...")
            
            # Receive server DH parameters
            dh_params = json.loads(self.socket.recv(4096).decode())
            prime = dh_params['prime']
            generator = dh_params['generator']
            server_public_key = dh_params['server_public_key']
            
            # Generate client DH key pair
            self.client_dh = DiffieHellman(prime_bits=128)
            self.client_dh.p = prime
            self.client_dh.g = generator
            self.client_dh.private_key = self.client_dh.private_key % (prime - 1)
            self.client_dh.public_key = pow(generator, self.client_dh.private_key, prime)
            
            # Send client public key to server
            client_dh_response = {
                'client_public_key': self.client_dh.public_key
            }
            self.socket.send(json.dumps(client_dh_response).encode())
            
            # Compute shared secret and session key
            shared_secret = self.client_dh.compute_shared_secret(server_public_key)
            session_key = self.derive_symmetric_key(shared_secret)
            self.fernet = Fernet(session_key)
            
            # Receive session confirmation
            encrypted_confirmation = self.socket.recv(4096)
            confirmation = json.loads(self.fernet.decrypt(encrypted_confirmation).decode())
            self.session_id = confirmation['session_id']
            self.server_rsa_public_key = confirmation['server_rsa_public_key']
            
            print(f"✅ Secure session established: {self.session_id}")
            return True
            
        except Exception as e:
            print(f"❌ Connection failed: {str(e)}")
            return False
    
    def derive_symmetric_key(self, shared_secret: str) -> bytes:
        """Derive symmetric key from shared secret"""
        key_material = shared_secret.encode() + b'payment-gateway-session'
        return base64.urlsafe_b64encode(hashlib.sha256(key_material).digest())
    
    def send_request(self, request: dict) -> dict:
        """Send encrypted request and receive response"""
        try:
            # Encrypt and send request
            encrypted_request = self.fernet.encrypt(json.dumps(request).encode())
            self.socket.send(encrypted_request)
            
            # Receive and decrypt response
            encrypted_response = self.socket.recv(8192)
            response = json.loads(self.fernet.decrypt(encrypted_response).decode())
            return response
            
        except Exception as e:
            return {'type': 'ERROR', 'message': f'Communication error: {str(e)}'}
    
    def process_transaction(self, amount: float, description: str):
        """Send transaction to server with Paillier encryption"""
        print(f"\n💳 Processing transaction: {description} - ${amount:.2f}")
        
        # Convert amount to cents and encrypt
        amount_cents = int(amount * 100)
        encrypted_amount = self.paillier.encrypt(amount_cents)
        
        request = {
            'type': 'PROCESS_TRANSACTION',
            'encrypted_amount': encrypted_amount,
            'description': description,
            'timestamp': time.time()
        }
        
        response = self.send_request(request)
        
        if response.get('type') == 'TRANSACTION_PROCESSED':
            print(f"✅ Transaction #{response['transaction_id']} processed successfully!")
        else:
            print(f"❌ Transaction failed: {response.get('message', 'Unknown error')}")
        
        return response
    
    def get_total(self):
        """Request total amount from server"""
        print("\n🧮 Requesting total amount...")
        
        request = {'type': 'GET_TOTAL'}
        response = self.send_request(request)
        
        if response.get('type') == 'TOTAL_CALCULATED':
            total = response['total_amount']
            count = response['transaction_count']
            print(f"💰 Total: ${total:.2f} ({count} transactions)")
        else:
            print(f"❌ Failed to get total: {response.get('message')}")
        
        return response
    
    def get_summary(self):
        """Request signed transaction summary"""
        print("\n📋 Requesting signed transaction summary...")
        
        request = {'type': 'GET_SUMMARY'}
        response = self.send_request(request)
        
        if response.get('type') == 'SUMMARY_GENERATED':
            summary = response['summary']
            signature = response['signature']
            verified = response['verified']
            
            print(f"\n📊 TRANSACTION SUMMARY")
            print("=" * 50)
            print(f"Session ID: {summary['session_id']}")
            print(f"Total Transactions: {summary['transaction_count']}")
            print(f"Total Amount: ${summary['total_amount']:.2f}")
            print(f"Digital Signature Verified: {verified}")
            
            # Client-side verification
            summary_str = json.dumps(summary, sort_keys=True)
            client_verified = self.verify_server_signature(summary_str, signature)
            print(f"Client Verification: {client_verified}")
            
            if verified and client_verified:
                print("✅ Summary is authentic and untampered!")
            else:
                print("❌ Summary verification failed!")
                
        else:
            print(f"❌ Failed to get summary: {response.get('message')}")
        
        return response
    
    def verify_server_signature(self, message: str, signature: int) -> bool:
        """Verify server's RSA signature"""
        try:
            if not self.server_rsa_public_key:
                return False
            
            message_hash = int(hashlib.sha256(message.encode()).hexdigest(), 16)
            e, n = self.server_rsa_public_key
            
            # Verify signature
            decrypted_hash = pow(signature, e, n)
            
            return decrypted_hash == (message_hash % n)
        except:
            return False
    
    def get_transactions(self):
        """Request transaction list"""
        print("\n📜 Requesting transaction list...")
        
        request = {'type': 'GET_TRANSACTIONS'}
        response = self.send_request(request)
        
        if response.get('type') == 'TRANSACTIONS_LIST':
            transactions = response['transactions']
            count = response['count']
            
            print(f"\n📋 TRANSACTIONS ({count} total)")
            print("=" * 40)
            for t in transactions:
                print(f"#{t['id']}: {t['description']}")
        else:
            print(f"❌ Failed to get transactions: {response.get('message')}")
        
        return response
    
    def disconnect(self):
        """Close connection to server"""
        if hasattr(self, 'socket'):
            self.socket.close()
        print("🔌 Disconnected from server")

    def run_client(self):
        """Run the client interface"""
        if not self.connect():
            return
        
        while True:
            print("\n" + "=" * 50)
            print("🏦 PAYMENT GATEWAY CLIENT")
            print("=" * 50)
            print("1. Process Transaction")
            print("2. Get Total Amount")
            print("3. Get Signed Summary")
            print("4. View Transactions")
            print("5. Exit")
            print("=" * 50)
            
            choice = input("\nEnter your choice (1-5): ").strip()
            
            if choice == '1':
                try:
                    amount = float(input("Enter transaction amount ($): "))
                    description = input("Enter transaction description: ")
                    self.process_transaction(amount, description)
                except ValueError:
                    print("❌ Invalid amount entered.")
            
            elif choice == '2':
                self.get_total()
            
            elif choice == '3':
                self.get_summary()
            
            elif choice == '4':
                self.get_transactions()
            
            elif choice == '5':
                print("👋 Thank you for using Payment Gateway!")
                break
            
            else:
                print("❌ Invalid choice. Please select 1-5.")
            
            input("\nPress Enter to continue...")
        
        self.disconnect()


# ==================== MAIN APPLICATION ====================

def main():
    print("🔐 SECURE PAYMENT GATEWAY SYSTEM")
    print("=" * 60)
    print("1. Start Payment Gateway Server")
    print("2. Start Payment Gateway Client")
    print("3. Exit")
    print("=" * 60)
    
    while True:
        choice = input("\nSelect mode (1-3): ").strip()
        
        if choice == '1':
            print("\n🚀 Starting Payment Gateway Server...")
            server = PaymentGatewayServer()
            server.start_server()
            break
            
        elif choice == '2':
            print("\n💻 Starting Payment Gateway Client...")
            client = PaymentClient()
            client.run_client()
            break
            
        elif choice == '3':
            print("👋 Goodbye!")
            break
            
        else:
            print("❌ Invalid choice. Please select 1-3.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Application terminated by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")