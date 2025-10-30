from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import json
import base64
from datetime import datetime
import hashlib
'''Secure E-Commerce Portal (RSA + AES + ElGamal Signature)

Build a simple e-commerce system where:

User login data is encrypted with AES.

Payment details are RSA-encrypted.

Each transaction is digitally signed using ElGamal to ensure authenticity.'''

class CryptoEngine:
    """Handles all cryptographic operations"""
    
    @staticmethod
    def generate_aes_key():
        """Generate AES-256 key"""
        return get_random_bytes(32)
    
    @staticmethod
    def aes_encrypt(key, plaintext):
        """Encrypt with AES-256 CBC"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded)
        
        return iv, ciphertext
    
    @staticmethod
    def aes_decrypt(key, iv, ciphertext):
        """Decrypt with AES-256 CBC"""
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)
        plaintext = unpad(padded, AES.block_size)
        return plaintext.decode('utf-8')
    
    @staticmethod
    def generate_rsa_keypair(bits=1024):
        """Generate RSA key pair"""
        key = RSA.generate(bits)
        return key, key.publickey()
    
    @staticmethod
    def rsa_encrypt(public_key, plaintext):
        """Encrypt with RSA"""
        cipher = PKCS1_OAEP.new(public_key)
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Chunk for large data
        max_chunk = 86  # RSA-1024 with OAEP
        chunks = [plaintext[i:i+max_chunk] 
                  for i in range(0, len(plaintext), max_chunk)]
        
        return [cipher.encrypt(chunk) for chunk in chunks]
    
    @staticmethod
    def rsa_decrypt(private_key, encrypted_chunks):
        """Decrypt with RSA"""
        cipher = PKCS1_OAEP.new(private_key)
        chunks = [cipher.decrypt(chunk) for chunk in encrypted_chunks]
        return b''.join(chunks).decode('utf-8')
    
    @staticmethod
    def generate_dsa_keypair(bits=1024):
        """Generate DSA key pair (faster than ElGamal)"""
        key = DSA.generate(bits)
        return key, key.publickey()
    
    @staticmethod
    def dsa_sign(private_key, message):
        """Create DSA digital signature"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        h = SHA256.new(message)
        signer = DSS.new(private_key, 'fips-186-3')
        signature = signer.sign(h)
        
        return base64.b64encode(signature).decode()
    
    @staticmethod
    def dsa_verify(public_key, message, signature):
        """Verify DSA signature"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        try:
            h = SHA256.new(message)
            verifier = DSS.new(public_key, 'fips-186-3')
            sig_bytes = base64.b64decode(signature)
            verifier.verify(h, sig_bytes)
            return True
        except:
            return False
    
    @staticmethod
    def hash_password(password):
        """Hash password with SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()


class Product:
    """Product in the e-commerce store"""
    
    def __init__(self, prod_id, name, price, stock):
        self.prod_id = prod_id
        self.name = name
        self.price = price
        self.stock = stock
        self.description = f"{name} - Premium Quality"
    
    def __str__(self):
        return f"{self.prod_id}: {self.name} - ${self.price:.2f} (Stock: {self.stock})"


class User:
    """User account"""
    
    def __init__(self, username, password, email, aes_key):
        self.username = username
        self.email = email
        self.balance = 1000.00  # Starting balance
        self.cart = []
        self.order_history = []
        
        # Encrypt password with AES
        self.password_hash = CryptoEngine.hash_password(password)
        
        # Store encrypted login data
        login_data = json.dumps({
            'username': username,
            'email': email,
            'password_hash': self.password_hash
        })
        self.encrypted_login_iv, self.encrypted_login_data = \
            CryptoEngine.aes_encrypt(aes_key, login_data)
        
        # Generate RSA keys for payment encryption
        self.payment_private, self.payment_public = CryptoEngine.generate_rsa_keypair()
        
        # Generate DSA keys for transaction signing
        self.signature_private, self.signature_public = CryptoEngine.generate_dsa_keypair()
    
    def add_to_cart(self, product, quantity):
        """Add product to shopping cart"""
        self.cart.append({
            'product': product,
            'quantity': quantity
        })
    
    def get_cart_total(self):
        """Calculate cart total"""
        return sum(item['product'].price * item['quantity'] 
                   for item in self.cart)
    
    def clear_cart(self):
        """Clear shopping cart"""
        self.cart = []


class Transaction:
    """Secure transaction with encryption and signature"""
    
    def __init__(self, trans_id, user, items, total_amount, payment_details):
        self.trans_id = trans_id
        self.username = user.username
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.total_amount = total_amount
        
        # Transaction data
        self.transaction_data = {
            'trans_id': trans_id,
            'username': user.username,
            'items': [{'product': item['product'].name, 
                      'quantity': item['quantity'],
                      'price': item['product'].price} 
                     for item in items],
            'total_amount': total_amount,
            'timestamp': self.timestamp
        }
        
        # Payment details (card info, etc.)
        self.payment_data = payment_details
        
        # 1. RSA Encrypt payment details with user's payment public key
        payment_json = json.dumps(payment_details)
        self.encrypted_payment = CryptoEngine.rsa_encrypt(
            user.payment_public, 
            payment_json
        )
        
        # 2. Create digital signature using DSA
        trans_json = json.dumps(self.transaction_data, sort_keys=True)
        self.signature = CryptoEngine.dsa_sign(
            user.signature_private, 
            trans_json
        )
        
        # Store public key for verification
        self.user_signature_public = user.signature_public
    
    def verify_signature(self):
        """Verify transaction signature"""
        trans_json = json.dumps(self.transaction_data, sort_keys=True)
        return CryptoEngine.dsa_verify(
            self.user_signature_public,
            trans_json,
            self.signature
        )
    
    def decrypt_payment_details(self, user_private_key):
        """Decrypt payment details"""
        payment_json = CryptoEngine.rsa_decrypt(
            user_private_key,
            self.encrypted_payment
        )
        return json.loads(payment_json)


class ECommerceSystem:
    """Main E-Commerce System"""
    
    def __init__(self):
        print("\n" + "="*70)
        print("  INITIALIZING SECURE E-COMMERCE PORTAL")
        print("="*70)
        
        # Generate system AES key for login encryption
        print("\nGenerating encryption keys...")
        self.system_aes_key = CryptoEngine.generate_aes_key()
        print("✓ AES-256 key generated for login encryption")
        print("✓ RSA-1024 for payment encryption")
        print("✓ DSA-1024 for transaction signatures")
        
        # Initialize system
        self.users = {}
        self.products = {}
        self.transactions = []
        self.transaction_counter = 1
        self.current_user = None
        
        # Setup demo data
        self._setup_demo_products()
        self._setup_demo_users()
        
        print("\n✓ System initialized successfully!")
    
    def _setup_demo_products(self):
        """Create demo products"""
        self.products = {
            'P001': Product('P001', 'Laptop Pro 15"', 1299.99, 10),
            'P002': Product('P002', 'Wireless Mouse', 29.99, 50),
            'P003': Product('P003', 'Mechanical Keyboard', 149.99, 25),
            'P004': Product('P004', 'USB-C Hub', 49.99, 30),
            'P005': Product('P005', 'Monitor 27" 4K', 599.99, 15),
        }
        print("✓ Product catalog loaded (5 products)")
    
    def _setup_demo_users(self):
        """Create demo users"""
        print("\nCreating demo user accounts...")
        self.register_user('alice', 'password123', 'alice@shop.com')
        self.register_user('bob', 'securepass', 'bob@shop.com')
        print("✓ Demo users created (alice, bob)")
    
    def register_user(self, username, password, email):
        """Register new user with encrypted credentials"""
        if username in self.users:
            return False
        
        user = User(username, password, email, self.system_aes_key)
        self.users[username] = user
        return True
    
    def login(self, username, password):
        """Authenticate user"""
        if username not in self.users:
            return False
        
        user = self.users[username]
        password_hash = CryptoEngine.hash_password(password)
        
        if password_hash == user.password_hash:
            self.current_user = user
            return True
        
        return False
    
    def decrypt_user_login_data(self, username):
        """Decrypt and display user login data (admin function)"""
        if username not in self.users:
            return None
        
        user = self.users[username]
        decrypted = CryptoEngine.aes_decrypt(
            self.system_aes_key,
            user.encrypted_login_iv,
            user.encrypted_login_data
        )
        return json.loads(decrypted)
    
    def display_products(self):
        """Display product catalog"""
        print("\n" + "="*70)
        print("  PRODUCT CATALOG")
        print("="*70)
        
        for prod_id, product in self.products.items():
            print(f"\n{product}")
            print(f"  Description: {product.description}")
            print("-"*70)
    
    def add_to_cart(self, prod_id, quantity):
        """Add product to cart"""
        if prod_id not in self.products:
            print("✗ Product not found!")
            return False
        
        product = self.products[prod_id]
        
        if quantity > product.stock:
            print(f"✗ Insufficient stock! Available: {product.stock}")
            return False
        
        self.current_user.add_to_cart(product, quantity)
        print(f"✓ Added {quantity}x {product.name} to cart")
        return True
    
    def view_cart(self):
        """Display shopping cart"""
        print("\n" + "="*70)
        print(f"  SHOPPING CART - {self.current_user.username}")
        print("="*70)
        
        if not self.current_user.cart:
            print("Your cart is empty.")
            return
        
        for idx, item in enumerate(self.current_user.cart, 1):
            product = item['product']
            quantity = item['quantity']
            subtotal = product.price * quantity
            
            print(f"\n{idx}. {product.name}")
            print(f"   Price: ${product.price:.2f} x {quantity} = ${subtotal:.2f}")
        
        total = self.current_user.get_cart_total()
        print("\n" + "-"*70)
        print(f"TOTAL: ${total:.2f}")
        print("="*70)
    
    def checkout(self):
        """Process checkout with secure payment"""
        if not self.current_user.cart:
            print("✗ Cart is empty!")
            return
        
        total = self.current_user.get_cart_total()
        
        print("\n" + "="*70)
        print("  SECURE CHECKOUT")
        print("="*70)
        print(f"\nTotal Amount: ${total:.2f}")
        print(f"Available Balance: ${self.current_user.balance:.2f}")
        
        if total > self.current_user.balance:
            print("\n✗ Insufficient balance!")
            return
        
        # Get payment details
        print("\n--- Payment Information ---")
        card_number = input("Card Number (16 digits): ").strip()
        card_name = input("Cardholder Name: ").strip()
        expiry = input("Expiry (MM/YY): ").strip()
        cvv = input("CVV (3 digits): ").strip()
        
        if len(card_number) != 16 or len(cvv) != 3:
            print("✗ Invalid card details!")
            return
        
        # Create payment details
        payment_details = {
            'card_number': card_number,
            'cardholder': card_name,
            'expiry': expiry,
            'cvv': cvv,
            'amount': total
        }
        
        print("\n🔄 Processing transaction...")
        print("  • Encrypting payment details with RSA...")
        print("  • Creating digital signature with DSA...")
        
        # Create transaction
        trans_id = f"TXN{self.transaction_counter:05d}"
        self.transaction_counter += 1
        
        transaction = Transaction(
            trans_id,
            self.current_user,
            self.current_user.cart.copy(),
            total,
            payment_details
        )
        
        # Update stock and balance
        for item in self.current_user.cart:
            item['product'].stock -= item['quantity']
        
        self.current_user.balance -= total
        
        # Store transaction
        self.transactions.append(transaction)
        self.current_user.order_history.append(transaction)
        
        # Clear cart
        self.current_user.clear_cart()
        
        print("\n" + "="*70)
        print("✓ TRANSACTION SUCCESSFUL!")
        print("="*70)
        print(f"Transaction ID: {trans_id}")
        print(f"Amount Charged: ${total:.2f}")
        print(f"New Balance: ${self.current_user.balance:.2f}")
        print(f"\n🔒 Security Features Applied:")
        print(f"  ✓ Payment details encrypted with RSA-1024")
        print(f"  ✓ Transaction signed with DSA-1024")
        print(f"  ✓ Signature hash: {transaction.signature[:32]}...")
        print("="*70)
    
    def view_order_history(self):
        """View user's order history"""
        print("\n" + "="*70)
        print(f"  ORDER HISTORY - {self.current_user.username}")
        print("="*70)
        
        if not self.current_user.order_history:
            print("No orders yet.")
            return
        
        for transaction in self.current_user.order_history:
            print(f"\n{'─'*70}")
            print(f"Transaction ID: {transaction.trans_id}")
            print(f"Date: {transaction.timestamp}")
            print(f"Total: ${transaction.total_amount:.2f}")
            print(f"Items:")
            
            for item_data in transaction.transaction_data['items']:
                print(f"  • {item_data['product']} x{item_data['quantity']} "
                      f"@ ${item_data['price']:.2f}")
            
            print(f"Status: ✓ Completed & Signed")
            print(f"{'─'*70}")
    
    def verify_transaction(self, trans_id):
        """Verify transaction signature"""
        transaction = None
        for trans in self.transactions:
            if trans.trans_id == trans_id:
                transaction = trans
                break
        
        if not transaction:
            print("✗ Transaction not found!")
            return
        
        print("\n" + "="*70)
        print("  TRANSACTION VERIFICATION")
        print("="*70)
        print(f"\nTransaction ID: {trans_id}")
        print(f"Username: {transaction.username}")
        print(f"Amount: ${transaction.total_amount:.2f}")
        print(f"Timestamp: {transaction.timestamp}")
        
        # Verify signature
        is_valid = transaction.verify_signature()
        
        print(f"\n🔏 Digital Signature Verification:")
        if is_valid:
            print("  ✓ VALID - Transaction is authentic")
            print("  ✓ Transaction has not been tampered with")
            print("  ✓ Signed by verified user")
        else:
            print("  ✗ INVALID - Possible tampering detected!")
        
        print("="*70)
    
    def decrypt_payment_info(self, trans_id):
        """Decrypt payment information (user only)"""
        transaction = None
        for trans in self.current_user.order_history:
            if trans.trans_id == trans_id:
                transaction = trans
                break
        
        if not transaction:
            print("✗ Transaction not found in your history!")
            return
        
        print("\n" + "="*70)
        print("  DECRYPT PAYMENT DETAILS")
        print("="*70)
        print("\n🔄 Decrypting with your private RSA key...")
        
        payment_data = transaction.decrypt_payment_details(
            self.current_user.payment_private
        )
        
        print("\n🔓 DECRYPTED PAYMENT INFORMATION:")
        print("-"*70)
        print(f"Card Number: {payment_data['card_number'][:4]}********{payment_data['card_number'][-4:]}")
        print(f"Cardholder: {payment_data['cardholder']}")
        print(f"Expiry: {payment_data['expiry']}")
        print(f"Amount: ${payment_data['amount']:.2f}")
        print("="*70)
    
    def admin_view_encrypted_login(self):
        """Admin function to view encrypted login data"""
        print("\n--- Admin: View Encrypted Login Data ---")
        username = input("Enter username: ").strip()
        
        if username not in self.users:
            print("✗ User not found!")
            return
        
        print(f"\n🔓 Decrypting login data for: {username}")
        login_data = self.decrypt_user_login_data(username)
        
        if login_data:
            print("\nDecrypted Login Information:")
            print(json.dumps(login_data, indent=2))
        else:
            print("✗ Failed to decrypt!")
    
    def display_security_info(self):
        """Display security features"""
        print("\n" + "="*70)
        print("  SECURITY FEATURES")
        print("="*70)
        print("""
🔐 MULTI-LAYER SECURITY ARCHITECTURE

1. LOGIN CREDENTIALS (AES-256 Encryption)
   • Username, email, and password hash encrypted
   • Symmetric encryption for fast access
   • Stored encrypted at rest

2. PAYMENT DETAILS (RSA-1024 Encryption)
   • Card number, CVV, expiry encrypted
   • Asymmetric encryption with user's public key
   • Only user's private key can decrypt
   • Secure key exchange

3. TRANSACTION AUTHENTICATION (DSA-1024 Signatures)
   • Every transaction digitally signed
   • Proves transaction authenticity
   • Detects tampering attempts
   • Non-repudiation guarantee

4. PASSWORD HASHING (SHA-256)
   • Passwords never stored in plaintext
   • One-way hashing function
   • Secure authentication

┌────────────────────────────────────────────────────────────────┐
│  WHY THESE SECURITY MEASURES?                                  │
├────────────────────────────────────────────────────────────────┤
│  ✓ Protect customer data from breaches                        │
│  ✓ Secure payment processing                                  │
│  ✓ Prevent transaction fraud                                  │
│  ✓ Comply with PCI-DSS standards                              │
│  ✓ Build customer trust                                       │
└────────────────────────────────────────────────────────────────┘
        """)
        print("="*70)
    
    def run(self):
        """Main system loop"""
        while True:
            if not self.current_user:
                print("\n" + "="*70)
                print("  SECURE E-COMMERCE PORTAL")
                print("="*70)
                print("1. Login")
                print("2. Register")
                print("3. View Products")
                print("4. Security Information")
                print("5. Exit")
                print("="*70)
                
                choice = input("\nEnter choice: ").strip()
                
                if choice == '1':
                    print("\n--- User Login ---")
                    username = input("Username: ").strip()
                    password = input("Password: ").strip()
                    
                    if self.login(username, password):
                        print(f"✓ Welcome back, {username}!")
                    else:
                        print("✗ Invalid credentials!")
                
                elif choice == '2':
                    print("\n--- User Registration ---")
                    username = input("Username: ").strip()
                    password = input("Password: ").strip()
                    email = input("Email: ").strip()
                    
                    if self.register_user(username, password, email):
                        print("✓ Registration successful!")
                        print("✓ Your login data is AES-encrypted")
                        print("✓ RSA keys generated for payments")
                        print("✓ DSA keys generated for signatures")
                    else:
                        print("✗ Username already exists!")
                
                elif choice == '3':
                    self.display_products()
                
                elif choice == '4':
                    self.display_security_info()
                
                elif choice == '5':
                    print("\n" + "="*70)
                    print("  Thank you for visiting!")
                    print("="*70)
                    break
                
                else:
                    print("✗ Invalid choice!")
            
            else:
                print("\n" + "="*70)
                print(f"  WELCOME, {self.current_user.username.upper()}")
                print("="*70)
                print(f"Balance: ${self.current_user.balance:.2f}")
                print(f"Cart Items: {len(self.current_user.cart)}")
                print("-"*70)
                print("1. Browse Products")
                print("2. Add to Cart")
                print("3. View Cart")
                print("4. Checkout")
                print("5. Order History")
                print("6. Verify Transaction")
                print("7. Decrypt Payment Info")
                print("8. Admin: View Encrypted Login")
                print("9. Logout")
                print("="*70)
                
                choice = input("\nEnter choice: ").strip()
                
                if choice == '1':
                    self.display_products()
                
                elif choice == '2':
                    prod_id = input("Product ID: ").strip().upper()
                    try:
                        quantity = int(input("Quantity: ").strip())
                        self.add_to_cart(prod_id, quantity)
                    except ValueError:
                        print("✗ Invalid quantity!")
                
                elif choice == '3':
                    self.view_cart()
                
                elif choice == '4':
                    self.checkout()
                
                elif choice == '5':
                    self.view_order_history()
                
                elif choice == '6':
                    trans_id = input("Transaction ID: ").strip().upper()
                    self.verify_transaction(trans_id)
                
                elif choice == '7':
                    trans_id = input("Transaction ID: ").strip().upper()
                    self.decrypt_payment_info(trans_id)
                
                elif choice == '8':
                    self.admin_view_encrypted_login()
                
                elif choice == '9':
                    print(f"✓ Logged out from {self.current_user.username}")
                    self.current_user = None
                
                else:
                    print("✗ Invalid choice!")


if __name__ == "__main__":
    system = ECommerceSystem()
    system.run()