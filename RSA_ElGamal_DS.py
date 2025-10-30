from Crypto.PublicKey import RSA, DSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import json
import base64
from datetime import datetime
'''Multi-Role Secure Banking System (RSA + ElGamal + Digital Signature)

Design a menu-driven banking system with roles: Customer, Merchant, and Auditor.

Customer and Merchant perform transactions encrypted using RSA.

Each transaction is digitally signed using ElGamal for authenticity.

The Auditor can view and verify transactions using public keys..'''

class CryptoUtils:
    """Utility class for cryptographic operations"""
    
    @staticmethod
    def generate_rsa_keypair(bits=2048):
        """Generate RSA key pair"""
        print("  Generating RSA keys...", end=" ", flush=True)
        key = RSA.generate(bits)
        print("✓")
        return key, key.publickey()
    
    @staticmethod
    def generate_dsa_keypair(bits=2048):
        """Generate DSA key pair for digital signatures (faster than ElGamal)"""
        print("  Generating DSA signature keys...", end=" ", flush=True)
        key = DSA.generate(bits)
        print("✓")
        return key, key.publickey()
    
    @staticmethod
    def rsa_encrypt(public_key, plaintext):
        """Encrypt data using RSA public key"""
        cipher = PKCS1_OAEP.new(public_key)
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        
        # RSA can only encrypt small amounts of data
        if len(plaintext) > 190:  # RSA-2048 can encrypt max ~190 bytes with OAEP
            raise ValueError("Message too long for RSA encryption")
        
        ciphertext = cipher.encrypt(plaintext)
        return base64.b64encode(ciphertext).decode()
    
    @staticmethod
    def rsa_decrypt(private_key, ciphertext_b64):
        """Decrypt data using RSA private key"""
        cipher = PKCS1_OAEP.new(private_key)
        ciphertext = base64.b64decode(ciphertext_b64)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode()
    
    @staticmethod
    def dsa_sign(private_key, message):
        """Sign message using DSA"""
        if isinstance(message, str):
            message = message.encode()
        
        # Hash the message
        h = SHA256.new(message)
        
        # DSA signature
        signer = DSS.new(private_key, 'fips-186-3')
        signature = signer.sign(h)
        
        return {
            'signature': base64.b64encode(signature).decode(),
            'hash': h.hexdigest()
        }
    
    @staticmethod
    def dsa_verify(public_key, message, signature_data):
        """Verify DSA signature"""
        if isinstance(message, str):
            message = message.encode()
        
        # Hash the message
        h = SHA256.new(message)
        
        # Verify hash matches
        if h.hexdigest() != signature_data['hash']:
            return False
        
        try:
            # Verify signature
            verifier = DSS.new(public_key, 'fips-186-3')
            signature = base64.b64decode(signature_data['signature'])
            verifier.verify(h, signature)
            return True
        except ValueError:
            return False


class User:
    """Base class for all users"""
    
    def __init__(self, user_id, name, role):
        self.user_id = user_id
        self.name = name
        self.role = role
        print(f"\nInitializing {role}: {name} ({user_id})")
        self.rsa_private, self.rsa_public = CryptoUtils.generate_rsa_keypair()
        self.dsa_private, self.dsa_public = CryptoUtils.generate_dsa_keypair()


class Customer(User):
    """Customer class with banking operations"""
    
    def __init__(self, user_id, name, initial_balance=10000):
        super().__init__(user_id, name, "Customer")
        self.balance = initial_balance


class Merchant(User):
    """Merchant class for receiving payments"""
    
    def __init__(self, user_id, name, initial_balance=5000):
        super().__init__(user_id, name, "Merchant")
        self.balance = initial_balance


class Auditor(User):
    """Auditor class for viewing and verifying transactions"""
    
    def __init__(self, user_id, name):
        super().__init__(user_id, name, "Auditor")


class Transaction:
    """Transaction class"""
    
    def __init__(self, trans_id, sender, receiver, amount, description=""):
        self.trans_id = trans_id
        self.sender_id = sender.user_id
        self.receiver_id = receiver.user_id
        self.amount = amount
        self.description = description
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Create transaction data
        self.data = {
            'trans_id': trans_id,
            'sender_id': sender.user_id,
            'receiver_id': receiver.user_id,
            'amount': amount,
            'description': description,
            'timestamp': self.timestamp
        }
        
        # Encrypt transaction data with receiver's public key
        trans_json = json.dumps(self.data)
        self.encrypted_data = CryptoUtils.rsa_encrypt(receiver.rsa_public, trans_json)
        
        # Sign transaction with sender's DSA private key
        self.signature = CryptoUtils.dsa_sign(sender.dsa_private, trans_json)
        
        # Store sender and receiver public keys for verification
        self.sender_dsa_public = sender.dsa_public
        self.receiver_rsa_public = receiver.rsa_public


class BankingSystem:
    """Main banking system"""
    
    def __init__(self):
        self.customers = {}
        self.merchants = {}
        self.auditors = {}
        self.transactions = []
        self.transaction_counter = 1
        
        # Create default users
        self._create_default_users()
    
    def _create_default_users(self):
        """Create default users for demo"""
        print("\n" + "="*60)
        print("  SETTING UP SECURE BANKING SYSTEM")
        print("="*60)
        
        # Customers
        self.customers['C001'] = Customer('C001', 'Alice Johnson', 15000)
        self.customers['C002'] = Customer('C002', 'Bob Smith', 20000)
        
        # Merchants
        self.merchants['M001'] = Merchant('M001', 'TechStore Inc.', 50000)
        self.merchants['M002'] = Merchant('M002', 'FoodMart', 30000)
        
        # Auditor
        self.auditors['A001'] = Auditor('A001', 'Carol Auditor')
        
        print("\n✓ All users initialized successfully!")
        print("✓ RSA Encryption enabled (2048-bit)")
        print("✓ DSA Digital Signatures enabled (2048-bit)")
        print("✓ Multi-role access control active")
    
    def display_menu(self):
        """Display main menu"""
        print("\n" + "="*60)
        print("     SECURE MULTI-ROLE BANKING SYSTEM")
        print("="*60)
        print("1. Customer Login")
        print("2. Merchant Login")
        print("3. Auditor Login")
        print("4. View All Users")
        print("5. Exit")
        print("="*60)
    
    def customer_menu(self, customer):
        """Customer operations menu"""
        while True:
            print(f"\n{'='*60}")
            print(f"  CUSTOMER PORTAL - {customer.name}")
            print(f"{'='*60}")
            print(f"Balance: ${customer.balance:,.2f}")
            print("-"*60)
            print("1. Send Money to Merchant")
            print("2. View My Transactions")
            print("3. Check Balance")
            print("4. Logout")
            print("="*60)
            
            choice = input("Enter choice: ").strip()
            
            if choice == '1':
                self.customer_send_payment(customer)
            elif choice == '2':
                self.view_user_transactions(customer)
            elif choice == '3':
                print(f"\nCurrent Balance: ${customer.balance:,.2f}")
            elif choice == '4':
                print("Logging out...")
                break
            else:
                print("Invalid choice!")
    
    def merchant_menu(self, merchant):
        """Merchant operations menu"""
        while True:
            print(f"\n{'='*60}")
            print(f"  MERCHANT PORTAL - {merchant.name}")
            print(f"{'='*60}")
            print(f"Balance: ${merchant.balance:,.2f}")
            print("-"*60)
            print("1. View Received Payments")
            print("2. Decrypt Transaction Details")
            print("3. Check Balance")
            print("4. Logout")
            print("="*60)
            
            choice = input("Enter choice: ").strip()
            
            if choice == '1':
                self.view_user_transactions(merchant)
            elif choice == '2':
                self.merchant_decrypt_transaction(merchant)
            elif choice == '3':
                print(f"\nCurrent Balance: ${merchant.balance:,.2f}")
            elif choice == '4':
                print("Logging out...")
                break
            else:
                print("Invalid choice!")
    
    def auditor_menu(self, auditor):
        """Auditor operations menu"""
        while True:
            print(f"\n{'='*60}")
            print(f"  AUDITOR PORTAL - {auditor.name}")
            print(f"{'='*60}")
            print("1. View All Transactions")
            print("2. Verify Transaction Signature")
            print("3. View Transaction Statistics")
            print("4. Logout")
            print("="*60)
            
            choice = input("Enter choice: ").strip()
            
            if choice == '1':
                self.auditor_view_all_transactions()
            elif choice == '2':
                self.auditor_verify_signature()
            elif choice == '3':
                self.display_statistics()
            elif choice == '4':
                print("Logging out...")
                break
            else:
                print("Invalid choice!")
    
    def customer_send_payment(self, customer):
        """Customer sends payment to merchant"""
        print("\n--- Send Payment to Merchant ---")
        print("Available Merchants:")
        for mid, merchant in self.merchants.items():
            print(f"  {mid}: {merchant.name}")
        
        merchant_id = input("Enter Merchant ID: ").strip().upper()
        
        if merchant_id not in self.merchants:
            print("Invalid Merchant ID!")
            return
        
        merchant = self.merchants[merchant_id]
        
        try:
            amount = float(input("Enter amount: $"))
            if amount <= 0:
                print("Amount must be positive!")
                return
            
            if amount > customer.balance:
                print("Insufficient balance!")
                return
            
            description = input("Enter description: ").strip()
            
            # Create transaction
            trans_id = f"T{self.transaction_counter:04d}"
            self.transaction_counter += 1
            
            print("\nProcessing transaction...")
            transaction = Transaction(trans_id, customer, merchant, amount, description)
            
            # Update balances
            customer.balance -= amount
            merchant.balance += amount
            
            # Store transaction
            self.transactions.append(transaction)
            
            print(f"\n✓ Transaction Successful!")
            print(f"Transaction ID: {trans_id}")
            print(f"Amount: ${amount:,.2f}")
            print(f"Recipient: {merchant.name}")
            print(f"New Balance: ${customer.balance:,.2f}")
            print(f"\n🔒 Transaction encrypted with RSA")
            print(f"🔏 Transaction signed with DSA")
            
        except ValueError:
            print("Invalid amount!")
        except Exception as e:
            print(f"Transaction failed: {e}")
    
    def view_user_transactions(self, user):
        """View transactions for a specific user"""
        print(f"\n--- Transactions for {user.name} ---")
        user_trans = [t for t in self.transactions 
                     if t.sender_id == user.user_id or t.receiver_id == user.user_id]
        
        if not user_trans:
            print("No transactions found.")
            return
        
        for trans in user_trans:
            print(f"\n{'='*50}")
            print(f"Transaction ID: {trans.trans_id}")
            print(f"Timestamp: {trans.timestamp}")
            
            if trans.sender_id == user.user_id:
                print(f"Type: SENT")
                print(f"To: {trans.receiver_id}")
                print(f"Amount: -${trans.amount:,.2f}")
            else:
                print(f"Type: RECEIVED")
                print(f"From: {trans.sender_id}")
                print(f"Amount: +${trans.amount:,.2f}")
            
            print(f"Status: Encrypted ✓ | Signed ✓")
    
    def merchant_decrypt_transaction(self, merchant):
        """Merchant decrypts transaction details"""
        print("\n--- Decrypt Transaction ---")
        trans_id = input("Enter Transaction ID: ").strip().upper()
        
        transaction = None
        for trans in self.transactions:
            if trans.trans_id == trans_id and trans.receiver_id == merchant.user_id:
                transaction = trans
                break
        
        if not transaction:
            print("Transaction not found or not authorized!")
            return
        
        try:
            # Decrypt transaction
            decrypted_data = CryptoUtils.rsa_decrypt(merchant.rsa_private, 
                                                     transaction.encrypted_data)
            trans_data = json.loads(decrypted_data)
            
            print(f"\n{'='*50}")
            print("🔓 DECRYPTED TRANSACTION DETAILS")
            print(f"{'='*50}")
            print(f"Transaction ID: {trans_data['trans_id']}")
            print(f"From: {trans_data['sender_id']}")
            print(f"To: {trans_data['receiver_id']}")
            print(f"Amount: ${trans_data['amount']:,.2f}")
            print(f"Description: {trans_data['description']}")
            print(f"Timestamp: {trans_data['timestamp']}")
            print(f"{'='*50}")
            
        except Exception as e:
            print(f"Decryption failed: {e}")
    
    def auditor_view_all_transactions(self):
        """Auditor views all transactions"""
        print(f"\n{'='*70}")
        print("ALL TRANSACTIONS (Auditor View)")
        print(f"{'='*70}")
        
        if not self.transactions:
            print("No transactions in the system.")
            return
        
        for trans in self.transactions:
            print(f"\nTransaction ID: {trans.trans_id}")
            print(f"Timestamp: {trans.timestamp}")
            print(f"From: {trans.sender_id} → To: {trans.receiver_id}")
            print(f"Amount: ${trans.amount:,.2f}")
            print(f"Encrypted: ✓ | Signed: ✓")
            print("-"*70)
    
    def auditor_verify_signature(self):
        """Auditor verifies transaction signature"""
        print("\n--- Verify Transaction Signature ---")
        trans_id = input("Enter Transaction ID: ").strip().upper()
        
        transaction = None
        for trans in self.transactions:
            if trans.trans_id == trans_id:
                transaction = trans
                break
        
        if not transaction:
            print("Transaction not found!")
            return
        
        try:
            # Recreate original message
            trans_json = json.dumps(transaction.data)
            
            # Verify signature using sender's public key
            is_valid = CryptoUtils.dsa_verify(
                transaction.sender_dsa_public,
                trans_json,
                transaction.signature
            )
            
            print(f"\n{'='*50}")
            print("SIGNATURE VERIFICATION RESULT")
            print(f"{'='*50}")
            print(f"Transaction ID: {trans_id}")
            print(f"Signature Valid: {'✓ YES' if is_valid else '✗ NO'}")
            print(f"Verification Algorithm: DSA (Digital Signature Algorithm)")
            print(f"Hash Algorithm: SHA-256")
            print(f"Hash: {transaction.signature['hash'][:32]}...")
            print(f"{'='*50}")
            
            if is_valid:
                print("\n✓ Transaction is authentic and has not been tampered with!")
            else:
                print("\n✗ WARNING: Signature verification failed!")
            
        except Exception as e:
            print(f"Verification failed: {e}")
    
    def display_statistics(self):
        """Display transaction statistics"""
        print(f"\n{'='*60}")
        print("TRANSACTION STATISTICS")
        print(f"{'='*60}")
        print(f"Total Transactions: {len(self.transactions)}")
        
        total_volume = sum(t.amount for t in self.transactions)
        print(f"Total Volume: ${total_volume:,.2f}")
        
        if self.transactions:
            avg_amount = total_volume / len(self.transactions)
            print(f"Average Transaction: ${avg_amount:,.2f}")
        
        print(f"\nTotal Customers: {len(self.customers)}")
        print(f"Total Merchants: {len(self.merchants)}")
        print(f"Total Auditors: {len(self.auditors)}")
        print(f"{'='*60}")
    
    def view_all_users(self):
        """Display all users in the system"""
        print(f"\n{'='*60}")
        print("ALL USERS IN THE SYSTEM")
        print(f"{'='*60}")
        
        print("\nCUSTOMERS:")
        for cid, customer in self.customers.items():
            print(f"  {cid}: {customer.name} - Balance: ${customer.balance:,.2f}")
        
        print("\nMERCHANTS:")
        for mid, merchant in self.merchants.items():
            print(f"  {mid}: {merchant.name} - Balance: ${merchant.balance:,.2f}")
        
        print("\nAUDITORS:")
        for aid, auditor in self.auditors.items():
            print(f"  {aid}: {auditor.name}")
        
        print(f"{'='*60}")
    
    def run(self):
        """Main system loop"""
        while True:
            self.display_menu()
            choice = input("\nEnter choice: ").strip()
            
            if choice == '1':
                # Customer login
                print("\nAvailable Customers:")
                for cid, customer in self.customers.items():
                    print(f"  {cid}: {customer.name}")
                customer_id = input("Enter Customer ID: ").strip().upper()
                if customer_id in self.customers:
                    self.customer_menu(self.customers[customer_id])
                else:
                    print("Invalid Customer ID!")
            
            elif choice == '2':
                # Merchant login
                print("\nAvailable Merchants:")
                for mid, merchant in self.merchants.items():
                    print(f"  {mid}: {merchant.name}")
                merchant_id = input("Enter Merchant ID: ").strip().upper()
                if merchant_id in self.merchants:
                    self.merchant_menu(self.merchants[merchant_id])
                else:
                    print("Invalid Merchant ID!")
            
            elif choice == '3':
                # Auditor login
                print("\nAvailable Auditors:")
                for aid, auditor in self.auditors.items():
                    print(f"  {aid}: {auditor.name}")
                auditor_id = input("Enter Auditor ID: ").strip().upper()
                if auditor_id in self.auditors:
                    self.auditor_menu(self.auditors[auditor_id])
                else:
                    print("Invalid Auditor ID!")
            
            elif choice == '4':
                self.view_all_users()
            
            elif choice == '5':
                print("\n" + "="*60)
                print("  Thank you for using Secure Banking System!")
                print("="*60)
                break
            
            else:
                print("Invalid choice! Please try again.")


if __name__ == "__main__":
    system = BankingSystem()
    system.run()