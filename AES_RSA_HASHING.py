'''Secure Messaging with Hybrid Cryptography (AES + RSA + Hashing)

Implement a secure messaging system where:

The message is encrypted using AES (CBC mode).

The AES key itself is encrypted using RSA public key.

A SHA-256 hash is generated to ensure message integrity at the receiver’s end.'''
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import base64
import json
from datetime import datetime
import os

class CryptoEngine:
    """Handles all cryptographic operations"""
    
    @staticmethod
    def generate_rsa_keypair(bits=2048):
        """Generate RSA key pair quickly"""
        key = RSA.generate(bits)
        return key, key.publickey()
    
    @staticmethod
    def generate_aes_key():
        """Generate random AES-256 key"""
        return get_random_bytes(32)  # 256 bits
    
    @staticmethod
    def encrypt_message_aes(message, aes_key):
        """Encrypt message using AES-256 in CBC mode"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Generate random IV
        iv = get_random_bytes(16)
        
        # Create AES cipher
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        
        # Pad and encrypt
        padded_message = pad(message, AES.block_size)
        ciphertext = cipher.encrypt(padded_message)
        
        return iv, ciphertext
    
    @staticmethod
    def decrypt_message_aes(iv, ciphertext, aes_key):
        """Decrypt message using AES-256"""
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_message = cipher.decrypt(ciphertext)
        message = unpad(padded_message, AES.block_size)
        return message.decode('utf-8')
    
    @staticmethod
    def encrypt_key_rsa(aes_key, rsa_public_key):
        """Encrypt AES key using RSA public key"""
        cipher = PKCS1_OAEP.new(rsa_public_key)
        encrypted_key = cipher.encrypt(aes_key)
        return encrypted_key
    
    @staticmethod
    def decrypt_key_rsa(encrypted_key, rsa_private_key):
        """Decrypt AES key using RSA private key"""
        cipher = PKCS1_OAEP.new(rsa_private_key)
        aes_key = cipher.decrypt(encrypted_key)
        return aes_key
    
    @staticmethod
    def compute_hash(data):
        """Compute SHA-256 hash of data"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        hash_obj = SHA256.new(data)
        return hash_obj.hexdigest()
    
    @staticmethod
    def verify_hash(data, expected_hash):
        """Verify data integrity using hash"""
        computed_hash = CryptoEngine.compute_hash(data)
        return computed_hash == expected_hash


class SecureMessage:
    """Represents a secure encrypted message"""
    
    def __init__(self, sender, receiver, plaintext):
        self.sender = sender
        self.receiver = receiver
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.plaintext = plaintext
        
        # Step 1: Generate random AES key
        self.aes_key = CryptoEngine.generate_aes_key()
        
        # Step 2: Encrypt message with AES
        self.iv, self.ciphertext = CryptoEngine.encrypt_message_aes(
            plaintext, self.aes_key
        )
        
        # Step 3: Encrypt AES key with receiver's RSA public key
        self.encrypted_aes_key = CryptoEngine.encrypt_key_rsa(
            self.aes_key, receiver.rsa_public
        )
        
        # Step 4: Compute SHA-256 hash for integrity
        self.message_hash = CryptoEngine.compute_hash(plaintext)
        
        # For transmission (base64 encoding for display)
        self.encrypted_data = {
            'iv': base64.b64encode(self.iv).decode(),
            'ciphertext': base64.b64encode(self.ciphertext).decode(),
            'encrypted_key': base64.b64encode(self.encrypted_aes_key).decode(),
            'hash': self.message_hash,
            'sender': sender.name,
            'receiver': receiver.name,
            'timestamp': self.timestamp
        }
    
    def decrypt(self, receiver):
        """Decrypt message using receiver's private key"""
        # Step 1: Decrypt AES key using RSA private key
        aes_key = CryptoEngine.decrypt_key_rsa(
            self.encrypted_aes_key, receiver.rsa_private
        )
        
        # Step 2: Decrypt message using AES key
        decrypted_message = CryptoEngine.decrypt_message_aes(
            self.iv, self.ciphertext, aes_key
        )
        
        # Step 3: Verify hash for integrity
        is_valid = CryptoEngine.verify_hash(decrypted_message, self.message_hash)
        
        return decrypted_message, is_valid


class User:
    """User with RSA key pair"""
    
    def __init__(self, name):
        self.name = name
        # Generate RSA key pair (fast generation)
        self.rsa_private, self.rsa_public = CryptoEngine.generate_rsa_keypair(1024)
        self.inbox = []
        self.sent_messages = []
    
    def send_message(self, receiver, message_text):
        """Send encrypted message to another user"""
        secure_msg = SecureMessage(self, receiver, message_text)
        receiver.inbox.append(secure_msg)
        self.sent_messages.append(secure_msg)
        return secure_msg
    
    def read_message(self, message):
        """Read and decrypt a received message"""
        decrypted_text, is_valid = message.decrypt(self)
        return decrypted_text, is_valid


class MessagingSystem:
    """Main messaging system"""
    
    def __init__(self):
        self.users = {}
        self.current_user = None
        self._initialize_demo_users()
    
    def _initialize_demo_users(self):
        """Create demo users"""
        print("\n" + "="*70)
        print("  INITIALIZING SECURE MESSAGING SYSTEM")
        print("="*70)
        print("\nGenerating RSA key pairs for users...")
        
        self.users['alice'] = User("Alice")
        print("  ✓ Alice initialized")
        
        self.users['bob'] = User("Bob")
        print("  ✓ Bob initialized")
        
        self.users['charlie'] = User("Charlie")
        print("  ✓ Charlie initialized")
        
        print("\n✓ System ready!")
        print("✓ Hybrid Encryption: AES-256 (CBC) + RSA-1024")
        print("✓ Integrity Check: SHA-256")
    
    def display_main_menu(self):
        """Display main menu"""
        print("\n" + "="*70)
        print("     SECURE MESSAGING SYSTEM - HYBRID CRYPTOGRAPHY")
        print("="*70)
        print("1. Login")
        print("2. View All Users")
        print("3. Send Demo Message")
        print("4. How It Works")
        print("5. Exit")
        print("="*70)
    
    def display_user_menu(self):
        """Display user menu"""
        print(f"\n{'='*70}")
        print(f"  LOGGED IN AS: {self.current_user.name}")
        print(f"{'='*70}")
        print(f"Inbox: {len(self.current_user.inbox)} messages")
        print(f"Sent: {len(self.current_user.sent_messages)} messages")
        print("-"*70)
        print("1. Send Message")
        print("2. View Inbox")
        print("3. View Sent Messages")
        print("4. View Encryption Details")
        print("5. Logout")
        print("="*70)
    
    def login(self):
        """User login"""
        print("\n--- User Login ---")
        print("Available users:")
        for username in self.users.keys():
            print(f"  • {username}")
        
        username = input("\nEnter username: ").strip().lower()
        
        if username in self.users:
            self.current_user = self.users[username]
            print(f"✓ Logged in as {self.current_user.name}")
            return True
        else:
            print("✗ User not found!")
            return False
    
    def send_message(self):
        """Send encrypted message"""
        print("\n--- Send Secure Message ---")
        print("Available recipients:")
        for username, user in self.users.items():
            if user != self.current_user:
                print(f"  • {username} ({user.name})")
        
        recipient_name = input("\nEnter recipient username: ").strip().lower()
        
        if recipient_name not in self.users:
            print("✗ Recipient not found!")
            return
        
        if recipient_name == self.current_user.name.lower():
            print("✗ Cannot send message to yourself!")
            return
        
        receiver = self.users[recipient_name]
        
        print("\nEnter your message (press Enter when done):")
        message_text = input("> ").strip()
        
        if not message_text:
            print("✗ Message cannot be empty!")
            return
        
        print("\n🔄 Encrypting message...")
        secure_msg = self.current_user.send_message(receiver, message_text)
        
        print("\n" + "="*70)
        print("✓ MESSAGE SENT SUCCESSFULLY!")
        print("="*70)
        print(f"To: {receiver.name}")
        print(f"Timestamp: {secure_msg.timestamp}")
        print(f"\n🔐 ENCRYPTION DETAILS:")
        print(f"  • Message encrypted with: AES-256 (CBC mode)")
        print(f"  • AES key encrypted with: RSA-1024 (receiver's public key)")
        print(f"  • Integrity hash: SHA-256")
        print(f"  • Message hash: {secure_msg.message_hash[:32]}...")
        print("="*70)
    
    def view_inbox(self):
        """View and decrypt inbox messages"""
        print("\n" + "="*70)
        print(f"  INBOX - {self.current_user.name}")
        print("="*70)
        
        if not self.current_user.inbox:
            print("No messages in inbox.")
            return
        
        for idx, msg in enumerate(self.current_user.inbox, 1):
            print(f"\n{'─'*70}")
            print(f"Message #{idx}")
            print(f"From: {msg.sender.name}")
            print(f"Timestamp: {msg.timestamp}")
            print(f"Status: 🔒 Encrypted")
            print(f"{'─'*70}")
            
            choice = input("Decrypt this message? (y/n): ").strip().lower()
            
            if choice == 'y':
                print("\n🔄 Decrypting message...")
                decrypted_text, is_valid = self.current_user.read_message(msg)
                
                print("\n" + "="*70)
                print("📧 DECRYPTED MESSAGE:")
                print("="*70)
                print(decrypted_text)
                print("="*70)
                
                print(f"\n🔍 INTEGRITY CHECK:")
                if is_valid:
                    print("  ✓ Hash verification: PASSED")
                    print("  ✓ Message has not been tampered with")
                else:
                    print("  ✗ Hash verification: FAILED")
                    print("  ✗ Warning: Message may have been tampered with!")
                
                print(f"\n📊 DECRYPTION DETAILS:")
                print(f"  • Original hash: {msg.message_hash[:32]}...")
                print(f"  • Computed hash: {CryptoEngine.compute_hash(decrypted_text)[:32]}...")
                print(f"  • AES key decrypted using RSA private key")
                print(f"  • Message decrypted using AES-256 CBC")
                print("="*70)
    
    def view_sent_messages(self):
        """View sent messages"""
        print("\n" + "="*70)
        print(f"  SENT MESSAGES - {self.current_user.name}")
        print("="*70)
        
        if not self.current_user.sent_messages:
            print("No sent messages.")
            return
        
        for idx, msg in enumerate(self.current_user.sent_messages, 1):
            print(f"\n{'─'*70}")
            print(f"Message #{idx}")
            print(f"To: {msg.receiver.name}")
            print(f"Timestamp: {msg.timestamp}")
            print(f"Original message: {msg.plaintext}")
            print(f"Message hash: {msg.message_hash[:32]}...")
            print(f"Status: ✓ Encrypted and delivered")
            print(f"{'─'*70}")
    
    def view_encryption_details(self):
        """Show encryption process details"""
        print("\n" + "="*70)
        print("  HYBRID ENCRYPTION ARCHITECTURE")
        print("="*70)
        print("""
┌─────────────────────────────────────────────────────────────────┐
│                    SENDER'S SIDE (Encryption)                    │
└─────────────────────────────────────────────────────────────────┘

1. GENERATE SYMMETRIC KEY:
   • Random AES-256 key generated (32 bytes)
   • Used for encrypting the actual message
   • Fast encryption for large messages

2. ENCRYPT MESSAGE:
   • Algorithm: AES-256 in CBC mode
   • Random IV (Initialization Vector) generated
   • Message padded and encrypted with AES key
   • Result: Ciphertext

3. ENCRYPT AES KEY:
   • AES key encrypted with receiver's RSA public key
   • Algorithm: RSA-1024 with OAEP padding
   • Only receiver's private key can decrypt this

4. GENERATE HASH:
   • SHA-256 hash computed on original message
   • Used for integrity verification
   • Detects any tampering

┌─────────────────────────────────────────────────────────────────┐
│                   RECEIVER'S SIDE (Decryption)                   │
└─────────────────────────────────────────────────────────────────┘

1. DECRYPT AES KEY:
   • Use RSA private key to decrypt AES key
   • Only receiver has the correct private key

2. DECRYPT MESSAGE:
   • Use decrypted AES key with IV
   • Decrypt ciphertext using AES-256 CBC
   • Unpad to get original message

3. VERIFY INTEGRITY:
   • Compute SHA-256 hash of decrypted message
   • Compare with received hash
   • Match = Message authentic, No tampering

┌─────────────────────────────────────────────────────────────────┐
│                      WHY HYBRID ENCRYPTION?                      │
└─────────────────────────────────────────────────────────────────┘

✓ SPEED: AES is very fast for large messages
✓ SECURITY: RSA protects the AES key
✓ SCALABILITY: Can encrypt unlimited message size
✓ KEY EXCHANGE: No need for pre-shared keys
✓ INTEGRITY: SHA-256 ensures message not tampered
        """)
        print("="*70)
    
    def send_demo_message(self):
        """Send a demo message to show the system"""
        print("\n--- Demo Message ---")
        alice = self.users['alice']
        bob = self.users['bob']
        
        demo_text = "Hello Bob! This is a secure message using hybrid cryptography."
        
        print(f"Sending demo message from Alice to Bob...")
        print(f'Message: "{demo_text}"')
        
        secure_msg = alice.send_message(bob, demo_text)
        
        print("\n✓ Message encrypted and sent!")
        print(f"\n📊 Encryption Applied:")
        print(f"  • AES-256 CBC for message content")
        print(f"  • RSA-1024 for AES key")
        print(f"  • SHA-256 for integrity")
        
        print(f"\n🔐 Encrypted Data (Base64):")
        print(f"  IV: {secure_msg.encrypted_data['iv'][:40]}...")
        print(f"  Ciphertext: {secure_msg.encrypted_data['ciphertext'][:40]}...")
        print(f"  Encrypted Key: {secure_msg.encrypted_data['encrypted_key'][:40]}...")
        print(f"  Hash: {secure_msg.message_hash}")
        
        # Now decrypt
        print(f"\n🔓 Decrypting with Bob's private key...")
        decrypted_text, is_valid = bob.read_message(secure_msg)
        
        print(f"\n✓ Decrypted Message: \"{decrypted_text}\"")
        print(f"✓ Hash Verification: {'PASSED' if is_valid else 'FAILED'}")
    
    def view_all_users(self):
        """Display all users"""
        print("\n" + "="*70)
        print("  ALL USERS")
        print("="*70)
        for username, user in self.users.items():
            print(f"\nUsername: {username}")
            print(f"Name: {user.name}")
            print(f"Inbox: {len(user.inbox)} messages")
            print(f"Sent: {len(user.sent_messages)} messages")
            print(f"RSA Key: Generated ✓")
            print("-"*70)
    
    def run(self):
        """Main system loop"""
        while True:
            if self.current_user is None:
                self.display_main_menu()
                choice = input("\nEnter choice: ").strip()
                
                if choice == '1':
                    self.login()
                elif choice == '2':
                    self.view_all_users()
                elif choice == '3':
                    self.send_demo_message()
                elif choice == '4':
                    self.view_encryption_details()
                elif choice == '5':
                    print("\n" + "="*70)
                    print("  Thank you for using Secure Messaging System!")
                    print("="*70)
                    break
                else:
                    print("✗ Invalid choice!")
            
            else:
                self.display_user_menu()
                choice = input("\nEnter choice: ").strip()
                
                if choice == '1':
                    self.send_message()
                elif choice == '2':
                    self.view_inbox()
                elif choice == '3':
                    self.view_sent_messages()
                elif choice == '4':
                    self.view_encryption_details()
                elif choice == '5':
                    print(f"✓ Logged out from {self.current_user.name}")
                    self.current_user = None
                else:
                    print("✗ Invalid choice!")


if __name__ == "__main__":
    system = MessagingSystem()
    system.run()