"""
Hybrid Key Management and Access Control System
Implements Diffie-Hellman, RSA encryption, and MAC for secure key exchange
and message authentication.

Required libraries:
pip install pycryptodome
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
import hashlib
import secrets
import os
import json


class User:
    """Represents a user with RSA keys and DH parameters"""
    
    def __init__(self, name):
        self.name = name
        # Generate RSA key pair (2048 bits)
        self.rsa_key = RSA.generate(2048)
        self.rsa_public_key = self.rsa_key.publickey()
        
        # Diffie-Hellman parameters
        self.dh_private_key = None
        self.dh_public_key = None
        self.dh_shared_secret = None
        
        # Session key
        self.session_key = None
        
        print(f"✓ Created user '{name}' with RSA keypair")
    
    def generate_dh_keys(self, p, g):
        """Generate Diffie-Hellman key pair"""
        self.dh_private_key = secrets.randbelow(p - 2) + 1
        self.dh_public_key = pow(g, self.dh_private_key, p)
        print(f"✓ {self.name} generated DH public key: {self.dh_public_key}")
        return self.dh_public_key
    
    def compute_dh_shared_secret(self, other_public_key, p):
        """Compute shared secret using other party's public key"""
        self.dh_shared_secret = pow(other_public_key, self.dh_private_key, p)
        print(f"✓ {self.name} computed shared secret: {self.dh_shared_secret}")
        return self.dh_shared_secret
    
    def encrypt_with_rsa(self, data, recipient_public_key):
        """Encrypt data using recipient's RSA public key"""
        cipher = PKCS1_OAEP.new(recipient_public_key)
        encrypted = cipher.encrypt(data)
        return encrypted
    
    def decrypt_with_rsa(self, encrypted_data):
        """Decrypt data using own RSA private key"""
        cipher = PKCS1_OAEP.new(self.rsa_key)
        decrypted = cipher.decrypt(encrypted_data)
        return decrypted


class HybridKeyManagementSystem:
    """Hybrid Key Management and Access Control System"""
    
    def __init__(self):
        # Diffie-Hellman parameters (using safe prime)
        self.dh_prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        self.dh_generator = 2
        
        # Users
        self.users = {}
        self.messages = []
        
        print("✓ Hybrid Key Management System initialized")
        print(f"  DH Prime (p): {hex(self.dh_prime)[:50]}...")
        print(f"  DH Generator (g): {self.dh_generator}")
    
    def create_user(self, name):
        """Create a new user"""
        if name in self.users:
            print(f"\n⚠ User '{name}' already exists!")
            return None
        
        user = User(name)
        self.users[name] = user
        return user
    
    def view_users(self):
        """View all users"""
        if not self.users:
            print("\n⚠ No users in the system!")
            return
        
        print("\n" + "="*70)
        print("REGISTERED USERS")
        print("="*70)
        for name, user in self.users.items():
            print(f"\n👤 {name}")
            print(f"  RSA Public Key (n): {user.rsa_public_key.n}")
            print(f"  RSA Public Key (e): {user.rsa_public_key.e}")
            if user.dh_public_key:
                print(f"  DH Public Key: {user.dh_public_key}")
            if user.dh_shared_secret:
                print(f"  DH Shared Secret: {user.dh_shared_secret}")
            print("-"*70)
    
    def perform_diffie_hellman(self, user1_name, user2_name):
        """Perform Diffie-Hellman key exchange between two users"""
        if user1_name not in self.users or user2_name not in self.users:
            print("\n⚠ One or both users not found!")
            return
        
        user1 = self.users[user1_name]
        user2 = self.users[user2_name]
        
        print("\n" + "="*70)
        print(f"DIFFIE-HELLMAN KEY EXCHANGE: {user1_name} ↔ {user2_name}")
        print("="*70)
        
        # Step 1: Both users generate their key pairs
        print("\n🔑 Step 1: Generate DH key pairs")
        pub1 = user1.generate_dh_keys(self.dh_prime, self.dh_generator)
        pub2 = user2.generate_dh_keys(self.dh_prime, self.dh_generator)
        
        # Step 2: Exchange public keys and compute shared secret
        print("\n🔄 Step 2: Exchange public keys and compute shared secret")
        secret1 = user1.compute_dh_shared_secret(pub2, self.dh_prime)
        secret2 = user2.compute_dh_shared_secret(pub1, self.dh_prime)
        
        # Verify both computed the same secret
        if secret1 == secret2:
            print(f"\n✓ SUCCESS! Both users computed the same shared secret")
            print(f"  Shared Secret: {secret1}")
            
            # Derive session key from shared secret
            session_key = hashlib.sha256(str(secret1).encode()).digest()
            user1.session_key = session_key
            user2.session_key = session_key
            print(f"  Session Key (SHA-256 of shared secret): {session_key.hex()}")
        else:
            print(f"\n✗ ERROR! Shared secrets don't match!")
    
    def exchange_session_key_rsa(self, sender_name, receiver_name):
        """Exchange session key using RSA encryption"""
        if sender_name not in self.users or receiver_name not in self.users:
            print("\n⚠ One or both users not found!")
            return
        
        sender = self.users[sender_name]
        receiver = self.users[receiver_name]
        
        print("\n" + "="*70)
        print(f"RSA SESSION KEY EXCHANGE: {sender_name} → {receiver_name}")
        print("="*70)
        
        # Generate a random session key
        session_key = get_random_bytes(32)  # 256-bit key
        print(f"\n🔑 Generated session key: {session_key.hex()}")
        
        # Encrypt session key with receiver's RSA public key
        print(f"\n🔒 Encrypting with {receiver_name}'s RSA public key...")
        encrypted_key = sender.encrypt_with_rsa(session_key, receiver.rsa_public_key)
        print(f"  Encrypted key (first 64 bytes): {encrypted_key[:64].hex()}...")
        
        # Receiver decrypts the session key
        print(f"\n🔓 {receiver_name} decrypting with private RSA key...")
        decrypted_key = receiver.decrypt_with_rsa(encrypted_key)
        
        # Verify
        if session_key == decrypted_key:
            print(f"✓ SUCCESS! Session key securely exchanged")
            print(f"  Decrypted key: {decrypted_key.hex()}")
            
            sender.session_key = session_key
            receiver.session_key = decrypted_key
        else:
            print(f"✗ ERROR! Decryption failed!")
    
    def generate_mac(self, sender_name, message):
        """Generate MAC for a message"""
        if sender_name not in self.users:
            print("\n⚠ User not found!")
            return None
        
        sender = self.users[sender_name]
        
        if not sender.session_key:
            print(f"\n⚠ {sender_name} doesn't have a session key! Perform key exchange first.")
            return None
        
        print("\n" + "="*70)
        print(f"GENERATING MAC: {sender_name}")
        print("="*70)
        
        print(f"\n📝 Message: {message}")
        print(f"🔑 Session Key: {sender.session_key.hex()}")
        
        # Generate HMAC using session key
        hmac = HMAC.new(sender.session_key, digestmod=SHA256)
        hmac.update(message.encode('utf-8'))
        mac = hmac.hexdigest()
        
        print(f"\n✓ Generated MAC (HMAC-SHA256): {mac}")
        
        # Store message with MAC
        message_data = {
            'sender': sender_name,
            'message': message,
            'mac': mac,
            'timestamp': len(self.messages) + 1
        }
        self.messages.append(message_data)
        
        return mac
    
    def verify_mac(self, message_id, receiver_name):
        """Verify MAC of a message"""
        if receiver_name not in self.users:
            print("\n⚠ User not found!")
            return False
        
        if message_id < 1 or message_id > len(self.messages):
            print("\n⚠ Invalid message ID!")
            return False
        
        receiver = self.users[receiver_name]
        message_data = self.messages[message_id - 1]
        
        if not receiver.session_key:
            print(f"\n⚠ {receiver_name} doesn't have a session key!")
            return False
        
        print("\n" + "="*70)
        print(f"VERIFYING MAC: Message #{message_id}")
        print("="*70)
        
        print(f"\n👤 Sender: {message_data['sender']}")
        print(f"📝 Message: {message_data['message']}")
        print(f"🔐 Original MAC: {message_data['mac']}")
        
        # Recompute MAC
        hmac = HMAC.new(receiver.session_key, digestmod=SHA256)
        hmac.update(message_data['message'].encode('utf-8'))
        computed_mac = hmac.hexdigest()
        
        print(f"🔍 Computed MAC: {computed_mac}")
        
        # Verify
        is_valid = computed_mac == message_data['mac']
        
        if is_valid:
            print(f"\n✓ MAC VERIFIED! Message is authentic and unmodified")
        else:
            print(f"\n✗ MAC VERIFICATION FAILED! Message may be tampered or from wrong sender")
        
        return is_valid
    
    def view_messages(self):
        """View all messages with MACs"""
        if not self.messages:
            print("\n⚠ No messages in the system!")
            return
        
        print("\n" + "="*70)
        print("MESSAGES WITH MAC")
        print("="*70)
        for msg in self.messages:
            print(f"\nID: {msg['timestamp']}")
            print(f"Sender: {msg['sender']}")
            print(f"Message: {msg['message']}")
            print(f"MAC: {msg['mac']}")
            print("-"*70)
    
    def demonstrate_tampering(self, message_id):
        """Simulate message tampering"""
        if message_id < 1 or message_id > len(self.messages):
            print("\n⚠ Invalid message ID!")
            return
        
        print("\n" + "="*70)
        print(f"SIMULATING MESSAGE TAMPERING")
        print("="*70)
        
        original_message = self.messages[message_id - 1]['message']
        print(f"\n📝 Original message: {original_message}")
        
        self.messages[message_id - 1]['message'] = original_message + " [TAMPERED]"
        print(f"⚠ Modified message: {self.messages[message_id - 1]['message']}")
        print("\nNow try verifying the MAC to detect tampering!")


def clear_screen():
    """Clear the console screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_menu():
    """Display the main menu"""
    print("\n" + "="*70)
    print(" 🔐 HYBRID KEY MANAGEMENT & ACCESS CONTROL SYSTEM 🔑")
    print(" Diffie-Hellman + RSA + MAC")
    print("="*70)
    print("\n📋 MAIN MENU:")
    print("\n  User Management:")
    print("    1. Create User")
    print("    2. View All Users")
    print("\n  Key Exchange:")
    print("    3. Perform Diffie-Hellman Key Exchange")
    print("    4. Exchange Session Key (RSA)")
    print("\n  Message Authentication:")
    print("    5. Generate MAC for Message")
    print("    6. Verify MAC")
    print("    7. View All Messages")
    print("\n  Security Testing:")
    print("    8. Simulate Message Tampering (Demo)")
    print("\n  System:")
    print("    9. Clear Screen")
    print("    0. Exit")
    print("\n" + "="*70)


def main():
    """Main menu-based application"""
    system = HybridKeyManagementSystem()
    
    clear_screen()
    print("\n🎉 Welcome to Hybrid Key Management System!")
    print("This system demonstrates secure key exchange and message authentication.")
    
    while True:
        print_menu()
        
        choice = input("\n👉 Enter your choice (0-9): ").strip()
        
        if choice == '1':
            # Create User
            name = input("\n📝 Enter user name: ").strip()
            if name:
                system.create_user(name)
            else:
                print("\n⚠ Name cannot be empty!")
        
        elif choice == '2':
            # View All Users
            system.view_users()
        
        elif choice == '3':
            # Diffie-Hellman Key Exchange
            print("\n🔄 Diffie-Hellman Key Exchange")
            user1 = input("  Enter first user name: ").strip()
            user2 = input("  Enter second user name: ").strip()
            system.perform_diffie_hellman(user1, user2)
        
        elif choice == '4':
            # RSA Session Key Exchange
            print("\n🔐 RSA Session Key Exchange")
            sender = input("  Enter sender name: ").strip()
            receiver = input("  Enter receiver name: ").strip()
            system.exchange_session_key_rsa(sender, receiver)
        
        elif choice == '5':
            # Generate MAC
            sender = input("\n📝 Enter sender name: ").strip()
            message = input("  Enter message: ").strip()
            if sender and message:
                system.generate_mac(sender, message)
            else:
                print("\n⚠ Sender and message cannot be empty!")
        
        elif choice == '6':
            # Verify MAC
            if not system.messages:
                print("\n⚠ No messages available!")
            else:
                system.view_messages()
                try:
                    msg_id = int(input("\n  Enter message ID to verify: "))
                    receiver = input("  Enter receiver name: ").strip()
                    system.verify_mac(msg_id, receiver)
                except ValueError:
                    print("\n⚠ Invalid message ID!")
        
        elif choice == '7':
            # View All Messages
            system.view_messages()
        
        elif choice == '8':
            # Simulate Tampering
            if not system.messages:
                print("\n⚠ No messages available!")
            else:
                system.view_messages()
                try:
                    msg_id = int(input("\n  Enter message ID to tamper: "))
                    system.demonstrate_tampering(msg_id)
                except ValueError:
                    print("\n⚠ Invalid message ID!")
        
        elif choice == '9':
            # Clear Screen
            clear_screen()
            continue
        
        elif choice == '0':
            # Exit
            print("\n👋 Thank you for using Hybrid Key Management System!")
            print("Stay secure! 🔐\n")
            break
        
        else:
            print("\n⚠ Invalid choice! Please enter a number between 0 and 9.")
        
        input("\n⏎ Press Enter to continue...")


if __name__ == "__main__":
    main()