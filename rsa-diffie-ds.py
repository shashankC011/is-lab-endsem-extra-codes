'''RSA + Diffie-Hellman + Digital Signature

Question:
Create a secure communication system between two users (Alice and Bob).

Use Diffie-Hellman to generate a shared session key.

Encrypt all exchanged messages using RSA with that session key.

Each user should digitally sign the message before sending.

The receiver must verify the signature and decrypt the message.

Include menu options for:

Generate keys and establish session

Send signed encrypted message

Receive and verify message

Topics tested: key exchange, encryption, authentication.'''
import random
import hashlib
from Crypto.Util.number import getPrime, inverse, getRandomRange
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import json

class RSADiffieHellmanSystem:
    def __init__(self):
        self.users = {}
        self.session_keys = {}
        
    def generate_rsa_keys(self, user, key_size=1024):
        """Generate RSA public and private keys for a user"""
        # Generate two large prime numbers
        p = getPrime(key_size // 2)
        q = getPrime(key_size // 2)
        
        # Calculate modulus
        n = p * q
        
        # Calculate Euler's totient function
        phi = (p - 1) * (q - 1)
        
        # Choose public exponent (commonly 65537)
        e = 65537
        
        # Calculate private exponent
        d = inverse(e, phi)
        
        self.users[user] = {
            'public_key': {'e': e, 'n': n},
            'private_key': {'d': d, 'n': n},
            'p': p, 'q': q
        }
        
        print(f"RSA keys generated for {user}")
        print(f"Public Key (e, n): ({e}, {n})")
        return {'e': e, 'n': n}, {'d': d, 'n': n}
    
    def diffie_hellman_key_exchange(self, user1, user2):
        """Perform Diffie-Hellman key exchange between two users"""
        # Common parameters (public)
        p = getPrime(512)  # Large prime
        g = 2  # Generator
        
        # Each user generates their private key
        a_private = random.randint(2, p-2)  # Alice's private key
        b_private = random.randint(2, p-2)  # Bob's private key
        
        # Each user computes their public key
        a_public = pow(g, a_private, p)
        b_public = pow(g, b_private, p)
        
        # Exchange public keys and compute shared secret
        a_shared = pow(b_public, a_private, p)
        b_shared = pow(a_public, b_private, p)
        
        # Verify both computed the same shared secret
        assert a_shared == b_shared, "Shared secret mismatch!"
        
        # Convert shared secret to session key (using hash)
        session_key = hashlib.sha256(str(a_shared).encode()).digest()[:16]  # 16 bytes for AES
        
        self.session_keys[user1] = session_key
        self.session_keys[user2] = session_key
        
        print(f"Diffie-Hellman key exchange completed between {user1} and {user2}")
        print(f"Shared session key established")
        return session_key
    
    def rsa_encrypt(self, message, public_key):
        """Encrypt message using RSA public key"""
        e, n = public_key['e'], public_key['n']
        
        # Convert message to integer
        message_int = int.from_bytes(message.encode('utf-8'), 'big')
        
        # Encrypt: c = m^e mod n
        if message_int >= n:
            raise ValueError("Message too large for RSA encryption")
        
        cipher_int = pow(message_int, e, n)
        
        # Convert back to bytes
        cipher_bytes = cipher_int.to_bytes((cipher_int.bit_length() + 7) // 8, 'big')
        
        return base64.b64encode(cipher_bytes).decode()
    
    def rsa_decrypt(self, cipher_text, private_key):
        """Decrypt message using RSA private key"""
        d, n = private_key['d'], private_key['n']
        
        # Decode from base64
        cipher_bytes = base64.b64decode(cipher_text)
        
        # Convert to integer
        cipher_int = int.from_bytes(cipher_bytes, 'big')
        
        # Decrypt: m = c^d mod n
        message_int = pow(cipher_int, d, n)
        
        # Convert back to string
        message = message_int.to_bytes((message_int.bit_length() + 7) // 8, 'big').decode('utf-8')
        
        return message
    
    def aes_encrypt(self, message, key):
        """Encrypt message using AES with session key"""
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
        iv = cipher.iv
        return base64.b64encode(iv + ct_bytes).decode('utf-8')
    
    def aes_decrypt(self, cipher_text, key):
        """Decrypt message using AES with session key"""
        cipher_text = base64.b64decode(cipher_text)
        iv = cipher_text[:16]
        ct = cipher_text[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    
    def sign_message(self, message, private_key):
        """Create digital signature using RSA private key"""
        # Hash the message
        message_hash = hashlib.sha256(message.encode()).digest()
        
        # Convert hash to integer
        hash_int = int.from_bytes(message_hash, 'big')
        
        # Sign: signature = hash^d mod n
        d, n = private_key['d'], private_key['n']
        
        if hash_int >= n:
            hash_int = hash_int % n
        
        signature_int = pow(hash_int, d, n)
        
        # Convert signature to bytes
        signature_bytes = signature_int.to_bytes((signature_int.bit_length() + 7) // 8, 'big')
        
        return base64.b64encode(signature_bytes).decode()
    
    def verify_signature(self, message, signature, public_key):
        """Verify digital signature using RSA public key"""
        # Hash the message
        message_hash = hashlib.sha256(message.encode()).digest()
        
        # Convert hash to integer
        original_hash_int = int.from_bytes(message_hash, 'big')
        
        # Decode signature
        signature_bytes = base64.b64decode(signature)
        signature_int = int.from_bytes(signature_bytes, 'big')
        
        # Verify: hash = signature^e mod n
        e, n = public_key['e'], public_key['n']
        
        recovered_hash_int = pow(signature_int, e, n)
        
        # Compare hashes
        return original_hash_int == recovered_hash_int
    
    def send_signed_encrypted_message(self, sender, receiver, message):
        """Send a message with digital signature and encryption"""
        if sender not in self.users or receiver not in self.users:
            print("Error: Users not registered!")
            return None
        
        if sender not in self.session_keys:
            print("Error: No session key established!")
            return None
        
        # Step 1: Create digital signature
        signature = self.sign_message(message, self.users[sender]['private_key'])
        
        # Step 2: Combine message and signature
        message_data = {
            'message': message,
            'signature': signature,
            'sender': sender
        }
        
        # Step 3: Encrypt the combined data with session key
        encrypted_data = self.aes_encrypt(json.dumps(message_data), self.session_keys[sender])
        
        print(f"Message sent from {sender} to {receiver}")
        print(f"Original message: {message}")
        print(f"Digital signature created")
        print(f"Message encrypted with session key")
        
        return encrypted_data
    
    def receive_verify_decrypt_message(self, receiver, encrypted_data):
        """Receive, verify signature and decrypt message"""
        if receiver not in self.users:
            print("Error: User not registered!")
            return None
        
        if receiver not in self.session_keys:
            print("Error: No session key established!")
            return None
        
        try:
            # Step 1: Decrypt with session key
            decrypted_data = self.aes_decrypt(encrypted_data, self.session_keys[receiver])
            message_data = json.loads(decrypted_data)
            
            message = message_data['message']
            signature = message_data['signature']
            sender = message_data['sender']
            
            # Step 2: Verify digital signature
            sender_public_key = self.users[sender]['public_key']
            is_valid = self.verify_signature(message, signature, sender_public_key)
            
            if is_valid:
                print(f"✓ Message received from {sender}")
                print(f"✓ Digital signature verified successfully")
                print(f"✓ Message decrypted with session key")
                print(f"Message content: {message}")
                return message
            else:
                print("✗ Digital signature verification failed!")
                print("✗ Message may have been tampered with!")
                return None
                
        except Exception as e:
            print(f"Error processing message: {e}")
            return None

def main():
    system = RSADiffieHellmanSystem()
    
    while True:
        print("\n" + "="*50)
        print("    SECURE COMMUNICATION SYSTEM")
        print("="*50)
        print("1. Generate RSA Keys for Users")
        print("2. Establish Secure Session (Diffie-Hellman)")
        print("3. Send Signed Encrypted Message")
        print("4. Receive and Verify Message")
        print("5. Display User Information")
        print("6. Exit")
        print("="*50)
        
        choice = input("Enter your choice (1-6): ")
        
        if choice == '1':
            print("\n--- Generate RSA Keys ---")
            user = input("Enter username: ")
            system.generate_rsa_keys(user)
            
        elif choice == '2':
            print("\n--- Establish Secure Session ---")
            user1 = input("Enter first username: ")
            user2 = input("Enter second username: ")
            
            if user1 in system.users and user2 in system.users:
                system.diffie_hellman_key_exchange(user1, user2)
            else:
                print("Error: One or both users not registered!")
                
        elif choice == '3':
            print("\n--- Send Signed Encrypted Message ---")
            sender = input("Enter sender username: ")
            receiver = input("Enter receiver username: ")
            message = input("Enter message to send: ")
            
            if sender in system.users and receiver in system.users:
                encrypted_message = system.send_signed_encrypted_message(sender, receiver, message)
                if encrypted_message:
                    print(f"\nEncrypted message ready for transmission:")
                    print(f"Length: {len(encrypted_message)} characters")
            else:
                print("Error: One or both users not registered!")
                
        elif choice == '4':
            print("\n--- Receive and Verify Message ---")
            receiver = input("Enter receiver username: ")
            
            if receiver in system.users:
                encrypted_message = input("Enter the encrypted message: ")
                system.receive_verify_decrypt_message(receiver, encrypted_message)
            else:
                print("Error: User not registered!")
                
        elif choice == '5':
            print("\n--- User Information ---")
            for user, data in system.users.items():
                print(f"\nUser: {user}")
                print(f"Public Key (n): {data['public_key']['n']}")
                print(f"Has Session Key: {user in system.session_keys}")
                
        elif choice == '6':
            print("Exiting Secure Communication System. Goodbye!")
            break
            
        else:
            print("Invalid choice! Please try again.")

if __name__ == "__main__":
    main()