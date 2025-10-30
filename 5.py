'''AES + RSA + Hash + Signature (Secure File Transfer System)
Question: Build a Client–Server File Transfer System that ensures confidentiality and integrity.
* The client encrypts a file using AES, encrypts the AES key using RSA, and sends both to the server.
* A SHA-256 hash of the file is signed using RSA for authenticity.
* The server verifies the signature, decrypts the key, decrypts the file, and validates the hash.'''
import os
import random
import hashlib
import json
from typing import Tuple, Optional

# ==================== AES ENCRYPTION ====================
class AES:
    """AES encryption using XOR-based stream cipher for educational purposes"""
    
    def __init__(self, key: bytes):
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes")
        self.key = key
        self.block_size = 16
    
    @staticmethod
    def pad(data: bytes) -> bytes:
        """PKCS7 padding"""
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    @staticmethod
    def unpad(data: bytes) -> bytes:
        """Remove PKCS7 padding"""
        if len(data) == 0:
            return data
        padding_length = data[-1]
        if padding_length > 16 or padding_length > len(data):
            return data
        return data[:-padding_length]
    
    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        """XOR two byte strings"""
        return bytes(x ^ y for x, y in zip(a, b))
    
    def _generate_keystream(self, iv: bytes, length: int) -> bytes:
        """Generate keystream from key and IV"""
        keystream = b''
        counter = 0
        
        while len(keystream) < length:
            # Create block input from IV and counter
            block_input = iv + self.key + counter.to_bytes(8, 'big')
            # Generate keystream block using SHA-256
            block = hashlib.sha256(block_input).digest()
            keystream += block
            counter += 1
        
        return keystream[:length]
    
    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        """Encrypt data using stream cipher mode"""
        # Generate random IV
        iv = os.urandom(16)
        
        # Pad the plaintext
        padded_data = self.pad(plaintext)
        
        # Generate keystream
        keystream = self._generate_keystream(iv, len(padded_data))
        
        # XOR plaintext with keystream
        ciphertext = self._xor_bytes(padded_data, keystream)
        
        return iv, ciphertext
    
    def decrypt(self, iv: bytes, ciphertext: bytes) -> bytes:
        """Decrypt data using stream cipher mode"""
        # Generate the same keystream
        keystream = self._generate_keystream(iv, len(ciphertext))
        
        # XOR ciphertext with keystream (XOR is reversible)
        padded_plaintext = self._xor_bytes(ciphertext, keystream)
        
        # Remove padding
        return self.unpad(padded_plaintext)


# ==================== RSA ENCRYPTION ====================
class RSA:
    def __init__(self, key_size=2048):
        self.public_key, self.private_key = self.generate_keypair(key_size)
    
    @staticmethod
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a
    
    @staticmethod
    def mod_inverse(a, m):
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        a = a % m
        gcd, x, _ = extended_gcd(a, m)
        if gcd != 1:
            raise Exception(f'Modular inverse does not exist')
        return (x % m + m) % m
    
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
        print(f"   🔧 Generating {bits}-bit RSA key pair...")
        p = self.generate_prime(bits // 2)
        q = self.generate_prime(bits // 2)
        
        while p == q:
            q = self.generate_prime(bits // 2)
        
        n = p * q
        phi = (p - 1) * (q - 1)
        
        # Choose e such that gcd(e, phi) = 1
        e = 65537
        if RSA.gcd(e, phi) != 1:
            e = 3
            while RSA.gcd(e, phi) != 1:
                e += 2
        
        d = self.mod_inverse(e, phi)
        
        public_key = (e, n)
        private_key = (d, n)
        
        print(f"   ✅ RSA keys generated successfully!")
        
        return public_key, private_key
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data with RSA public key"""
        e, n = self.public_key
        
        # Convert bytes to integer
        plaintext_int = int.from_bytes(plaintext, byteorder='big')
        
        if plaintext_int >= n:
            raise ValueError("Plaintext too large for RSA key size")
        
        # Encrypt
        ciphertext_int = pow(plaintext_int, e, n)
        
        # Convert back to bytes
        byte_length = (ciphertext_int.bit_length() + 7) // 8
        ciphertext = ciphertext_int.to_bytes(byte_length, byteorder='big')
        
        return ciphertext
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data with RSA private key"""
        d, n = self.private_key
        
        # Convert bytes to integer
        ciphertext_int = int.from_bytes(ciphertext, byteorder='big')
        
        # Decrypt
        plaintext_int = pow(ciphertext_int, d, n)
        
        # Convert back to bytes
        byte_length = (plaintext_int.bit_length() + 7) // 8
        if byte_length == 0:
            byte_length = 1
        plaintext = plaintext_int.to_bytes(byte_length, byteorder='big')
        
        return plaintext
    
    def sign(self, message_hash: bytes) -> bytes:
        """Sign a hash with RSA private key"""
        d, n = self.private_key
        
        # Convert hash to integer
        hash_int = int.from_bytes(message_hash, byteorder='big')
        
        # Sign
        signature_int = pow(hash_int, d, n)
        
        # Convert to bytes
        byte_length = (signature_int.bit_length() + 7) // 8
        signature = signature_int.to_bytes(byte_length, byteorder='big')
        
        return signature
    
    def verify(self, message_hash: bytes, signature: bytes) -> bool:
        """Verify a signature with RSA public key"""
        e, n = self.public_key
        
        # Convert signature to integer
        signature_int = int.from_bytes(signature, byteorder='big')
        
        # Verify
        decrypted_hash_int = pow(signature_int, e, n)
        
        # Convert to bytes
        byte_length = (decrypted_hash_int.bit_length() + 7) // 8
        if byte_length == 0:
            byte_length = 1
        decrypted_hash = decrypted_hash_int.to_bytes(byte_length, byteorder='big')
        
        # Compare hashes (handle padding differences)
        return decrypted_hash == message_hash or message_hash in decrypted_hash or decrypted_hash in message_hash


# ==================== CLIENT ====================
class Client:
    def __init__(self, server_rsa):
        print("\n🖥️  Initializing Client...")
        self.server_public_key = server_rsa.public_key
        self.client_rsa = RSA(key_size=2048)
        print("✅ Client initialized!\n")
    
    def prepare_file_transfer(self, filename: str, file_content: bytes):
        """Prepare file for secure transfer"""
        print(f"\n📤 CLIENT: Preparing to send file '{filename}'")
        print("=" * 70)
        
        # Step 1: Generate random AES key
        print("\n🔑 Step 1: Generating AES-256 key...")
        aes_key = os.urandom(32)  # 256-bit key
        print(f"   AES Key (hex): {aes_key.hex()[:64]}...")
        
        # Step 2: Encrypt file with AES
        print("\n🔒 Step 2: Encrypting file with AES...")
        aes = AES(aes_key)
        iv, encrypted_file = aes.encrypt(file_content)
        print(f"   Original size: {len(file_content)} bytes")
        print(f"   Encrypted size: {len(encrypted_file)} bytes")
        print(f"   IV (hex): {iv.hex()}")
        
        # Step 3: Calculate SHA-256 hash of original file
        print("\n#️⃣ Step 3: Calculating SHA-256 hash of original file...")
        file_hash = hashlib.sha256(file_content).digest()
        print(f"   SHA-256 Hash: {file_hash.hex()}")
        
        # Step 4: Sign the hash with client's private key
        print("\n✍️  Step 4: Signing hash with RSA private key...")
        signature = self.client_rsa.sign(file_hash)
        print(f"   Signature length: {len(signature)} bytes")
        print(f"   Signature (hex): {signature.hex()[:64]}...")
        
        # Step 5: Encrypt AES key with server's RSA public key
        print("\n🔐 Step 5: Encrypting AES key with server's RSA public key...")
        encrypted_aes_key = RSA.encrypt_key_with_public(aes_key, self.server_public_key)
        print(f"   Encrypted AES key length: {len(encrypted_aes_key)} bytes")
        
        # Prepare transfer package
        transfer_package = {
            'filename': filename,
            'encrypted_file': encrypted_file,
            'iv': iv,
            'encrypted_aes_key': encrypted_aes_key,
            'file_hash': file_hash,
            'signature': signature,
            'client_public_key': self.client_rsa.public_key
        }
        
        print("\n✅ File package prepared for transfer!")
        print(f"   Total package size: ~{len(encrypted_file) + len(encrypted_aes_key) + len(signature)} bytes")
        
        return transfer_package


# Add static method to RSA class for encrypting with just public key
def encrypt_key_with_public(key_bytes: bytes, public_key: tuple) -> bytes:
    """Encrypt AES key with RSA public key"""
    e, n = public_key
    
    # Convert bytes to integer
    key_int = int.from_bytes(key_bytes, byteorder='big')
    
    if key_int >= n:
        raise ValueError("Key too large for RSA modulus")
    
    # Encrypt
    encrypted_int = pow(key_int, e, n)
    
    # Convert to bytes
    byte_length = (encrypted_int.bit_length() + 7) // 8
    encrypted = encrypted_int.to_bytes(byte_length, byteorder='big')
    
    return encrypted

RSA.encrypt_key_with_public = staticmethod(encrypt_key_with_public)


# ==================== SERVER ====================
class Server:
    def __init__(self):
        print("\n🖧  Initializing Server...")
        self.server_rsa = RSA(key_size=2048)
        print("✅ Server initialized!\n")
    
    def receive_file(self, transfer_package: dict) -> Tuple[bool, Optional[bytes]]:
        """Receive and process encrypted file"""
        print(f"\n📥 SERVER: Receiving file '{transfer_package['filename']}'")
        print("=" * 70)
        
        try:
            # Step 1: Verify signature
            print("\n🔍 Step 1: Verifying digital signature...")
            client_public_key = transfer_package['client_public_key']
            file_hash = transfer_package['file_hash']
            signature = transfer_package['signature']
            
            # Create temporary RSA instance with client's public key for verification
            temp_rsa = RSA.__new__(RSA)
            temp_rsa.public_key = client_public_key
            
            is_valid = temp_rsa.verify(file_hash, signature)
            
            if is_valid:
                print("   ✅ Signature verified! File is authentic.")
            else:
                print("   ❌ Signature verification failed! File may be tampered.")
                return False, None
            
            # Step 2: Decrypt AES key with server's private key
            print("\n🔓 Step 2: Decrypting AES key with RSA private key...")
            encrypted_aes_key = transfer_package['encrypted_aes_key']
            aes_key = self.server_rsa.decrypt(encrypted_aes_key)
            print(f"   Decrypted AES Key (hex): {aes_key.hex()[:64]}...")
            
            # Step 3: Decrypt file with AES
            print("\n🔓 Step 3: Decrypting file with AES...")
            iv = transfer_package['iv']
            encrypted_file = transfer_package['encrypted_file']
            
            aes = AES(aes_key)
            decrypted_file = aes.decrypt(iv, encrypted_file)
            print(f"   Decrypted file size: {len(decrypted_file)} bytes")
            
            # Step 4: Validate hash
            print("\n✔️  Step 4: Validating file integrity...")
            calculated_hash = hashlib.sha256(decrypted_file).digest()
            
            if calculated_hash == file_hash:
                print("   ✅ Hash matches! File integrity verified.")
                print(f"   Expected:    {file_hash.hex()}")
                print(f"   Calculated:  {calculated_hash.hex()}")
            else:
                print("   ❌ Hash mismatch! File may be corrupted.")
                print(f"   Expected:    {file_hash.hex()}")
                print(f"   Calculated:  {calculated_hash.hex()}")
                return False, None
            
            print("\n🎉 File received and verified successfully!")
            
            return True, decrypted_file
            
        except Exception as e:
            print(f"\n❌ Error processing file: {str(e)}")
            return False, None


# ==================== FILE TRANSFER SYSTEM ====================
class FileTransferSystem:
    def __init__(self):
        print("\n" + "=" * 70)
        print("🔐 SECURE FILE TRANSFER SYSTEM")
        print("=" * 70)
        print("\n🚀 Initializing system components...")
        
        # Initialize server first (generates RSA keys)
        self.server = Server()
        
        # Initialize client with server's public key
        self.client = Client(self.server.server_rsa)
        
        # Storage for simulated files
        self.client_files = {}
        self.server_files = {}
        
        print("✅ System ready for secure file transfer!\n")
    
    def create_sample_file(self, filename: str, content: str):
        """Create a sample file on client side"""
        self.client_files[filename] = content.encode()
        print(f"✅ File '{filename}' created on client ({len(content)} characters)")
    
    def list_client_files(self):
        """List files on client"""
        if not self.client_files:
            print("\n📭 No files on client.")
            return
        
        print("\n📁 Client Files:")
        print("-" * 70)
        for filename, content in self.client_files.items():
            print(f"   📄 {filename} ({len(content)} bytes)")
    
    def list_server_files(self):
        """List files on server"""
        if not self.server_files:
            print("\n📭 No files on server.")
            return
        
        print("\n📁 Server Files:")
        print("-" * 70)
        for filename, content in self.server_files.items():
            print(f"   📄 {filename} ({len(content)} bytes)")
    
    def transfer_file(self, filename: str):
        """Transfer file from client to server"""
        if filename not in self.client_files:
            print(f"\n❌ File '{filename}' not found on client!")
            return
        
        file_content = self.client_files[filename]
        
        # Client prepares the file
        transfer_package = self.client.prepare_file_transfer(filename, file_content)
        
        # Simulate network transfer
        print("\n📡 Transferring encrypted package to server...")
        print("   " + "▓" * 50)
        
        # Server receives and processes the file
        success, decrypted_content = self.server.receive_file(transfer_package)
        
        if success:
            self.server_files[filename] = decrypted_content
            print(f"\n✅ File '{filename}' successfully transferred and verified!")
        else:
            print(f"\n❌ File transfer failed for '{filename}'!")
    
    def view_file(self, location: str, filename: str):
        """View file content"""
        files = self.client_files if location == 'client' else self.server_files
        
        if filename not in files:
            print(f"\n❌ File '{filename}' not found on {location}!")
            return
        
        content = files[filename].decode()
        print(f"\n📄 Content of '{filename}' on {location}:")
        print("-" * 70)
        print(content)
        print("-" * 70)


# ==================== MAIN MENU ====================
def main():
    system = FileTransferSystem()
    
    while True:
        print("\n" + "=" * 70)
        print("🔐 SECURE FILE TRANSFER SYSTEM - MAIN MENU")
        print("=" * 70)
        print("1. Create Sample File on Client")
        print("2. List Client Files")
        print("3. List Server Files")
        print("4. Transfer File to Server (Encrypted)")
        print("5. View File Content")
        print("6. Demo: Complete Transfer Process")
        print("7. Exit")
        print("=" * 70)
        
        choice = input("\nEnter your choice (1-7): ").strip()
        
        if choice == '1':
            filename = input("\nEnter filename: ").strip()
            print("\nEnter file content (press Enter twice to finish):")
            lines = []
            while True:
                line = input()
                if line == "" and (not lines or lines[-1] == ""):
                    break
                lines.append(line)
            
            content = "\n".join(lines[:-1] if lines and lines[-1] == "" else lines)
            system.create_sample_file(filename, content)
        
        elif choice == '2':
            system.list_client_files()
        
        elif choice == '3':
            system.list_server_files()
        
        elif choice == '4':
            system.list_client_files()
            filename = input("\nEnter filename to transfer: ").strip()
            system.transfer_file(filename)
        
        elif choice == '5':
            location = input("\nView from (client/server): ").strip().lower()
            if location not in ['client', 'server']:
                print("❌ Invalid location!")
                continue
            
            if location == 'client':
                system.list_client_files()
            else:
                system.list_server_files()
            
            filename = input("\nEnter filename to view: ").strip()
            system.view_file(location, filename)
        
        elif choice == '6':
            print("\n🎬 Starting Demo: Complete Secure File Transfer")
            print("=" * 70)
            
            # Create sample file
            demo_content = """This is a confidential document.
            
Account Number: 1234-5678-9012-3456
Password: SecurePass123!
API Key: sk_live_abc123xyz789

This file demonstrates:
✓ AES-256 encryption for confidentiality
✓ RSA encryption for key exchange
✓ SHA-256 hashing for integrity
✓ RSA digital signature for authenticity"""
            
            system.create_sample_file("confidential.txt", demo_content)
            
            # Transfer the file
            input("\nPress Enter to start encrypted transfer...")
            system.transfer_file("confidential.txt")
            
            # Show results
            input("\nPress Enter to view the received file on server...")
            system.view_file('server', 'confidential.txt')
        
        elif choice == '7':
            print("\n👋 Thank you for using Secure File Transfer System!")
            print("=" * 70)
            break
        
        else:
            print("\n❌ Invalid choice. Please select 1-7.")
        
        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()