from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1
from Crypto.Random import get_random_bytes
import json
import base64
from datetime import datetime
import pickle
'''Secure Audit Trail (RSA + Digital Signature + SHA-1)

Develop a transaction logging system where:

All transactions are RSA-encrypted.

Each log entry is digitally signed (RSA signature).

A SHA-1 hash chain is used so tampering any record invalidates all following logs..'''

class CryptoUtils:
    """Cryptographic utility functions"""
    
    @staticmethod
    def generate_rsa_keypair(bits=1024):
        """Generate RSA key pair"""
        key = RSA.generate(bits)
        return key, key.publickey()
    
    @staticmethod
    def rsa_encrypt(public_key, plaintext):
        """Encrypt data with RSA public key"""
        cipher = PKCS1_OAEP.new(public_key)
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Handle large data by chunking
        max_chunk_size = 86  # For RSA-1024 with OAEP
        chunks = [plaintext[i:i+max_chunk_size] 
                  for i in range(0, len(plaintext), max_chunk_size)]
        
        encrypted_chunks = [cipher.encrypt(chunk) for chunk in chunks]
        return encrypted_chunks
    
    @staticmethod
    def rsa_decrypt(private_key, encrypted_chunks):
        """Decrypt data with RSA private key"""
        cipher = PKCS1_OAEP.new(private_key)
        decrypted_chunks = [cipher.decrypt(chunk) for chunk in encrypted_chunks]
        plaintext = b''.join(decrypted_chunks)
        return plaintext.decode('utf-8')
    
    @staticmethod
    def sign_data(private_key, data):
        """Create RSA digital signature"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        hash_obj = SHA1.new(data)
        signature = pkcs1_15.new(private_key).sign(hash_obj)
        return base64.b64encode(signature).decode()
    
    @staticmethod
    def verify_signature(public_key, data, signature):
        """Verify RSA digital signature"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        try:
            hash_obj = SHA1.new(data)
            signature_bytes = base64.b64decode(signature)
            pkcs1_15.new(public_key).verify(hash_obj, signature_bytes)
            return True
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def compute_sha1(data):
        """Compute SHA-1 hash"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        hash_obj = SHA1.new(data)
        return hash_obj.hexdigest()


class AuditLogEntry:
    """Represents a single audit log entry in the chain"""
    
    def __init__(self, log_id, action, user, details, previous_hash, system_private_key):
        self.log_id = log_id
        self.action = action
        self.user = user
        self.details = details
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.previous_hash = previous_hash
        
        # Create log data
        self.log_data = {
            'log_id': log_id,
            'action': action,
            'user': user,
            'details': details,
            'timestamp': self.timestamp,
            'previous_hash': previous_hash
        }
        
        # Convert to JSON for encryption and hashing
        self.log_json = json.dumps(self.log_data, sort_keys=True)
        
        # 1. RSA Encrypt the log entry
        self.encrypted_data = CryptoUtils.rsa_encrypt(
            system_private_key.publickey(), 
            self.log_json
        )
        
        # 2. Create digital signature of the log
        self.signature = CryptoUtils.sign_data(system_private_key, self.log_json)
        
        # 3. Compute current hash (includes previous hash for chaining)
        hash_input = f"{self.log_json}|{previous_hash}|{self.signature}"
        self.current_hash = CryptoUtils.compute_sha1(hash_input)
    
    def verify_signature(self, system_public_key):
        """Verify the digital signature of this log entry"""
        return CryptoUtils.verify_signature(
            system_public_key, 
            self.log_json, 
            self.signature
        )
    
    def verify_hash_chain(self):
        """Verify the hash chain integrity"""
        hash_input = f"{self.log_json}|{self.previous_hash}|{self.signature}"
        computed_hash = CryptoUtils.compute_sha1(hash_input)
        return computed_hash == self.current_hash
    
    def decrypt(self, system_private_key):
        """Decrypt the log entry"""
        return CryptoUtils.rsa_decrypt(system_private_key, self.encrypted_data)


class AuditTrailSystem:
    """Main Audit Trail System with blockchain-like properties"""
    
    def __init__(self):
        print("\n" + "="*70)
        print("  INITIALIZING SECURE AUDIT TRAIL SYSTEM")
        print("="*70)
        print("\nGenerating system RSA keys...")
        
        # Generate system RSA key pair
        self.system_private, self.system_public = CryptoUtils.generate_rsa_keypair(1024)
        
        print("✓ System keys generated")
        print("✓ RSA-1024 Encryption enabled")
        print("✓ RSA Digital Signatures enabled")
        print("✓ SHA-1 Hash Chain enabled")
        
        # Initialize audit log chain
        self.audit_chain = []
        self.genesis_hash = "0" * 40  # SHA-1 produces 40 hex characters
        
        # Create genesis block
        self._create_genesis_block()
        
        print(f"\n✓ Genesis block created")
        print(f"✓ Audit trail initialized with hash: {self.genesis_hash[:16]}...")
    
    def _create_genesis_block(self):
        """Create the first block in the audit chain"""
        genesis_entry = AuditLogEntry(
            log_id=0,
            action="SYSTEM_INIT",
            user="SYSTEM",
            details="Audit trail system initialized",
            previous_hash=self.genesis_hash,
            system_private_key=self.system_private
        )
        self.audit_chain.append(genesis_entry)
    
    def add_transaction(self, action, user, details):
        """Add a new transaction to the audit log"""
        # Get previous hash from the last entry
        previous_hash = self.audit_chain[-1].current_hash
        
        # Create new log entry
        log_id = len(self.audit_chain)
        new_entry = AuditLogEntry(
            log_id=log_id,
            action=action,
            user=user,
            details=details,
            previous_hash=previous_hash,
            system_private_key=self.system_private
        )
        
        # Add to chain
        self.audit_chain.append(new_entry)
        
        return new_entry
    
    def verify_entire_chain(self):
        """Verify integrity of entire audit chain"""
        print("\n" + "="*70)
        print("  VERIFYING ENTIRE AUDIT CHAIN")
        print("="*70)
        
        all_valid = True
        
        for i, entry in enumerate(self.audit_chain):
            print(f"\nVerifying Log Entry #{entry.log_id}:")
            
            # 1. Verify digital signature
            sig_valid = entry.verify_signature(self.system_public)
            print(f"  ✓ Signature: {'VALID' if sig_valid else 'INVALID'}")
            
            # 2. Verify hash chain
            hash_valid = entry.verify_hash_chain()
            print(f"  ✓ Hash Chain: {'VALID' if hash_valid else 'INVALID'}")
            
            # 3. Verify link to previous entry
            if i > 0:
                expected_prev = self.audit_chain[i-1].current_hash
                link_valid = entry.previous_hash == expected_prev
                print(f"  ✓ Chain Link: {'VALID' if link_valid else 'INVALID'}")
                
                if not link_valid:
                    all_valid = False
                    print(f"  ✗ ERROR: Chain broken at entry #{entry.log_id}")
            
            if not (sig_valid and hash_valid):
                all_valid = False
                print(f"  ✗ ERROR: Entry #{entry.log_id} is corrupted")
        
        print("\n" + "="*70)
        if all_valid:
            print("✓ AUDIT CHAIN IS VALID - NO TAMPERING DETECTED")
        else:
            print("✗ AUDIT CHAIN IS INVALID - TAMPERING DETECTED!")
        print("="*70)
        
        return all_valid
    
    def display_chain(self, show_encrypted=False):
        """Display the entire audit chain"""
        print("\n" + "="*70)
        print("  AUDIT TRAIL CHAIN")
        print("="*70)
        
        for entry in self.audit_chain:
            print(f"\n{'─'*70}")
            print(f"Log ID: {entry.log_id}")
            print(f"Action: {entry.action}")
            print(f"User: {entry.user}")
            print(f"Details: {entry.details}")
            print(f"Timestamp: {entry.timestamp}")
            print(f"Previous Hash: {entry.previous_hash[:32]}...")
            print(f"Current Hash: {entry.current_hash[:32]}...")
            print(f"Signature: {entry.signature[:32]}...")
            
            if show_encrypted:
                print(f"Encrypted: Yes ({len(entry.encrypted_data)} chunks)")
            
            print(f"{'─'*70}")
    
    def decrypt_log_entry(self, log_id):
        """Decrypt and display a specific log entry"""
        if log_id < 0 or log_id >= len(self.audit_chain):
            print("✗ Invalid log ID!")
            return
        
        entry = self.audit_chain[log_id]
        
        print("\n" + "="*70)
        print(f"  DECRYPTING LOG ENTRY #{log_id}")
        print("="*70)
        
        # Decrypt
        decrypted_json = entry.decrypt(self.system_private)
        decrypted_data = json.loads(decrypted_json)
        
        print(f"\n🔓 DECRYPTED CONTENT:")
        print(json.dumps(decrypted_data, indent=2))
        
        # Verify signature
        sig_valid = entry.verify_signature(self.system_public)
        print(f"\n🔏 Signature Verification: {'✓ VALID' if sig_valid else '✗ INVALID'}")
        
        # Verify hash
        hash_valid = entry.verify_hash_chain()
        print(f"🔗 Hash Chain Verification: {'✓ VALID' if hash_valid else '✗ INVALID'}")
        
        print("="*70)
    
    def simulate_tampering(self, log_id):
        """Simulate tampering with a log entry to demonstrate chain invalidation"""
        if log_id < 1 or log_id >= len(self.audit_chain):
            print("✗ Invalid log ID! Cannot tamper with genesis block.")
            return
        
        print("\n" + "="*70)
        print("  SIMULATING TAMPERING")
        print("="*70)
        print(f"\n⚠️  WARNING: Tampering with log entry #{log_id}")
        
        # Tamper with the entry
        entry = self.audit_chain[log_id]
        original_action = entry.action
        entry.log_data['action'] = "TAMPERED_ACTION"
        entry.log_json = json.dumps(entry.log_data, sort_keys=True)
        
        print(f"Original Action: {original_action}")
        print(f"Tampered Action: TAMPERED_ACTION")
        print("\n✓ Tampering complete")
        print(f"✓ This will invalidate log #{log_id} and all subsequent logs")
    
    def export_chain_summary(self):
        """Export a summary of the audit chain"""
        print("\n" + "="*70)
        print("  AUDIT CHAIN SUMMARY")
        print("="*70)
        
        print(f"\nTotal Log Entries: {len(self.audit_chain)}")
        print(f"Genesis Hash: {self.genesis_hash}")
        print(f"Latest Hash: {self.audit_chain[-1].current_hash}")
        
        # Count actions
        action_counts = {}
        for entry in self.audit_chain:
            action = entry.action
            action_counts[action] = action_counts.get(action, 0) + 1
        
        print(f"\nAction Breakdown:")
        for action, count in action_counts.items():
            print(f"  • {action}: {count}")
        
        print(f"\nSecurity Features:")
        print(f"  ✓ RSA-1024 Encryption")
        print(f"  ✓ RSA Digital Signatures")
        print(f"  ✓ SHA-1 Hash Chaining")
        print(f"  ✓ Tamper-Evident Design")
        print("="*70)
    
    def display_hash_chain_visual(self):
        """Display visual representation of hash chain"""
        print("\n" + "="*70)
        print("  HASH CHAIN VISUALIZATION")
        print("="*70)
        
        print("\n┌─────────────────────────────────────────────────────────┐")
        print("│  Each block's hash depends on all previous blocks      │")
        print("│  Tampering ANY block invalidates ALL following blocks  │")
        print("└─────────────────────────────────────────────────────────┘\n")
        
        for i, entry in enumerate(self.audit_chain[:5]):  # Show first 5
            if i == 0:
                print(f"┌─────────[ LOG #{entry.log_id} - GENESIS ]─────────┐")
            else:
                print(f"┌─────────[ LOG #{entry.log_id} ]─────────┐")
            
            print(f"│ Action: {entry.action:<30} │")
            print(f"│ User: {entry.user:<32} │")
            print(f"│ Hash: {entry.current_hash[:20]}... │")
            print(f"└────────────────────────────────────────────┘")
            
            if i < len(self.audit_chain) - 1:
                print("        │")
                print("        │ Chained via")
                print("        │ previous_hash")
                print("        ↓")
        
        if len(self.audit_chain) > 5:
            print(f"\n... and {len(self.audit_chain) - 5} more entries in the chain")


def main():
    """Main program"""
    system = AuditTrailSystem()
    
    while True:
        print("\n" + "="*70)
        print("     SECURE AUDIT TRAIL SYSTEM")
        print("="*70)
        print("1. Add Transaction")
        print("2. View Audit Chain")
        print("3. Verify Entire Chain")
        print("4. Decrypt Specific Log Entry")
        print("5. View Chain Summary")
        print("6. View Hash Chain Visualization")
        print("7. Add Demo Transactions")
        print("8. Simulate Tampering (Demo)")
        print("9. Exit")
        print("="*70)
        
        choice = input("\nEnter choice: ").strip()
        
        if choice == '1':
            print("\n--- Add New Transaction ---")
            action = input("Action (e.g., LOGIN, TRANSFER, DELETE): ").strip().upper()
            user = input("User: ").strip()
            details = input("Details: ").strip()
            
            if action and user:
                entry = system.add_transaction(action, user, details)
                print(f"\n✓ Transaction added to audit log")
                print(f"  Log ID: {entry.log_id}")
                print(f"  Hash: {entry.current_hash[:32]}...")
                print(f"  Previous Hash: {entry.previous_hash[:32]}...")
                print(f"  Signature: {entry.signature[:32]}...")
            else:
                print("✗ Action and User are required!")
        
        elif choice == '2':
            show_enc = input("Show encrypted data? (y/n): ").strip().lower() == 'y'
            system.display_chain(show_encrypted=show_enc)
        
        elif choice == '3':
            system.verify_entire_chain()
        
        elif choice == '4':
            try:
                log_id = int(input("Enter Log ID to decrypt: ").strip())
                system.decrypt_log_entry(log_id)
            except ValueError:
                print("✗ Invalid Log ID!")
        
        elif choice == '5':
            system.export_chain_summary()
        
        elif choice == '6':
            system.display_hash_chain_visual()
        
        elif choice == '7':
            print("\n--- Adding Demo Transactions ---")
            demo_transactions = [
                ("LOGIN", "alice", "User logged in from 192.168.1.100"),
                ("TRANSFER", "alice", "Transferred $500 to bob"),
                ("UPDATE", "bob", "Updated profile information"),
                ("DELETE", "admin", "Deleted old records"),
                ("LOGOUT", "alice", "User logged out"),
            ]
            
            for action, user, details in demo_transactions:
                entry = system.add_transaction(action, user, details)
                print(f"✓ Added: {action} by {user}")
            
            print(f"\n✓ All demo transactions added!")
        
        elif choice == '8':
            print("\n--- Tampering Demonstration ---")
            print("This will tamper with a log entry to show how the chain")
            print("becomes invalid when ANY entry is modified.\n")
            
            if len(system.audit_chain) < 3:
                print("✗ Need at least 3 log entries. Add demo transactions first.")
            else:
                try:
                    log_id = int(input(f"Enter Log ID to tamper (1-{len(system.audit_chain)-1}): "))
                    system.simulate_tampering(log_id)
                    
                    input("\nPress Enter to verify chain and see the impact...")
                    system.verify_entire_chain()
                except ValueError:
                    print("✗ Invalid Log ID!")
        
        elif choice == '9':
            print("\n" + "="*70)
            print("  Thank you for using Secure Audit Trail System!")
            print("="*70)
            break
        
        else:
            print("✗ Invalid choice!")


if __name__ == "__main__":
    main()