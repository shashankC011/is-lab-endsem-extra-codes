# ============================================================
# AES Encryption in Different Modes Demo
# Demonstrates ECB, CBC, CFB, OFB, and CTR modes using Helpers.py
# ============================================================

import os
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii

# Import helper functions (assuming Helpers.py is in the same directory)
from Helpers import aes_encrypt, aes_decrypt, aes_encrypt_bytes, aes_decrypt_bytes

class AESModeDemo:
    def __init__(self):
        # Generate a random 256-bit AES key
        self.key = get_random_bytes(32)  # 256-bit key
        self.test_message = "This is a test message for AES encryption in different modes! " * 2
        self.test_bytes = self.test_message.encode('utf-8')
        
    def print_separator(self, title):
        print(f"\n{'='*60}")
        print(f"  {title}")
        print(f"{'='*60}")
    
    def print_results(self, mode, ciphertext, decrypted, iv=None):
        print(f"Mode: {mode}")
        print(f"Key: {binascii.hexlify(self.key).decode()[:32]}...")
        if iv:
            print(f"IV: {binascii.hexlify(iv).decode()}")
        print(f"Original: {self.test_message[:50]}...")
        print(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode()[:64]}...")
        print(f"Decrypted: {decrypted[:50]}...")
        print(f"Match: {decrypted == self.test_message}")
        print("-" * 60)
    
    def demo_ecb_mode(self):
        """Electronic Codebook (ECB) Mode - Not recommended for production"""
        self.print_separator("AES ECB Mode (Electronic Codebook)")
        
        try:
            # Using helper function
            ciphertext = aes_encrypt(self.test_message, self.key, AES.MODE_ECB)
            decrypted = aes_decrypt(ciphertext, self.key, AES.MODE_ECB)
            self.print_results("ECB", ciphertext, decrypted)
            
            print("⚠️  ECB Mode Warning:")
            print("   - Identical plaintext blocks produce identical ciphertext blocks")
            print("   - Not semantically secure")
            print("   - Should not be used for sensitive data")
            
        except Exception as e:
            print(f"ECB Mode Error: {e}")
    
    def demo_cbc_mode(self):
        """Cipher Block Chaining (CBC) Mode"""
        self.print_separator("AES CBC Mode (Cipher Block Chaining)")
        
        try:
            # Generate random IV
            iv = get_random_bytes(16)
            
            # Manual CBC implementation using pycryptodome
            cipher_enc = AES.new(self.key, AES.MODE_CBC, iv)
            padded_data = pad(self.test_bytes, AES.block_size)
            ciphertext = cipher_enc.encrypt(padded_data)
            
            # Decrypt
            cipher_dec = AES.new(self.key, AES.MODE_CBC, iv)
            padded_decrypted = cipher_dec.decrypt(ciphertext)
            decrypted_bytes = unpad(padded_decrypted, AES.block_size)
            decrypted = decrypted_bytes.decode('utf-8')
            
            self.print_results("CBC", ciphertext, decrypted, iv)
            
            print("✅ CBC Mode Benefits:")
            print("   - Each block depends on the previous block")
            print("   - Requires IV (Initialization Vector)")
            print("   - Provides confidentiality but not authentication")
            
        except Exception as e:
            print(f"CBC Mode Error: {e}")
    
    def demo_cfb_mode(self):
        """Cipher Feedback (CFB) Mode"""
        self.print_separator("AES CFB Mode (Cipher Feedback)")
        
        try:
            # Generate random IV
            iv = get_random_bytes(16)
            
            # CFB mode - turns block cipher into stream cipher
            cipher_enc = AES.new(self.key, AES.MODE_CFB, iv)
            ciphertext = cipher_enc.encrypt(self.test_bytes)
            
            # Decrypt
            cipher_dec = AES.new(self.key, AES.MODE_CFB, iv)
            decrypted_bytes = cipher_dec.decrypt(ciphertext)
            decrypted = decrypted_bytes.decode('utf-8')
            
            self.print_results("CFB", ciphertext, decrypted, iv)
            
            print("✅ CFB Mode Benefits:")
            print("   - Self-synchronizing stream cipher")
            print("   - Error propagation is limited")
            print("   - Can encrypt data smaller than block size")
            
        except Exception as e:
            print(f"CFB Mode Error: {e}")
    
    def demo_ofb_mode(self):
        """Output Feedback (OFB) Mode"""
        self.print_separator("AES OFB Mode (Output Feedback)")
        
        try:
            # Generate random IV
            iv = get_random_bytes(16)
            
            # OFB mode - another stream cipher mode
            cipher_enc = AES.new(self.key, AES.MODE_OFB, iv)
            ciphertext = cipher_enc.encrypt(self.test_bytes)
            
            # Decrypt
            cipher_dec = AES.new(self.key, AES.MODE_OFB, iv)
            decrypted_bytes = cipher_dec.decrypt(ciphertext)
            decrypted = decrypted_bytes.decode('utf-8')
            
            self.print_results("OFB", ciphertext, decrypted, iv)
            
            print("✅ OFB Mode Benefits:")
            print("   - Stream cipher mode")
            print("   - No error propagation")
            print("   - Preprocessing possible")
            print("   - Bit errors don't propagate")
            
        except Exception as e:
            print(f"OFB Mode Error: {e}")
    
    def demo_ctr_mode(self):
        """Counter (CTR) Mode"""
        self.print_separator("AES CTR Mode (Counter)")
        
        try:
            # Generate random nonce
            nonce = get_random_bytes(8)  # CTR mode uses nonce + counter
            
            # CTR mode - converts block cipher to stream cipher
            cipher_enc = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
            ciphertext = cipher_enc.encrypt(self.test_bytes)
            
            # Decrypt
            cipher_dec = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
            decrypted_bytes = cipher_dec.decrypt(ciphertext)
            decrypted = decrypted_bytes.decode('utf-8')
            
            self.print_results("CTR", ciphertext, decrypted, nonce)
            
            print("✅ CTR Mode Benefits:")
            print("   - Parallel encryption/decryption possible")
            print("   - Random access to encrypted data")
            print("   - No padding required")
            print("   - Stream cipher properties")
            
        except Exception as e:
            print(f"CTR Mode Error: {e}")
    
    def demo_gcm_mode(self):
        """Galois/Counter Mode (GCM) - Authenticated Encryption"""
        self.print_separator("AES GCM Mode (Galois/Counter - Authenticated)")
        
        try:
            # Generate random nonce
            nonce = get_random_bytes(12)  # GCM typically uses 96-bit nonce
            
            # Additional Authentication Data (AAD)
            aad = b"metadata_not_encrypted_but_authenticated"
            
            # GCM mode provides both confidentiality and authenticity
            cipher_enc = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            cipher_enc.update(aad)
            ciphertext, tag = cipher_enc.encrypt_and_digest(self.test_bytes)
            
            # Decrypt and verify
            cipher_dec = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            cipher_dec.update(aad)
            decrypted_bytes = cipher_dec.decrypt_and_verify(ciphertext, tag)
            decrypted = decrypted_bytes.decode('utf-8')
            
            print(f"Mode: GCM")
            print(f"Key: {binascii.hexlify(self.key).decode()[:32]}...")
            print(f"Nonce: {binascii.hexlify(nonce).decode()}")
            print(f"Auth Tag: {binascii.hexlify(tag).decode()}")
            print(f"AAD: {aad.decode()}")
            print(f"Original: {self.test_message[:50]}...")
            print(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode()[:64]}...")
            print(f"Decrypted: {decrypted[:50]}...")
            print(f"Match: {decrypted == self.test_message}")
            print("-" * 60)
            
            print("✅ GCM Mode Benefits:")
            print("   - Provides both confidentiality and authenticity")
            print("   - Parallel processing possible")
            print("   - Built-in integrity checking")
            print("   - AEAD (Authenticated Encryption with Associated Data)")
            
        except Exception as e:
            print(f"GCM Mode Error: {e}")
    
    def compare_modes(self):
        """Compare different modes"""
        self.print_separator("AES Modes Comparison Summary")
        
        modes_info = [
            ("ECB", "❌ Not Secure", "Identical blocks → identical ciphertext"),
            ("CBC", "✅ Secure", "Sequential, requires padding"),
            ("CFB", "✅ Secure", "Stream cipher, self-synchronizing"),
            ("OFB", "✅ Secure", "Stream cipher, no error propagation"),
            ("CTR", "✅ Secure", "Stream cipher, parallel processing"),
            ("GCM", "✅ Most Secure", "Authenticated encryption + integrity")
        ]
        
        print(f"{'Mode':<6} {'Security':<15} {'Characteristics'}")
        print("-" * 60)
        for mode, security, chars in modes_info:
            print(f"{mode:<6} {security:<15} {chars}")
        
        print(f"\n💡 Recommendations:")
        print("   • Use GCM for new applications (authenticated encryption)")
        print("   • Use CBC with HMAC for legacy compatibility")
        print("   • Avoid ECB mode entirely")
        print("   • Always use random IVs/nonces")
        print("   • Consider CTR for parallel processing needs")

def main():
    print("🔐 AES Encryption Modes Demonstration")
    print("Using pycryptodome library with helper functions")
    
    demo = AESModeDemo()
    
    # Run all demonstrations
    demo.demo_ecb_mode()
    demo.demo_cbc_mode()
    demo.demo_cfb_mode()
    demo.demo_ofb_mode()
    demo.demo_ctr_mode()
    demo.demo_gcm_mode()
    demo.compare_modes()
    
    print(f"\n{'='*60}")
    print("Demo completed! Check the output above for detailed results.")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()