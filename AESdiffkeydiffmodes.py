# ============================================================
# AES with Different Key Sizes (128, 192, 256 bits) Demo
# Demonstrates how AES behavior changes with different key lengths
# ============================================================

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii
import time

# Import helper functions
from Helpers import aes_encrypt, aes_decrypt

def print_separator(title):
    """Print a formatted separator with title"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def print_key_info(key_size, key):
    """Print information about the key being used"""
    print(f"Key Size: {key_size} bits ({len(key)} bytes)")
    print(f"Key (hex): {binascii.hexlify(key).decode()}")
    print(f"Security Level: {key_size}-bit")
    # Number of rounds varies by key size in AES
    if key_size == 128:
        print(f"AES Rounds: 10")
    elif key_size == 192:
        print(f"AES Rounds: 12")
    elif key_size == 256:
        print(f"AES Rounds: 14")

def aes_128_demo():
    """Demonstrate AES-128 (128-bit key) in different modes"""
    print_separator("AES-128 (128-bit Key) Demonstrations")
    
    # Generate 128-bit key (16 bytes)
    key_128 = get_random_bytes(16)
    message = "Testing AES-128 encryption with different modes!"
    
    print_key_info(128, key_128)
    print(f"Original message: {message}")
    
    # ECB Mode
    print(f"\n--- ECB Mode ---")
    ciphertext_ecb = aes_encrypt(message, key_128, AES.MODE_ECB)
    decrypted_ecb = aes_decrypt(ciphertext_ecb, key_128, AES.MODE_ECB)
    print(f"Ciphertext (hex): {binascii.hexlify(ciphertext_ecb).decode()[:64]}...")
    print(f"Decrypted: {decrypted_ecb}")
    print(f"Success: {decrypted_ecb == message}")
    
    # CBC Mode
    print(f"\n--- CBC Mode ---")
    iv = get_random_bytes(16)  # IV size = block size (16 bytes for AES)
    print(f"IV (hex): {binascii.hexlify(iv).decode()}")
    
    cipher = AES.new(key_128, AES.MODE_CBC, iv)
    padded = pad(message.encode(), AES.block_size)
    ciphertext_cbc = cipher.encrypt(padded)
    
    cipher = AES.new(key_128, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext_cbc)
    decrypted_cbc = unpad(decrypted_padded, AES.block_size).decode()
    
    print(f"Ciphertext (hex): {binascii.hexlify(ciphertext_cbc).decode()[:64]}...")
    print(f"Decrypted: {decrypted_cbc}")
    print(f"Success: {decrypted_cbc == message}")
    
    # CTR Mode
    print(f"\n--- CTR Mode ---")
    nonce = get_random_bytes(8)
    print(f"Nonce (hex): {binascii.hexlify(nonce).decode()}")
    
    cipher = AES.new(key_128, AES.MODE_CTR, nonce=nonce)
    ciphertext_ctr = cipher.encrypt(message.encode())
    
    cipher = AES.new(key_128, AES.MODE_CTR, nonce=nonce)
    decrypted_ctr = cipher.decrypt(ciphertext_ctr).decode()
    
    print(f"Ciphertext (hex): {binascii.hexlify(ciphertext_ctr).decode()[:64]}...")
    print(f"Decrypted: {decrypted_ctr}")
    print(f"Success: {decrypted_ctr == message}")

def aes_192_demo():
    """Demonstrate AES-192 (192-bit key) in different modes"""
    print_separator("AES-192 (192-bit Key) Demonstrations")
    
    # Generate 192-bit key (24 bytes)
    key_192 = get_random_bytes(24)
    message = "Testing AES-192 encryption with different modes!"
    
    print_key_info(192, key_192)
    print(f"Original message: {message}")
    
    # ECB Mode - Note: Helper function may not support 192-bit directly
    print(f"\n--- ECB Mode ---")
    # Using direct pycryptodome since helper might be designed for specific key sizes
    cipher = AES.new(key_192, AES.MODE_ECB)
    padded = pad(message.encode(), AES.block_size)
    ciphertext_ecb = cipher.encrypt(padded)
    
    cipher = AES.new(key_192, AES.MODE_ECB)
    decrypted_padded = cipher.decrypt(ciphertext_ecb)
    decrypted_ecb = unpad(decrypted_padded, AES.block_size).decode()
    
    print(f"Ciphertext (hex): {binascii.hexlify(ciphertext_ecb).decode()[:64]}...")
    print(f"Decrypted: {decrypted_ecb}")
    print(f"Success: {decrypted_ecb == message}")
    
    # CBC Mode
    print(f"\n--- CBC Mode ---")
    iv = get_random_bytes(16)  # IV size remains 16 bytes (block size) regardless of key size
    print(f"IV (hex): {binascii.hexlify(iv).decode()}")
    
    cipher = AES.new(key_192, AES.MODE_CBC, iv)
    padded = pad(message.encode(), AES.block_size)
    ciphertext_cbc = cipher.encrypt(padded)
    
    cipher = AES.new(key_192, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext_cbc)
    decrypted_cbc = unpad(decrypted_padded, AES.block_size).decode()
    
    print(f"Ciphertext (hex): {binascii.hexlify(ciphertext_cbc).decode()[:64]}...")
    print(f"Decrypted: {decrypted_cbc}")
    print(f"Success: {decrypted_cbc == message}")
    
    # GCM Mode
    print(f"\n--- GCM Mode ---")
    nonce = get_random_bytes(12)  # GCM nonce size is typically 12 bytes
    print(f"Nonce (hex): {binascii.hexlify(nonce).decode()}")
    
    cipher = AES.new(key_192, AES.MODE_GCM, nonce=nonce)
    ciphertext_gcm, auth_tag = cipher.encrypt_and_digest(message.encode())
    
    cipher = AES.new(key_192, AES.MODE_GCM, nonce=nonce)
    decrypted_gcm = cipher.decrypt_and_verify(ciphertext_gcm, auth_tag).decode()
    
    print(f"Ciphertext (hex): {binascii.hexlify(ciphertext_gcm).decode()[:64]}...")
    print(f"Auth Tag (hex): {binascii.hexlify(auth_tag).decode()}")
    print(f"Decrypted: {decrypted_gcm}")
    print(f"Success: {decrypted_gcm == message}")

def aes_256_demo():
    """Demonstrate AES-256 (256-bit key) in different modes"""
    print_separator("AES-256 (256-bit Key) Demonstrations")
    
    # Generate 256-bit key (32 bytes)
    key_256 = get_random_bytes(32)
    message = "Testing AES-256 encryption with different modes!"
    
    print_key_info(256, key_256)
    print(f"Original message: {message}")
    
    # ECB Mode using helper function
    print(f"\n--- ECB Mode ---")
    ciphertext_ecb = aes_encrypt(message, key_256, AES.MODE_ECB)
    decrypted_ecb = aes_decrypt(ciphertext_ecb, key_256, AES.MODE_ECB)
    print(f"Ciphertext (hex): {binascii.hexlify(ciphertext_ecb).decode()[:64]}...")
    print(f"Decrypted: {decrypted_ecb}")
    print(f"Success: {decrypted_ecb == message}")
    
    # CBC Mode
    print(f"\n--- CBC Mode ---")
    iv = get_random_bytes(16)  # IV size = block size (always 16 bytes for AES)
    print(f"IV (hex): {binascii.hexlify(iv).decode()}")
    
    cipher = AES.new(key_256, AES.MODE_CBC, iv)
    padded = pad(message.encode(), AES.block_size)
    ciphertext_cbc = cipher.encrypt(padded)
    
    cipher = AES.new(key_256, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext_cbc)
    decrypted_cbc = unpad(decrypted_padded, AES.block_size).decode()
    
    print(f"Ciphertext (hex): {binascii.hexlify(ciphertext_cbc).decode()[:64]}...")
    print(f"Decrypted: {decrypted_cbc}")
    print(f"Success: {decrypted_cbc == message}")
    
    # OFB Mode
    print(f"\n--- OFB Mode ---")
    iv = get_random_bytes(16)
    print(f"IV (hex): {binascii.hexlify(iv).decode()}")
    
    cipher = AES.new(key_256, AES.MODE_OFB, iv)
    ciphertext_ofb = cipher.encrypt(message.encode())
    
    cipher = AES.new(key_256, AES.MODE_OFB, iv)
    decrypted_ofb = cipher.decrypt(ciphertext_ofb).decode()
    
    print(f"Ciphertext (hex): {binascii.hexlify(ciphertext_ofb).decode()[:64]}...")
    print(f"Decrypted: {decrypted_ofb}")
    print(f"Success: {decrypted_ofb == message}")
    
    # GCM Mode (Most secure)
    print(f"\n--- GCM Mode ---")
    nonce = get_random_bytes(12)
    aad = b"metadata_for_256bit_test"
    print(f"Nonce (hex): {binascii.hexlify(nonce).decode()}")
    print(f"AAD: {aad.decode()}")
    
    cipher = AES.new(key_256, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ciphertext_gcm, auth_tag = cipher.encrypt_and_digest(message.encode())
    
    cipher = AES.new(key_256, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    decrypted_gcm = cipher.decrypt_and_verify(ciphertext_gcm, auth_tag).decode()
    
    print(f"Ciphertext (hex): {binascii.hexlify(ciphertext_gcm).decode()[:64]}...")
    print(f"Auth Tag (hex): {binascii.hexlify(auth_tag).decode()}")
    print(f"Decrypted: {decrypted_gcm}")
    print(f"Success: {decrypted_gcm == message}")

def performance_comparison():
    """Compare performance across different AES key sizes"""
    print_separator("Performance Comparison Across Key Sizes")
    
    message = "Performance test message for AES encryption" * 10  # Larger message
    
    # Test data for different key sizes
    key_128 = get_random_bytes(16)
    key_192 = get_random_bytes(24)
    key_256 = get_random_bytes(32)
    
    # Test each key size
    for key_size, key in [(128, key_128), (192, key_192), (256, key_256)]:
        print(f"\n--- AES-{key_size} Performance ---")
        
        # Time ECB encryption
        start_time = time.time()
        for _ in range(1000):  # Encrypt 1000 times
            cipher = AES.new(key, AES.MODE_ECB)
            padded = pad(message.encode(), AES.block_size)
            ciphertext = cipher.encrypt(padded)
        end_time = time.time()
        
        print(f"1000 ECB encryptions: {(end_time - start_time)*1000:.2f} ms")
        print(f"Key Size: {key_size} bits ({len(key)} bytes)")
        print(f"Rounds: {10 + (key_size - 128) // 32 * 2}")  # Formula for AES rounds

def key_size_differences():
    """Explain the differences between AES key sizes"""
    print_separator("Key Size Differences and Implications")
    
    print("AES Key Size Comparison:")
    print("┌─────────┬───────────┬─────────┬──────────────┬─────────────────┐")
    print("│ Version │ Key Size  │ Rounds  │ Security     │ Common Usage    │")
    print("├─────────┼───────────┼─────────┼──────────────┼─────────────────┤")
    print("│ AES-128 │ 128 bits  │   10    │ High         │ General purpose │")
    print("│ AES-192 │ 192 bits  │   12    │ Very High    │ Government      │")
    print("│ AES-256 │ 256 bits  │   14    │ Extremely    │ Top Secret      │")
    print("└─────────┴───────────┴─────────┴──────────────┴─────────────────┘")
    
    print(f"\nWhat Changes with Different Key Sizes:")
    print(f"• Key Length: Longer keys = more security, slightly slower")
    print(f"• Number of Rounds: More rounds = more processing")
    print(f"• Block Size: Always 128 bits (16 bytes) regardless of key size")
    print(f"• IV/Nonce Size: Depends on mode, not key size")
    print(f"• Security: Longer keys resist brute force attacks better")
    
    print(f"\nWhat Stays the Same:")
    print(f"• Block size is always 128 bits (16 bytes)")
    print(f"• All modes (ECB, CBC, CFB, OFB, CTR, GCM) work with all key sizes")
    print(f"• IV size depends on mode, not key size")
    print(f"• Padding requirements are the same")
    print(f"• Authentication tag size in GCM mode remains 128 bits")

def main():
    """Run all AES key size demonstrations"""
    print("🔐 AES Key Sizes (128, 192, 256 bits) Demonstration")
    
    # Demonstrate each key size
    aes_128_demo()    # 128-bit key
    aes_192_demo()    # 192-bit key  
    aes_256_demo()    # 256-bit key
    
    # Performance and differences
    performance_comparison()
    key_size_differences()
    
    print(f"\n{'='*60}")
    print("All AES key sizes demonstrated successfully!")
    print("Key takeaway: Block size stays 128-bit, but security increases")
    print("with longer keys at the cost of slightly more computation.")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()