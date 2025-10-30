# ============================================================
# Simple DES/3DES Encryption in Different Modes Demo
# Demonstrates DES and 3DES in ECB, CBC, CFB, OFB modes
# ============================================================

from Crypto.Cipher import DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii

# Import helper functions
from Helpers import tripledes_encrypt, tripledes_decrypt

def print_separator(title):
    """Print a formatted separator with title"""
    print(f"\n{'='*50}")
    print(f"  {title}")
    print(f"{'='*50}")

def des_ecb_demo():
    """Demonstrate DES in ECB mode"""
    print_separator("DES ECB Mode")
    
    # Generate 8-byte DES key
    key = get_random_bytes(8)
    message = "DES ECB test message for encryption!"
    
    print(f"Original message: {message}")
    print(f"Key (hex): {binascii.hexlify(key).decode()}")
    
    # Encrypt
    cipher = DES.new(key, DES.MODE_ECB)
    padded_message = pad(message.encode(), DES.block_size)  # DES block size = 8 bytes
    ciphertext = cipher.encrypt(padded_message)
    print(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode()}")
    
    # Decrypt
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_padded = cipher.decrypt(ciphertext)
    decrypted = unpad(decrypted_padded, DES.block_size).decode()
    print(f"Decrypted: {decrypted}")
    print(f"Success: {decrypted == message}")

def des_cbc_demo():
    """Demonstrate DES in CBC mode"""
    print_separator("DES CBC Mode")
    
    # Generate key and IV
    key = get_random_bytes(8)
    iv = get_random_bytes(8)  # DES IV size = block size = 8 bytes
    message = "DES CBC test message for encryption!"
    
    print(f"Original message: {message}")
    print(f"Key (hex): {binascii.hexlify(key).decode()}")
    print(f"IV (hex): {binascii.hexlify(iv).decode()}")
    
    # Encrypt
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_message = pad(message.encode(), DES.block_size)
    ciphertext = cipher.encrypt(padded_message)
    print(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode()}")
    
    # Decrypt
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    decrypted = unpad(decrypted_padded, DES.block_size).decode()
    print(f"Decrypted: {decrypted}")
    print(f"Success: {decrypted == message}")

def des_cfb_demo():
    """Demonstrate DES in CFB mode"""
    print_separator("DES CFB Mode")
    
    # Generate key and IV
    key = get_random_bytes(8)
    iv = get_random_bytes(8)
    message = "DES CFB test message for encryption!"
    
    print(f"Original message: {message}")
    print(f"Key (hex): {binascii.hexlify(key).decode()}")
    print(f"IV (hex): {binascii.hexlify(iv).decode()}")
    
    # Encrypt - CFB mode doesn't need padding
    cipher = DES.new(key, DES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(message.encode())
    print(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode()}")
    
    # Decrypt
    cipher = DES.new(key, DES.MODE_CFB, iv)
    decrypted = cipher.decrypt(ciphertext).decode()
    print(f"Decrypted: {decrypted}")
    print(f"Success: {decrypted == message}")

def des_ofb_demo():
    """Demonstrate DES in OFB mode"""
    print_separator("DES OFB Mode")
    
    # Generate key and IV
    key = get_random_bytes(8)
    iv = get_random_bytes(8)
    message = "DES OFB test message for encryption!"
    
    print(f"Original message: {message}")
    print(f"Key (hex): {binascii.hexlify(key).decode()}")
    print(f"IV (hex): {binascii.hexlify(iv).decode()}")
    
    # Encrypt - OFB mode doesn't need padding
    cipher = DES.new(key, DES.MODE_OFB, iv)
    ciphertext = cipher.encrypt(message.encode())
    print(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode()}")
    
    # Decrypt
    cipher = DES.new(key, DES.MODE_OFB, iv)
    decrypted = cipher.decrypt(ciphertext).decode()
    print(f"Decrypted: {decrypted}")
    print(f"Success: {decrypted == message}")

def tripledes_ecb_demo():
    """Demonstrate 3DES in ECB mode using helper function"""
    print_separator("3DES ECB Mode")
    
    # Generate 24-byte 3DES key
    key = get_random_bytes(24)
    message = "3DES ECB test message for encryption!"
    
    print(f"Original message: {message}")
    print(f"Key (hex): {binascii.hexlify(key).decode()}")
    
    # Encrypt using helper function
    ciphertext = tripledes_encrypt(message, key)
    print(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode()}")
    
    # Decrypt using helper function
    decrypted = tripledes_decrypt(ciphertext, key)
    print(f"Decrypted: {decrypted}")
    print(f"Success: {decrypted == message}")

def tripledes_cbc_demo():
    """Demonstrate 3DES in CBC mode"""
    print_separator("3DES CBC Mode")
    
    # Generate key and IV
    key = get_random_bytes(24)  # 3DES key is 24 bytes
    iv = get_random_bytes(8)    # Block size is still 8 bytes
    message = "3DES CBC test message for encryption!"
    
    print(f"Original message: {message}")
    print(f"Key (hex): {binascii.hexlify(key).decode()}")
    print(f"IV (hex): {binascii.hexlify(iv).decode()}")
    
    # Encrypt
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_message = pad(message.encode(), DES3.block_size)
    ciphertext = cipher.encrypt(padded_message)
    print(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode()}")
    
    # Decrypt
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    decrypted = unpad(decrypted_padded, DES3.block_size).decode()
    print(f"Decrypted: {decrypted}")
    print(f"Success: {decrypted == message}")

def tripledes_cfb_demo():
    """Demonstrate 3DES in CFB mode"""
    print_separator("3DES CFB Mode")
    
    # Generate key and IV
    key = get_random_bytes(24)
    iv = get_random_bytes(8)
    message = "3DES CFB test message for encryption!"
    
    print(f"Original message: {message}")
    print(f"Key (hex): {binascii.hexlify(key).decode()}")
    print(f"IV (hex): {binascii.hexlify(iv).decode()}")
    
    # Encrypt - CFB mode is a stream cipher, no padding needed
    cipher = DES3.new(key, DES3.MODE_CFB, iv)
    ciphertext = cipher.encrypt(message.encode())
    print(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode()}")
    
    # Decrypt
    cipher = DES3.new(key, DES3.MODE_CFB, iv)
    decrypted = cipher.decrypt(ciphertext).decode()
    print(f"Decrypted: {decrypted}")
    print(f"Success: {decrypted == message}")

def tripledes_ofb_demo():
    """Demonstrate 3DES in OFB mode"""
    print_separator("3DES OFB Mode")
    
    # Generate key and IV
    key = get_random_bytes(24)
    iv = get_random_bytes(8)
    message = "3DES OFB test message for encryption!"
    
    print(f"Original message: {message}")
    print(f"Key (hex): {binascii.hexlify(key).decode()}")
    print(f"IV (hex): {binascii.hexlify(iv).decode()}")
    
    # Encrypt - OFB mode is a stream cipher, no padding needed
    cipher = DES3.new(key, DES3.MODE_OFB, iv)
    ciphertext = cipher.encrypt(message.encode())
    print(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode()}")
    
    # Decrypt
    cipher = DES3.new(key, DES3.MODE_OFB, iv)
    decrypted = cipher.decrypt(ciphertext).decode()
    print(f"Decrypted: {decrypted}")
    print(f"Success: {decrypted == message}")

def main():
    """Run all DES/3DES mode demonstrations"""
    print("🔐 DES/3DES Encryption Modes Demonstration")
    
    # DES modes
    print("\n--- DES (Data Encryption Standard) ---")
    des_ecb_demo()      # Electronic Codebook
    des_cbc_demo()      # Cipher Block Chaining
    des_cfb_demo()      # Cipher Feedback
    des_ofb_demo()      # Output Feedback
    
    # 3DES modes
    print("\n--- 3DES (Triple DES) ---")
    tripledes_ecb_demo()    # ECB with helper function
    tripledes_cbc_demo()    # Cipher Block Chaining
    tripledes_cfb_demo()    # Cipher Feedback
    tripledes_ofb_demo()    # Output Feedback
    
    print(f"\n{'='*50}")
    print("Key differences in modes:")
    print("• ECB & CBC: Require padding (block modes)")
    print("• CFB & OFB: No padding needed (stream modes)")
    print("• DES: 8-byte key, 8-byte block size")
    print("• 3DES: 24-byte key, 8-byte block size")
    print("• IV size: Always 8 bytes for DES/3DES")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()