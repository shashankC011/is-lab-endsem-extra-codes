import logging
from datetime import datetime

# --- Setup logging ---
logging.basicConfig(
    filename="audit_log.txt",       # log file
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_action(action_desc):
    """Log an action with timestamp"""
    logging.info(action_desc)   # writes the log to audit_log.txt
    print(f"[LOGGED] {action_desc}")

# --- Example menu-driven framework with logging ---
def menu():
    while True:
        print("\n=== Information Security Lab Menu ===")
        print("1. DES Encryption/Decryption")
        print("2. AES Encryption/Decryption")
        print("3. 3DES Encryption/Decryption")
        print("4. RSA Encrypt/Decrypt")
        print("5. RSA Sign/Verify")
        print("6. Exit")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            des_menu()
        elif choice == "2":
            aes_menu()
        elif choice == "3":
            des3_menu()
        elif choice == "4":
            rsa_encrypt_decrypt_menu()
        elif choice == "5":
            rsa_sign_verify_menu()
        elif choice == "6":
            log_action("Exiting program")
            break
        else:
            print("Invalid choice! Try again.")

# --- Example submenus with logging ---
def des_menu():
    print("\n[DES Encryption/Decryption]")
    plaintext = input("Enter plaintext: ").encode()
    # Here you would call your DES encryption/decryption functions
    log_action(f"DES operation on message: {plaintext}")
    print("Placeholder for DES encrypt/decrypt")

def aes_menu():
    print("\n[AES Encryption/Decryption]")
    plaintext = input("Enter plaintext: ").encode()
    log_action(f"AES operation on message: {plaintext}")
    print("Placeholder for AES encrypt/decrypt")

def des3_menu():
    print("\n[3DES Encryption/Decryption]")
    plaintext = input("Enter plaintext: ").encode()
    log_action(f"3DES operation on message: {plaintext}")
    print("Placeholder for 3DES encrypt/decrypt")

def rsa_encrypt_decrypt_menu():
    print("\n[RSA Encrypt/Decrypt]")
    message = input("Enter message: ").encode()
    log_action(f"RSA encryption/decryption requested for message: {message}")
    print("Placeholder for RSA encrypt/decrypt")

def rsa_sign_verify_menu():
    print("\n[RSA Sign/Verify]")
    message = input("Enter message: ").encode()
    log_action(f"RSA sign/verify requested for message: {message}")
    print("Placeholder for RSA sign/verify")

# --- Run menu ---
if __name__ == "__main__":
    log_action("Program started")
    menu()
