import os
import json
import socket
import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path

from Crypto.PublicKey import RSA, ElGamal
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import MD5
from Crypto.Random import get_random_bytes, random
from Crypto.Util.number import GCD, inverse
from phe import paillier

# Configuration
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000
CLIENT_STATE_FILE = "client_state.json"
INPUT_DIR = "inputdata"


def ensure_dirs():
    Path(INPUT_DIR).mkdir(exist_ok=True)


def load_client_state():
    if not os.path.exists(CLIENT_STATE_FILE):
        return {"doctor_id": None, "elgamal": {}, "server_keys": {}}
    with open(CLIENT_STATE_FILE, "r") as f:
        return json.load(f)


def save_client_state(state):
    with open(CLIENT_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def send_request(action, role, body):
    """Send JSON request to server and receive response."""
    req = {"action": action, "role": role, "body": body}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_HOST, SERVER_PORT))
        sock.sendall((json.dumps(req) + "\n").encode())
        data = sock.recv(4096).decode()
        sock.close()
        return json.loads(data)
    except Exception as e:
        return {"status": "error", "error": f"Connection failed: {e}"}


def b64e(b: bytes) -> str:
    import base64
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    import base64
    return base64.b64decode(s.encode())


def fetch_server_keys(state):
    """Get server's public keys."""
    resp = send_request("get_public_info", "doctor", {})
    if resp.get("status") == "ok":
        state["server_keys"] = resp.get("data", {})
        save_client_state(state)
        print("Server keys fetched.")
        return True
    else:
        print(f"Failed to fetch server keys: {resp.get('error')}")
        return False


def register_doctor_client(state):
    """Register a new doctor with the server."""
    print("\n=== Doctor Registration ===")
    doctor_id = input("Choose doctor ID (alphanumeric): ").strip()
    if not doctor_id.isalnum():
        print("Invalid doctor ID.")
        return

    name = input("Doctor name: ").strip()
    department = input("Department: ").strip()

    if not state["server_keys"]:
        print("Fetch server keys first.")
        return

    # --- ElGamal key generation (used for signing medical data) ---
    eg_key = ElGamal.generate(512, get_random_bytes)
    p = int(eg_key.p)   # prime modulus used for modular arithmetic
    g = int(eg_key.g)   # generator for ElGamal computations
    y = int(eg_key.y)   # public key (shared with server to verify doctor’s signatures)
    x = int(eg_key.x)   # private key (kept secret by doctor, used for signing)

    state["doctor_id"] = doctor_id
    state["elgamal"] = {"p": p, "g": g, "y": y, "x": x}

    # --- Paillier encryption setup (for secure department storage) ---
    paillier_n = int(state["server_keys"]["paillier_n"])  # server’s Paillier modulus
    paillier_pub = paillier.PaillierPublicKey(paillier_n)

    dept_hash = int.from_bytes(hashlib.md5(department.encode()).digest(), "big")  # hashed for fixed size
    dept_enc = paillier_pub.encrypt(dept_hash)  # encrypted using Paillier (homomorphic)

    # --- Send encrypted department + doctor’s ElGamal public key ---
    body = {
        "doctor_id": doctor_id,
        "department_plain": department,
        "dept_enc": {
            "ciphertext": int(dept_enc.ciphertext()),
            "exponent": dept_enc.exponent,
        },
        "elgamal_pub": {"p": p, "g": g, "y": y},
    }

    resp = send_request("register_doctor", "doctor", body)
    if resp.get("status") == "ok":
        save_client_state(state)
        print(f"✓ Doctor '{doctor_id}' registered successfully.")
        print(f"  Name: {name}, Department: {department}")
    else:
        print(f"✗ Registration failed: {resp.get('error')}")


def elgamal_sign(eg_private, msg_bytes):
    """Sign message with ElGamal."""
    p = int(eg_private["p"])
    g = int(eg_private["g"])
    x = int(eg_private["x"])  # private signing key

    H = int.from_bytes(MD5.new(msg_bytes).digest(), "big") % (p - 1)  # hash of message for signature input
    while True:
        k = random.randint(2, p - 2)  # random nonce for each signature
        if GCD(k, p - 1) == 1:
            break

    r = pow(g, k, p)  # part of signature = g^k mod p
    kinv = inverse(k, p - 1)  # modular inverse of nonce
    s = (kinv * (H - x * r)) % (p - 1)  # actual signature value based on private key
    return int(r), int(s)


def submit_report(state):
    """Submit a medical report (encrypted with AES, key encrypted with RSA-OAEP)."""
    if not state["doctor_id"]:
        print("Register as doctor first.")
        return

    ensure_dirs()
    files = [f for f in os.listdir(INPUT_DIR) if f.lower().endswith(".md")]
    if not files:
        print("Place markdown files in inputdata/")
        return

    print("\nAvailable files:")
    for i, f in enumerate(files, 1):
        print(f"  {i}. {f}")

    try:
        idx = int(input("Select file #: ").strip()) - 1
        filename = files[idx]
    except (ValueError, IndexError):
        print("Invalid selection.")
        return

    filepath = os.path.join(INPUT_DIR, filename)
    with open(filepath, "rb") as f:
        report_bytes = f.read()

    timestamp = datetime.now(timezone.utc).isoformat()
    md5_hex = hashlib.md5(report_bytes).hexdigest()  # used to verify report integrity

    # --- Digital signature with ElGamal ---
    msg_to_sign = report_bytes + timestamp.encode()  # message + timestamp bound together
    r, s = elgamal_sign(state["elgamal"], msg_to_sign)  # signature pair

    # --- AES-256 encryption for report confidentiality ---
    aes_key = get_random_bytes(32)  # symmetric key (256-bit)
    cipher = AES.new(aes_key, AES.MODE_EAX)  # EAX mode gives confidentiality + integrity
    ciphertext, tag = cipher.encrypt_and_digest(report_bytes)

    # --- RSA-OAEP encrypts AES key (server can decrypt it later) ---
    rsa_pub_pem = state["server_keys"]["rsa_pub_pem_b64"]  # server’s RSA public key (Base64)
    rsa_pub = RSA.import_key(b64d(rsa_pub_pem))
    rsa_cipher = PKCS1_OAEP.new(rsa_pub)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)  # asymmetric encryption of AES key

    # --- Send encrypted report and encrypted key to server ---
    body = {
        "doctor_id": state["doctor_id"],
        "filename": filename,
        "timestamp": timestamp,
        "md5_hex": md5_hex,
        "sig": {"r": r, "s": s},  # ElGamal signature
        "aes": {
            "key_rsa_oaep_b64": b64e(encrypted_aes_key),  # AES key encrypted via RSA
            "nonce_b64": b64e(cipher.nonce),              # AES nonce (needed for decryption)
            "tag_b64": b64e(tag),                         # integrity tag from AES-EAX
            "ct_b64": b64e(ciphertext),                   # actual encrypted report
        },
    }

    resp = send_request("upload_report", "doctor", body)
    if resp.get("status") == "ok":
        print(f"✓ Report '{filename}' uploaded successfully.")
        print(f"  MD5: {md5_hex}")
        print(f"  Timestamp: {timestamp}")
    else:
        print(f"✗ Upload failed: {resp.get('error')}")


def homo_rsa_encrypt_amount(state, amount):
    """Encrypt amount using homomorphic RSA."""
    if amount < 0 or amount > 100000:
        print("Amount must be 0-100000.")
        return None

    n = int(state["server_keys"]["rsa_n"])          # RSA modulus (part of public key)
    e = int(state["server_keys"]["rsa_e"])          # RSA public exponent
    g = int(state["server_keys"]["rsa_homo_g"])     # generator for homomorphic operation

    # --- Homomorphic RSA encryption formula ---
    # Encrypts 'amount' such that ciphertexts can be multiplied to sum values
    m = pow(g, amount, n)  # base transformation using generator
    c = pow(m, e, n)       # standard RSA encryption step
    return int(c)


def submit_expense(state):
    """Submit an encrypted expense."""
    if not state["doctor_id"]:
        print("Register as doctor first.")
        return

    if not state["server_keys"]:
        print("Fetch server keys first.")
        return

    try:
        amount = int(input("Expense amount (integer, 0-100000): ").strip())
    except ValueError:
        print("Invalid amount.")
        return

    ciphertext = homo_rsa_encrypt_amount(state, amount)
    if ciphertext is None:
        return

    # Ciphertext is sent to server; server can aggregate without decryption
    body = {"doctor_id": state["doctor_id"], "amount_ciphertext": str(ciphertext)}

    resp = send_request("submit_expense", "doctor", body)
    if resp.get("status") == "ok":
        print(f"✓ Expense encrypted and submitted.")
        print(f"  Amount: {amount}")
        print(f"  Ciphertext: {ciphertext}")
    else:
        print(f"✗ Submission failed: {resp.get('error')}")


def doctor_menu(state):
    """Doctor submenu."""
    while True:
        print("\n=== Doctor Menu ===")
        print("1. Register with server")
        print("2. Fetch server keys")
        print("3. Submit report (encrypted)")
        print("4. Submit expense (homomorphic RSA)")
        print("5. Show current doctor ID")
        print("0. Back")

        ch = input("Choice: ").strip()
        if ch == "1":
            register_doctor_client(state)
        elif ch == "2":
            fetch_server_keys(state)
        elif ch == "3":
            submit_report(state)
        elif ch == "4":
            submit_expense(state)
        elif ch == "5":
            doc_id = state.get("doctor_id")
            if doc_id:
                print(f"Current doctor ID: {doc_id}")
            else:
                print("Not registered.")
        elif ch == "0":
            break
        else:
            print("Invalid choice.")


def main():
    ensure_dirs()
    state = load_client_state()

    while True:
        print("\n=== Medical Records Client ===")
        print("1. Doctor operations")
        print("0. Exit")

        ch = input("Choice: ").strip()
        if ch == "1":
            doctor_menu(state)
        elif ch == "0":
            print("Goodbye!")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
