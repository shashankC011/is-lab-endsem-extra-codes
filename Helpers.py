"""
This file provides a collection of Python functions for demonstrating
various cryptographic algorithms and concepts.

--- 1. General Utility Functions ---
- gcd(a, b): Calculates the greatest common divisor of two integers.
- mod_inverse(a, m): Finds the modular multiplicative inverse of `a` modulo `m`.
- is_prime(n, k=5): Performs a probabilistic test to check if a number is prime.
- int_to_fixed_block(value, block_size=16): Converts an integer into a fixed-size byte block.
- fixed_block_to_int(block): Converts a fixed-size byte block back into an integer.

--- 2. Classical Symmetric Ciphers ---
- caesar_encrypt(text, key): Encrypts text using the Caesar cipher.
- caesar_decrypt(cipher, key): Decrypts text from a Caesar cipher.
- affine_encrypt(text, a, b): Encrypts text using the Affine cipher.
- affine_decrypt(cipher, a, b): Decrypts text from an Affine cipher.
- playfair_encrypt(plaintext, key): Encrypts text using the Playfair cipher.
- playfair_decrypt(ciphertext, key): Decrypts text from a Playfair cipher.
- hill_encrypt(plaintext, key_matrix): Encrypts text using a 2x2 Hill cipher.
- hill_decrypt(ciphertext, key_matrix): Decrypts text from a 2x2 Hill cipher.

--- 3. AES / DES Helpers ---
- aes_encrypt(plaintext, key, mode, iv): Encrypts a string using AES with a specified mode.
- aes_decrypt(ciphertext, key, mode, iv): Decrypts a string using AES with a specified mode.
- tripledes_encrypt(plaintext, key): Encrypts a string using Triple DES.
- tripledes_decrypt(ciphertext, key): Decrypts a string using Triple DES.
- aes_encrypt_bytes(data, key, mode, iv): Encrypts raw bytes using AES.
- aes_decrypt_bytes(ciphertext, key, mode, iv): Decrypts raw bytes using AES.

--- 4. RSA ---
- rsa_keygen(bits=1024): Generates an RSA public and private key pair.
- rsa_encrypt(m, pubkey): Encrypts an integer message with an RSA public key.
- rsa_decrypt(c, privkey): Decrypts an integer ciphertext with an RSA private key.

--- 5. ElGamal ---
- elgamal_keygen(bits=512): Generates an ElGamal public key and private key.
- elgamal_encrypt(m, pubkey): Encrypts an integer message with an ElGamal public key.
- elgamal_decrypt(cipher, privkey, p): Decrypts an ElGamal ciphertext.

--- 6. Elliptic Curve Cryptography (ECC) ---
- ecc_keygen(curve): Generates an ECC private key (integer) and public key (point).
- ecc_encrypt(message_bytes, pubkey_point, curve): Encrypts a byte message using an ECC public key point.
- ecc_decrypt(cipher_tuple, privkey_d, curve): Decrypts an ECC ciphertext using a private key.

--- 7. Rabin ---
- rabin_keygen(bits=512): Generates a Rabin public key (`n`) and private key (`p, q`).
- rabin_encrypt(m, n): Encrypts an integer message with a Rabin public key.
- rabin_decrypt(c, priv): Decrypts a Rabin ciphertext, returning four possible results.

--- 8. Diffie-Hellman ---
- dh_generate_params(bits=512): Generates public parameters `p` and `g`.
- dh_generate_private(p): Generates a user's private key.
- dh_generate_public(g, priv, p): Generates a user's public key from their private key.
- dh_compute_shared(pub_other, priv_self, p): Computes the final shared secret key.

--- 9. Hashing Functions ---
- custom_hash(text): Computes a simple non-cryptographic hash of a string.
- md5_hash(text): Computes the MD5 hash of a string.
- sha1_hash(text): Computes the SHA-1 hash of a string.
- sha256_hash(text): Computes the SHA-256 hash of a string.
- compute_hash_bytes(data, algo="sha256"): Computes the hash of raw byte data.
- verify_integrity_bytes(data, received_hash, algo="sha256"): Verifies the hash of byte data.

--- 10. Digital Signatures (RSA) ---
- rsa_sign(message, privkey): Creates a digital signature for a message using an RSA private key.
- rsa_verify(message, signature, pubkey): Verifies an RSA digital signature using the public key.

--- 11. Paillier (Homomorphic Addition) ---
- paillier_keygen(bits=512): Generates a Paillier public and private key pair.
- paillier_encrypt(m, pubkey): Encrypts a message using the Paillier public key.
- paillier_decrypt(c, pubkey, privkey): Decrypts a Paillier ciphertext.
- paillier_add(c1, c2, pubkey): Homomorphically adds two Paillier ciphertexts.

--- 12. Searchable Encryption ---
- sse_create_index(documents, key): Creates a simple searchable keyword index from text documents.
- sse_search(index, query, key): Searches the encrypted index for a query keyword.

--- 13. Testing & Validation Helpers ---
- test_case_runner(test_cases, func): Runs a function against a list of test cases and expected outputs.
"""
import math
import random
import hashlib
from Crypto.Util.number import getPrime, inverse, GCD
from Crypto.Cipher import AES, DES3
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Random import get_random_bytes

# ------------------------------
# 1. General Utility Functions
# ------------------------------

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def mod_inverse(a, m):
    # Uses Python 3.8+ built-in pow inverse when available
    return pow(a, -1, m)


def is_prime(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
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


def int_to_fixed_block(value: int, block_size: int = 16) -> bytes:
    """
    Convert an integer (e.g. RSA ciphertext) into a fixed-size byte block.
    Pads with leading zeros to match the desired block_size.
    """
    b = long_to_bytes(value)
    return b.rjust(block_size, b'\x00')


def fixed_block_to_int(block: bytes) -> int:
    """
    Convert a fixed-size byte block back into an integer.
    Strips leading zeros automatically.
    """
    return bytes_to_long(block)

# ------------------------------
# 2. Classical Symmetric Ciphers
# ------------------------------

def caesar_encrypt(text, key):
    return ''.join(chr(((ord(c) - 97 + key) % 26) + 97) if c.isalpha() else c for c in text.lower())


def caesar_decrypt(cipher, key):
    return ''.join(chr(((ord(c) - 97 - key) % 26) + 97) if c.isalpha() else c for c in cipher.lower())

# Affine Cipher

def affine_encrypt(text, a, b):
    return ''.join(chr(((a * (ord(c) - 97) + b) % 26) + 97) if c.isalpha() else c for c in text.lower())


def affine_decrypt(cipher, a, b):
    a_inv = mod_inverse(a, 26)
    return ''.join(chr(((a_inv * ((ord(c) - 97 - b)) % 26) + 97)) if c.isalpha() else c for c in cipher.lower())

# Playfair Cipher (Implemented)

def _prepare_playfair_text(text):
    text = ''.join([c for c in text.lower() if c.isalpha()])
    text = text.replace('j', 'i')
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else 'x'
        if a == b:
            pairs.append((a, 'x'))
            i += 1
        else:
            pairs.append((a, b))
            i += 2
    if len(pairs) > 0 and len(pairs[-1][1]) == 0:
        pairs[-1] = (pairs[-1][0], 'x')
    return pairs


def _build_playfair_matrix(key):
    key = ''.join([c for c in key.lower() if c.isalpha()])
    key = key.replace('j', 'i')
    seen = set()
    matrix_list = []
    for c in key:
        if c not in seen:
            seen.add(c)
            matrix_list.append(c)
    for c in 'abcdefghijklmnopqrstuvwxyz':
        if c == 'j':
            continue
        if c not in seen:
            seen.add(c)
            matrix_list.append(c)
    matrix = [matrix_list[i*5:(i+1)*5] for i in range(5)]
    pos = {matrix[r][c]: (r, c) for r in range(5) for c in range(5)}
    return matrix, pos


def playfair_encrypt(plaintext, key):
    matrix, pos = _build_playfair_matrix(key)
    pairs = _prepare_playfair_text(plaintext)
    cipher = ''
    for a, b in pairs:
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            cipher += matrix[ra][(ca+1)%5]
            cipher += matrix[rb][(cb+1)%5]
        elif ca == cb:
            cipher += matrix[(ra+1)%5][ca]
            cipher += matrix[(rb+1)%5][cb]
        else:
            cipher += matrix[ra][cb]
            cipher += matrix[rb][ca]
    return cipher.upper()


def playfair_decrypt(ciphertext, key):
    ciphertext = ''.join([c for c in ciphertext.lower() if c.isalpha()])
    matrix, pos = _build_playfair_matrix(key)
    pairs = [(ciphertext[i], ciphertext[i+1]) for i in range(0, len(ciphertext), 2)]
    plain = ''
    for a, b in pairs:
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            plain += matrix[ra][(ca-1)%5]
            plain += matrix[rb][(cb-1)%5]
        elif ca == cb:
            plain += matrix[(ra-1)%5][ca]
            plain += matrix[(rb-1)%5][cb]
        else:
            plain += matrix[ra][cb]
            plain += matrix[rb][ca]
    return plain.replace('x', '')

# Hill Cipher (2x2 implemented)

def _matrix_mod_inv_2x2(mat, mod=26):
    a, b = mat[0]
    c, d = mat[1]
    det = (a*d - b*c) % mod
    det_inv = mod_inverse(det, mod)
    inv = [[(d * det_inv) % mod, ((-b) * det_inv) % mod], [((-c) * det_inv) % mod, (a * det_inv) % mod]]
    return inv


def _matrix_mult_vec_2x2(mat, vec, mod=26):
    return [ (mat[0][0]*vec[0] + mat[0][1]*vec[1]) % mod, (mat[1][0]*vec[0] + mat[1][1]*vec[1]) % mod ]


def hill_encrypt(plaintext, key_matrix):
    text = ''.join([c for c in plaintext.lower() if c.isalpha()])
    if len(text) % 2 != 0:
        text += 'x'
    cipher = ''
    for i in range(0, len(text), 2):
        vec = [ord(text[i])-97, ord(text[i+1])-97]
        res = _matrix_mult_vec_2x2(key_matrix, vec)
        cipher += chr(res[0]+97) + chr(res[1]+97)
    return cipher


def hill_decrypt(ciphertext, key_matrix):
    inv = _matrix_mod_inv_2x2(key_matrix)
    plain = ''
    for i in range(0, len(ciphertext),2):
        vec = [ord(ciphertext[i])-97, ord(ciphertext[i+1])-97]
        res = _matrix_mult_vec_2x2(inv, vec)
        plain += chr(res[0]+97) + chr(res[1]+97)
    return plain

# ------------------------------
# 3. AES / DES Helpers
# ------------------------------

def aes_encrypt(plaintext, key, mode=AES.MODE_ECB, iv=None):
    cipher = AES.new(key, mode, iv=iv) if iv else AES.new(key, mode)
    pad_len = AES.block_size - (len(plaintext) % AES.block_size)
    padded = plaintext + chr(pad_len)*pad_len
    return cipher.encrypt(padded.encode())


def aes_decrypt(ciphertext, key, mode=AES.MODE_ECB, iv=None):
    cipher = AES.new(key, mode, iv=iv) if iv else AES.new(key, mode)
    padded = cipher.decrypt(ciphertext)
    pad_len = padded[-1]
    return padded[:-pad_len].decode()


def tripledes_encrypt(plaintext, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    pad_len = 8 - (len(plaintext) % 8)
    padded = plaintext + chr(pad_len)*pad_len
    return cipher.encrypt(padded.encode())


def tripledes_decrypt(ciphertext, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded = cipher.decrypt(ciphertext)
    pad_len = padded[-1]
    return padded[:-pad_len].decode()

def aes_encrypt_bytes(data: bytes, key: bytes, mode=AES.MODE_ECB, iv=None):
    cipher = AES.new(key, mode, iv=iv) if iv else AES.new(key, mode)
    pad_len = AES.block_size - (len(data) % AES.block_size)
    padded = data + bytes([pad_len])*pad_len
    return cipher.encrypt(padded)

def aes_decrypt_bytes(ciphertext: bytes, key: bytes, mode=AES.MODE_ECB, iv=None):
    cipher = AES.new(key, mode, iv=iv) if iv else AES.new(key, mode)
    padded = cipher.decrypt(ciphertext)
    pad_len = padded[-1]
    return padded[:-pad_len]

# ------------------------------
# 4. RSA
# ------------------------------

def rsa_keygen(bits=1024):
    p = getPrime(bits//2)
    q = getPrime(bits//2)
    n = p * q
    phi = (p-1)*(q-1)
    e = 65537
    d = inverse(e, phi)
    return (n, e), (n, d)


def rsa_encrypt(m, pubkey):
    n, e = pubkey
    return pow(m, e, n)


def rsa_decrypt(c, privkey):
    n, d = privkey
    return pow(c, d, n)

# ------------------------------
# 5. ElGamal (Implemented over prime field)
# ------------------------------

def elgamal_keygen(bits=512):
    # Generate prime p and use g=2 (for simplicity). In production, pick proper generator.
    p = getPrime(bits)
    g = 2
    x = random.randint(2, p-2)
    y = pow(g, x, p)
    return (p, g, y), x


def elgamal_encrypt(m, pubkey):
    p, g, y = pubkey
    k = random.randint(2, p-2)
    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (m * s) % p
    return (c1, c2)


def elgamal_decrypt(cipher, privkey, p):
    c1, c2 = cipher
    x = privkey
    s = pow(c1, x, p)
    s_inv = mod_inverse(s, p)
    m = (c2 * s_inv) % p
    return m

# ------------------------------
# 6. ECC (Simple ECIES-like encryption on short messages)
# Note: This is an educational toy implementation. Use a library for production.
# ------------------------------

class Curve:
    def __init__(self, p, a, b, Gx, Gy, n):
        self.p = p
        self.a = a
        self.b = b
        self.G = (Gx, Gy)
        self.n = n


def _point_add(P, Q, curve):
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1) = P
    (x2, y2) = Q
    p = curve.p
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P != Q:
        lam = ((y2 - y1) * mod_inverse(x2 - x1, p)) % p
    else:
        lam = ((3 * x1 * x1 + curve.a) * mod_inverse(2 * y1, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def _point_mul(k, P, curve):
    R = None
    Q = P
    while k > 0:
        if k & 1:
            R = _point_add(R, Q, curve)
        Q = _point_add(Q, Q, curve)
        k >>= 1
    return R


def ecc_keygen(curve):
    d = random.randint(2, curve.n-2)
    Q = _point_mul(d, curve.G, curve)
    return d, Q


def ecc_encrypt(message_bytes, pubkey_point, curve):
    # ephemeral key
    k = random.randint(2, curve.n-2)
    C1 = _point_mul(k, curve.G, curve)
    S = _point_mul(k, pubkey_point, curve)
    if S is None:
        raise ValueError("Invalid shared secret")
    shared = hashlib.sha256(str(S[0]).encode()).digest()
    # XOR message with shared keystream
    ct = bytes(m ^ shared[i % len(shared)] for i, m in enumerate(message_bytes))
    return (C1, ct)


def ecc_decrypt(cipher_tuple, privkey_d, curve):
    C1, ct = cipher_tuple
    S = _point_mul(privkey_d, C1, curve)
    shared = hashlib.sha256(str(S[0]).encode()).digest()
    msg = bytes(c ^ shared[i % len(shared)] for i, c in enumerate(ct))
    return msg

# ------------------------------
# 7. Rabin (Implemented)
# ------------------------------

def rabin_keygen(bits=512):
    # Generate p and q such that p % 4 == 3 and q % 4 == 3
    while True:
        p = getPrime(bits)
        if p % 4 == 3:
            break
    while True:
        q = getPrime(bits)
        if q % 4 == 3 and q != p:
            break
    n = p * q
    return n, (p, q)


def rabin_encrypt(m, n):
    return pow(m, 2, n)


def _crt(a1, m1, a2, m2):
    # Solve x ≡ a1 (mod m1), x ≡ a2 (mod m2)
    m1_inv = mod_inverse(m1, m2)
    t = ((a2 - a1) * m1_inv) % m2
    return (a1 + m1 * t) % (m1 * m2)


def rabin_decrypt(c, priv):
    p, q = priv
    n = p * q
    mp = pow(c, (p+1)//4, p)
    mq = pow(c, (q+1)//4, q)
    # compute CRT combinations
    # find coefficients yp, yq such that yp*p + yq*q = 1
    yp = mod_inverse(p, q)
    yq = mod_inverse(q, p)
    r1 = _crt(mp, p, mq, q)
    r2 = n - r1
    r3 = _crt(mp, p, -mq % q, q)
    r4 = n - r3
    return [r1, r2, r3, r4]

# ------------------------------
# 8. Diffie-Hellman (Implemented)
# ------------------------------

def dh_generate_params(bits=512):
    p = getPrime(bits)
    g = 2
    return p, g


def dh_generate_private(p):
    return random.randint(2, p-2)


def dh_generate_public(g, priv, p):
    return pow(g, priv, p)


def dh_compute_shared(pub_other, priv_self, p):
    return pow(pub_other, priv_self, p)

# ------------------------------
# 9. Hashing Functions
# ------------------------------

def custom_hash(text):
    h = 5381
    for c in text:
        h = ((h * 33) + ord(c)) & 0xFFFFFFFF
    return h


def md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()


def sha1_hash(text):
    return hashlib.sha1(text.encode()).hexdigest()


def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

def compute_hash_bytes(data: bytes, algo: str = "sha256") -> str:
    """
    Compute hash for byte data using existing helpers.
    """
    text = data.decode(errors="ignore")  # convert bytes → string safely
    if algo == "sha256":
        return sha256_hash(text)
    elif algo == "sha1":
        return sha1_hash(text)
    elif algo == "md5":
        return md5_hash(text)
    elif algo == "custom":
        return str(custom_hash(text))
    else:
        raise ValueError("Unsupported hash algorithm")


def verify_integrity_bytes(data: bytes, received_hash: str, algo: str = "sha256") -> bool:
    """
    Verify integrity of byte data using existing hash helpers.
    """
    local_hash = compute_hash_bytes(data, algo)
    return local_hash == received_hash


# ------------------------------
# 10. Digital Signatures (RSA)
# ------------------------------

def rsa_sign(message, privkey):
    h = int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big')
    n, d = privkey
    return pow(h, d, n)


def rsa_verify(message, signature, pubkey):
    h = int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big')
    n, e = pubkey
    return h == pow(signature, e, n)

# ------------------------------
# 11. Paillier (Homomorphic Addition)
# ------------------------------

def paillier_keygen(bits=512):
    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q
    lam = (p-1)*(q-1)//gcd(p-1, q-1)
    g = n+1
    mu = mod_inverse(lam, n)
    return (n, g), (lam, mu)


def paillier_encrypt(m, pubkey):
    n, g = pubkey
    r = random.randint(1, n-1)
    return (pow(g, m, n*n) * pow(r, n, n*n)) % (n*n)


def paillier_decrypt(c, pubkey, privkey):
    n, g = pubkey
    lam, mu = privkey
    x = pow(c, lam, n*n)
    l = (x-1)//n
    return (l * mu) % n


def paillier_add(c1, c2, pubkey):
    n, g = pubkey
    return (c1 * c2) % (n*n)

# ------------------------------
# 12. Searchable Encryption (Toy Example)
# ------------------------------

def sse_create_index(documents, key):
    index = {}
    for doc_id, doc in documents.items():
        for word in doc.split():
            h = hashlib.sha256((key+word).encode()).hexdigest()
            index.setdefault(h, []).append(doc_id)
    return index


def sse_search(index, query, key):
    h = hashlib.sha256((key+query).encode()).hexdigest()
    return index.get(h, [])

# ------------------------------
# 13. Testing & Validation Helpers
# ------------------------------

def test_case_runner(test_cases, func):
    results = []
    for case in test_cases:
        inp, expected = case
        output = func(*inp)
        results.append((output == expected, output))
    return results

# End of helper library
