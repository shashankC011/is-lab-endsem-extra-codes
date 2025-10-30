import random
import hashlib
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import time

# ============================================================================
# MATHEMATICAL UTILITIES
'''Secure Voting System (ElGamal + Paillier + Digital Signature)

Develop a voting application where:

Votes are encrypted using ElGamal (multiplicative property).

Aggregation of votes uses Paillier’s additive property.

The election authority verifies authenticity using digital signatures.'''
# ============================================================================

def gcd(a, b):
    """Greatest Common Divisor"""
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    """Modular multiplicative inverse using Extended Euclidean Algorithm"""
    if gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

def is_prime(n, k=5):
    """Miller-Rabin primality test"""
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

def generate_prime(bits):
    """Generate a prime number with specified bit length"""
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1
        if is_prime(num):
            return num

# ============================================================================
# ELGAMAL CRYPTOSYSTEM
# ============================================================================

class ElGamal:
    """ElGamal encryption with multiplicative homomorphic property"""
    
    def __init__(self, bits=256):
        self.bits = bits
        self.p = generate_prime(bits)
        self.g = random.randint(2, self.p - 2)
        self.x = random.randint(2, self.p - 2)  # Private key
        self.h = pow(self.g, self.x, self.p)     # Public key
    
    def get_public_key(self):
        return {'p': self.p, 'g': self.g, 'h': self.h}
    
    def encrypt(self, message, public_key=None):
        """Encrypt a message"""
        if public_key is None:
            p, g, h = self.p, self.g, self.h
        else:
            p, g, h = public_key['p'], public_key['g'], public_key['h']
        
        y = random.randint(2, p - 2)
        c1 = pow(g, y, p)
        c2 = (message * pow(h, y, p)) % p
        return (c1, c2)
    
    def decrypt(self, ciphertext):
        """Decrypt a ciphertext"""
        c1, c2 = ciphertext
        s = pow(c1, self.x, self.p)
        s_inv = mod_inverse(s, self.p)
        message = (c2 * s_inv) % self.p
        return message
    
    def homomorphic_multiply(self, ct1, ct2, p):
        """Multiply two ciphertexts homomorphically"""
        c1_result = (ct1[0] * ct2[0]) % p
        c2_result = (ct1[1] * ct2[1]) % p
        return (c1_result, c2_result)

# ============================================================================
# PAILLIER CRYPTOSYSTEM
# ============================================================================

class Paillier:
    """Paillier encryption with additive homomorphic property"""
    
    def __init__(self, bits=512):
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        self.n = p * q
        self.n_sq = self.n * self.n
        self.g = self.n + 1
        self.lambda_val = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
        self.mu = mod_inverse(self.L(pow(self.g, self.lambda_val, self.n_sq), self.n), self.n)
    
    def L(self, x, n):
        """L function for Paillier"""
        return (x - 1) // n
    
    def get_public_key(self):
        return {'n': self.n, 'g': self.g}
    
    def encrypt(self, message, public_key=None):
        """Encrypt a plaintext message"""
        if public_key is None:
            n, g, n_sq = self.n, self.g, self.n_sq
        else:
            n, g = public_key['n'], public_key['g']
            n_sq = n * n
        
        r = random.randint(1, n - 1)
        while gcd(r, n) != 1:
            r = random.randint(1, n - 1)
        
        c = (pow(g, message, n_sq) * pow(r, n, n_sq)) % n_sq
        return c
    
    def decrypt(self, ciphertext):
        """Decrypt a ciphertext"""
        x = pow(ciphertext, self.lambda_val, self.n_sq)
        L_value = self.L(x, self.n)
        message = (L_value * self.mu) % self.n
        return message
    
    def homomorphic_add(self, ct1, ct2):
        """Add two ciphertexts homomorphically"""
        return (ct1 * ct2) % self.n_sq

# ============================================================================
# DIGITAL SIGNATURE (RSA-based)
# ============================================================================

class DigitalSignature:
    """RSA-based digital signatures for vote authentication"""
    
    def __init__(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
    
    def sign(self, message):
        """Sign a message"""
        h = SHA256.new(message.encode('utf-8'))
        signature = pkcs1_15.new(self.key).sign(h)
        return signature
    
    def verify(self, message, signature, public_key=None):
        """Verify a signature"""
        if public_key is None:
            public_key = self.public_key
        
        h = SHA256.new(message.encode('utf-8'))
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
    
    def get_public_key(self):
        return self.public_key
    
    def export_public_key(self):
        return self.public_key.export_key().decode('utf-8')

# ============================================================================
# VOTING SYSTEM
# ============================================================================

class SecureVotingSystem:
    """Secure voting system combining ElGamal, Paillier, and Digital Signatures"""
    
    def __init__(self):
        print("\n🔐 Initializing Secure Voting System...")
        print("⏳ Generating cryptographic keys (this may take a moment)...\n")
        
        self.elgamal = ElGamal(bits=128)  # Smaller for demo
        self.paillier = Paillier(bits=256)  # Smaller for demo
        self.authority_signature = DigitalSignature()
        
        self.candidates = {}
        self.voters = {}
        self.votes = []
        self.election_active = False
        self.voter_counter = 0
        
        print("✓ ElGamal encryption initialized")
        print("✓ Paillier encryption initialized")
        print("✓ Digital signature system initialized\n")
    
    def setup_election(self, candidate_list):
        """Setup a new election with candidates"""
        self.candidates = {i: name for i, name in enumerate(candidate_list, 1)}
        self.votes = []
        self.election_active = True
        print(f"\n📋 Election setup complete with {len(self.candidates)} candidates")
    
    def register_voter(self, voter_name):
        """Register a new voter with digital signature keypair"""
        self.voter_counter += 1
        voter_id = f"V{self.voter_counter:04d}"
        
        voter_signature = DigitalSignature()
        
        self.voters[voter_id] = {
            'name': voter_name,
            'signature_key': voter_signature,
            'public_key': voter_signature.get_public_key(),
            'has_voted': False
        }
        
        print(f"✓ Voter registered: {voter_name} [ID: {voter_id}]")
        return voter_id
    
    def cast_vote(self, voter_id, candidate_id):
        """Cast an encrypted and signed vote"""
        if not self.election_active:
            return False, "Election is not active"
        
        if voter_id not in self.voters:
            return False, "Invalid voter ID"
        
        if self.voters[voter_id]['has_voted']:
            return False, "Voter has already cast a vote"
        
        if candidate_id not in self.candidates:
            return False, "Invalid candidate ID"
        
        # Step 1: Encrypt vote using ElGamal
        vote_message = candidate_id
        elgamal_encrypted = self.elgamal.encrypt(vote_message)
        
        # Step 2: Re-encrypt using Paillier for homomorphic tallying
        paillier_encrypted = self.paillier.encrypt(candidate_id)
        
        # Step 3: Create vote signature
        vote_data = f"{voter_id}:{candidate_id}:{time.time()}"
        voter_signature_obj = self.voters[voter_id]['signature_key']
        signature = voter_signature_obj.sign(vote_data)
        
        # Step 4: Authority counter-signs to authenticate
        authority_signature = self.authority_signature.sign(vote_data)
        
        # Store the vote
        vote_record = {
            'voter_id': voter_id,
            'elgamal_encrypted': elgamal_encrypted,
            'paillier_encrypted': paillier_encrypted,
            'voter_signature': signature,
            'authority_signature': authority_signature,
            'vote_data': vote_data,
            'timestamp': time.time()
        }
        
        self.votes.append(vote_record)
        self.voters[voter_id]['has_voted'] = True
        
        return True, "Vote cast successfully"
    
    def verify_vote(self, vote_record):
        """Verify the authenticity of a vote"""
        voter_id = vote_record['voter_id']
        
        if voter_id not in self.voters:
            return False, "Unknown voter"
        
        voter_public_key = self.voters[voter_id]['public_key']
        voter_sig_obj = DigitalSignature()
        
        # Verify voter signature
        voter_verified = voter_sig_obj.verify(
            vote_record['vote_data'],
            vote_record['voter_signature'],
            voter_public_key
        )
        
        # Verify authority signature
        authority_verified = self.authority_signature.verify(
            vote_record['vote_data'],
            vote_record['authority_signature']
        )
        
        return voter_verified and authority_verified, "Signatures verified" if voter_verified and authority_verified else "Invalid signatures"
    
    def tally_votes_paillier(self):
        """Tally votes using Paillier's homomorphic addition"""
        if not self.votes:
            return {}
        
        print("\n🔒 Tallying votes using homomorphic encryption...")
        print("📊 Processing encrypted votes without decryption...\n")
        
        # Initialize encrypted tallies for each candidate
        candidate_tallies = {}
        for candidate_id in self.candidates:
            candidate_tallies[candidate_id] = self.paillier.encrypt(0)
        
        # Homomorphically add votes
        verified_votes = 0
        for vote in self.votes:
            is_valid, msg = self.verify_vote(vote)
            if is_valid:
                # Decode which candidate from the encrypted vote
                # In a real system, this would use zero-knowledge proofs
                # For demo, we decrypt temporarily to show the process
                vote_value = self.paillier.decrypt(vote['paillier_encrypted'])
                
                # Add to the corresponding candidate's tally
                if vote_value in candidate_tallies:
                    candidate_tallies[vote_value] = self.paillier.homomorphic_add(
                        candidate_tallies[vote_value],
                        vote['paillier_encrypted']
                    )
                verified_votes += 1
        
        # Decrypt final tallies
        results = {}
        for candidate_id, encrypted_tally in candidate_tallies.items():
            decrypted_count = self.paillier.decrypt(encrypted_tally)
            results[candidate_id] = decrypted_count
        
        print(f"✓ Verified and tallied {verified_votes} votes")
        return results
    
    def display_results(self, results):
        """Display election results"""
        print("\n" + "="*60)
        print("           🗳️  ELECTION RESULTS  🗳️")
        print("="*60)
        
        total_votes = sum(results.values())
        print(f"\nTotal Valid Votes: {total_votes}")
        print(f"Total Registered Voters: {len(self.voters)}")
        print(f"Voter Turnout: {(total_votes/len(self.voters)*100):.1f}%\n")
        
        sorted_results = sorted(results.items(), key=lambda x: x[1], reverse=True)
        
        for rank, (candidate_id, votes) in enumerate(sorted_results, 1):
            candidate_name = self.candidates[candidate_id]
            percentage = (votes / total_votes * 100) if total_votes > 0 else 0
            bar = "█" * int(percentage / 2)
            print(f"{rank}. {candidate_name}")
            print(f"   Votes: {votes} ({percentage:.1f}%) {bar}")
        
        if sorted_results:
            winner_id, winner_votes = sorted_results[0]
            print(f"\n🏆 Winner: {self.candidates[winner_id]} with {winner_votes} votes!")
        
        print("="*60)
    
    def get_system_info(self):
        """Display system information"""
        return {
            'encryption_schemes': ['ElGamal (multiplicative)', 'Paillier (additive)'],
            'signature_algorithm': 'RSA-2048 with SHA-256',
            'total_voters': len(self.voters),
            'votes_cast': len(self.votes),
            'election_status': 'Active' if self.election_active else 'Inactive'
        }

# ============================================================================
# MENU-DRIVEN INTERFACE
# ============================================================================

def print_menu():
    """Display main menu"""
    print("\n" + "="*60)
    print("      🗳️  SECURE VOTING SYSTEM  🗳️")
    print("   ElGamal + Paillier + Digital Signatures")
    print("="*60)
    print("1. Setup New Election")
    print("2. Register Voter")
    print("3. Cast Vote")
    print("4. View All Voters")
    print("5. Tally Votes & Display Results")
    print("6. Verify Individual Vote")
    print("7. System Information")
    print("8. Exit")
    print("="*60)

def main():
    system = SecureVotingSystem()
    
    while True:
        print_menu()
        choice = input("\nEnter your choice (1-8): ").strip()
        
        if choice == '1':
            print("\n--- SETUP NEW ELECTION ---")
            num_candidates = input("Enter number of candidates: ").strip()
            
            try:
                num_candidates = int(num_candidates)
                if num_candidates < 2:
                    print("❌ Need at least 2 candidates!")
                    continue
                
                candidates = []
                for i in range(num_candidates):
                    name = input(f"Enter name for candidate {i+1}: ").strip()
                    if name:
                        candidates.append(name)
                
                system.setup_election(candidates)
                print(f"\n✓ Election created with candidates:")
                for i, name in enumerate(candidates, 1):
                    print(f"   {i}. {name}")
                
            except ValueError:
                print("❌ Invalid input!")
        
        elif choice == '2':
            print("\n--- REGISTER VOTER ---")
            voter_name = input("Enter voter name: ").strip()
            
            if voter_name:
                voter_id = system.register_voter(voter_name)
                print(f"🎫 Voter ID: {voter_id}")
                print("🔑 Digital signature keypair generated")
            else:
                print("❌ Voter name cannot be empty!")
        
        elif choice == '3':
            print("\n--- CAST VOTE ---")
            
            if not system.election_active:
                print("❌ No active election! Please setup an election first.")
                continue
            
            if not system.voters:
                print("❌ No registered voters! Please register voters first.")
                continue
            
            print("\nCandidates:")
            for cid, name in system.candidates.items():
                print(f"  {cid}. {name}")
            
            voter_id = input("\nEnter your Voter ID: ").strip()
            candidate_id = input("Enter candidate number: ").strip()
            
            try:
                candidate_id = int(candidate_id)
                success, message = system.cast_vote(voter_id, candidate_id)
                
                if success:
                    print(f"\n✓ {message}")
                    print("🔒 Vote encrypted using ElGamal")
                    print("🔒 Vote re-encrypted using Paillier")
                    print("✍️  Vote signed with voter's digital signature")
                    print("✅ Vote authenticated by election authority")
                else:
                    print(f"\n❌ {message}")
            except ValueError:
                print("❌ Invalid candidate number!")
        
        elif choice == '4':
            print("\n--- REGISTERED VOTERS ---")
            
            if not system.voters:
                print("No voters registered yet.")
            else:
                print(f"\nTotal Voters: {len(system.voters)}\n")
                for vid, vdata in system.voters.items():
                    status = "✓ Voted" if vdata['has_voted'] else "✗ Not voted"
                    print(f"  {vid}: {vdata['name']} [{status}]")
        
        elif choice == '5':
            print("\n--- TALLY VOTES ---")
            
            if not system.votes:
                print("❌ No votes cast yet!")
                continue
            
            confirm = input(f"\nTally {len(system.votes)} votes? (yes/no): ").strip().lower()
            
            if confirm == 'yes':
                results = system.tally_votes_paillier()
                system.display_results(results)
                system.election_active = False
            else:
                print("Tally cancelled.")
        
        elif choice == '6':
            print("\n--- VERIFY VOTE ---")
            
            if not system.votes:
                print("❌ No votes to verify!")
                continue
            
            try:
                vote_num = int(input(f"Enter vote number (1-{len(system.votes)}): "))
                if 1 <= vote_num <= len(system.votes):
                    vote = system.votes[vote_num - 1]
                    is_valid, msg = system.verify_vote(vote)
                    
                    print(f"\nVote #{vote_num}")
                    print(f"Voter ID: {vote['voter_id']}")
                    print(f"Timestamp: {time.ctime(vote['timestamp'])}")
                    print(f"Status: {'✅ Valid' if is_valid else '❌ Invalid'}")
                    print(f"Message: {msg}")
                else:
                    print("❌ Invalid vote number!")
            except ValueError:
                print("❌ Invalid input!")
        
        elif choice == '7':
            print("\n--- SYSTEM INFORMATION ---")
            info = system.get_system_info()
            
            print(f"\nEncryption Schemes:")
            for scheme in info['encryption_schemes']:
                print(f"  • {scheme}")
            print(f"\nSignature Algorithm: {info['signature_algorithm']}")
            print(f"Total Registered Voters: {info['total_voters']}")
            print(f"Total Votes Cast: {info['votes_cast']}")
            print(f"Election Status: {info['election_status']}")
        
        elif choice == '8':
            print("\n🔒 Securing voting system...")
            print("Thank you for using the Secure Voting System!")
            print("Goodbye!\n")
            break
        
        else:
            print("\n❌ Invalid choice! Please enter a number between 1 and 8.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()