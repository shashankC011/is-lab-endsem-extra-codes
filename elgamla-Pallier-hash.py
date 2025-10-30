'''Develop a secure health data analytics system for hospitals.

Patient health values (e.g., blood pressure readings) should be encrypted using Paillier encryption for homomorphic addition.

Perform encrypted summation to compute total/average without decrypting.

Encrypt final results using ElGamal before transmission to the cloud.

Use a SHA-256 hash to verify that the received data was not altered.

Include options for:

Encrypt patient data

Perform encrypted addition

Verify hash integrity

Decrypt result'''
import random
import hashlib
import json
import time
from datetime import datetime

# ============================================================================
# MATHEMATICAL UTILITIES
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
# PAILLIER CRYPTOSYSTEM
# ============================================================================

class Paillier:
    """Paillier encryption with additive homomorphic property"""
    
    def __init__(self, bits=512):
        print(f"  Generating Paillier keys ({bits}-bit)...", end=" ")
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        self.n = p * q
        self.n_sq = self.n * self.n
        self.g = self.n + 1
        self.lambda_val = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
        self.mu = mod_inverse(self.L(pow(self.g, self.lambda_val, self.n_sq), self.n), self.n)
        print("✓")
    
    def L(self, x, n):
        """L function for Paillier"""
        return (x - 1) // n
    
    def get_public_key(self):
        return {'n': self.n, 'g': self.g}
    
    def encrypt(self, message):
        """Encrypt a plaintext message"""
        r = random.randint(1, self.n - 1)
        while gcd(r, self.n) != 1:
            r = random.randint(1, self.n - 1)
        
        c = (pow(self.g, message, self.n_sq) * pow(r, self.n, self.n_sq)) % self.n_sq
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
    
    def homomorphic_add_constant(self, ciphertext, constant):
        """Add a constant to an encrypted value"""
        return (ciphertext * pow(self.g, constant, self.n_sq)) % self.n_sq

# ============================================================================
# ELGAMAL CRYPTOSYSTEM
# ============================================================================

class ElGamal:
    """ElGamal encryption for secure transmission"""
    
    def __init__(self, bits=256):
        print(f"  Generating ElGamal keys ({bits}-bit)...", end=" ")
        self.bits = bits
        self.p = generate_prime(bits)
        self.g = random.randint(2, self.p - 2)
        self.x = random.randint(2, self.p - 2)  # Private key
        self.h = pow(self.g, self.x, self.p)     # Public key
        print("✓")
    
    def get_public_key(self):
        return {'p': self.p, 'g': self.g, 'h': self.h}
    
    def encrypt(self, message):
        """Encrypt a message"""
        y = random.randint(2, self.p - 2)
        c1 = pow(self.g, y, self.p)
        c2 = (message * pow(self.h, y, self.p)) % self.p
        return (c1, c2)
    
    def decrypt(self, ciphertext):
        """Decrypt a ciphertext"""
        c1, c2 = ciphertext
        s = pow(c1, self.x, self.p)
        s_inv = mod_inverse(s, self.p)
        message = (c2 * s_inv) % self.p
        return message

# ============================================================================
# SECURE HEALTH DATA ANALYTICS SYSTEM
# ============================================================================

class SecureHealthAnalytics:
    """Secure health data analytics with homomorphic encryption"""
    
    def __init__(self):
        print("\n🏥 Initializing Secure Health Data Analytics System...")
        print("⏳ Generating cryptographic keys...\n")
        
        self.paillier = Paillier(bits=256)  # Smaller for demo
        self.elgamal = ElGamal(bits=128)    # Smaller for demo
        
        self.patients = {}
        self.patient_counter = 0
        self.encrypted_readings = {}
        self.aggregated_data = {}
        
        print("\n✓ System initialization complete!\n")
    
    def compute_hash(self, data):
        """Compute SHA-256 hash of data"""
        if isinstance(data, dict):
            data_str = json.dumps(data, sort_keys=True)
        else:
            data_str = str(data)
        return hashlib.sha256(data_str.encode('utf-8')).hexdigest()
    
    def verify_hash(self, data, expected_hash):
        """Verify data integrity using hash"""
        computed_hash = self.compute_hash(data)
        return computed_hash == expected_hash
    
    def register_patient(self, name, age, patient_id=None):
        """Register a new patient"""
        if patient_id is None:
            self.patient_counter += 1
            patient_id = f"P{self.patient_counter:04d}"
        
        self.patients[patient_id] = {
            'name': name,
            'age': age,
            'registered_at': datetime.now().isoformat()
        }
        
        self.encrypted_readings[patient_id] = {
            'blood_pressure_systolic': [],
            'blood_pressure_diastolic': [],
            'heart_rate': [],
            'blood_sugar': [],
            'temperature': []
        }
        
        print(f"✓ Patient registered: {name} [ID: {patient_id}]")
        return patient_id
    
    def add_health_reading(self, patient_id, reading_type, value):
        """Add and encrypt a health reading for a patient"""
        if patient_id not in self.patients:
            return False, "Patient not found"
        
        valid_types = ['blood_pressure_systolic', 'blood_pressure_diastolic', 
                       'heart_rate', 'blood_sugar', 'temperature']
        
        if reading_type not in valid_types:
            return False, "Invalid reading type"
        
        # Encrypt the reading using Paillier
        encrypted_value = self.paillier.encrypt(value)
        
        # Store with metadata
        reading_data = {
            'encrypted_value': encrypted_value,
            'plaintext_value': value,  # For verification only
            'timestamp': time.time(),
            'hash': self.compute_hash({'patient_id': patient_id, 'value': value, 'type': reading_type})
        }
        
        self.encrypted_readings[patient_id][reading_type].append(reading_data)
        
        return True, f"Reading encrypted and stored [Hash: {reading_data['hash'][:16]}...]"
    
    def perform_encrypted_aggregation(self, patient_ids, reading_type):
        """Perform homomorphic addition on encrypted readings"""
        print(f"\n🔒 Performing encrypted aggregation for {reading_type}...")
        print("   Computing on ENCRYPTED data (no decryption)...\n")
        
        encrypted_sum = None
        count = 0
        all_readings = []
        
        for patient_id in patient_ids:
            if patient_id not in self.encrypted_readings:
                continue
            
            readings = self.encrypted_readings[patient_id][reading_type]
            
            for reading in readings:
                all_readings.append(reading)
                encrypted_value = reading['encrypted_value']
                
                if encrypted_sum is None:
                    encrypted_sum = encrypted_value
                else:
                    # Homomorphic addition
                    encrypted_sum = self.paillier.homomorphic_add(encrypted_sum, encrypted_value)
                
                count += 1
        
        if count == 0:
            return None, 0, []
        
        return encrypted_sum, count, all_readings
    
    def compute_statistics(self, patient_ids, reading_type):
        """Compute encrypted statistics and prepare for transmission"""
        # Step 1: Perform encrypted aggregation
        encrypted_sum, count, all_readings = self.perform_encrypted_aggregation(patient_ids, reading_type)
        
        if encrypted_sum is None:
            return None
        
        # Step 2: Decrypt the sum (hospital has private key)
        decrypted_sum = self.paillier.decrypt(encrypted_sum)
        average = decrypted_sum / count if count > 0 else 0
        
        # Step 3: Prepare statistics
        statistics = {
            'reading_type': reading_type,
            'total_sum': decrypted_sum,
            'average': average,
            'count': count,
            'patient_count': len(patient_ids),
            'timestamp': time.time()
        }
        
        # Step 4: Compute hash for integrity
        stats_hash = self.compute_hash(statistics)
        
        # Step 5: Encrypt results using ElGamal for cloud transmission
        # Convert sum to fit in ElGamal (modulo if needed)
        sum_for_elgamal = decrypted_sum % self.elgamal.p
        avg_scaled = int(average * 100) % self.elgamal.p  # Scale average
        
        elgamal_encrypted_sum = self.elgamal.encrypt(sum_for_elgamal)
        elgamal_encrypted_avg = self.elgamal.encrypt(avg_scaled)
        
        # Step 6: Package for transmission
        transmission_package = {
            'metadata': {
                'reading_type': reading_type,
                'count': count,
                'patient_count': len(patient_ids),
                'timestamp': statistics['timestamp']
            },
            'encrypted_data': {
                'sum': {'c1': elgamal_encrypted_sum[0], 'c2': elgamal_encrypted_sum[1]},
                'average_scaled': {'c1': elgamal_encrypted_avg[0], 'c2': elgamal_encrypted_avg[1]}
            },
            'integrity_hash': stats_hash,
            'plaintext_statistics': statistics  # For verification
        }
        
        return transmission_package
    
    def verify_and_decrypt_transmission(self, package):
        """Verify integrity and decrypt received data"""
        print("\n🔐 Verifying and decrypting transmission package...")
        
        # Step 1: Verify hash integrity
        stats = package['plaintext_statistics']
        expected_hash = package['integrity_hash']
        
        is_valid = self.verify_hash(stats, expected_hash)
        
        if not is_valid:
            print("❌ Hash verification FAILED! Data may be corrupted.")
            return None
        
        print("✓ Hash verification PASSED - Data integrity confirmed")
        
        # Step 2: Decrypt ElGamal encrypted data
        sum_encrypted = (package['encrypted_data']['sum']['c1'], 
                        package['encrypted_data']['sum']['c2'])
        avg_encrypted = (package['encrypted_data']['average_scaled']['c1'], 
                        package['encrypted_data']['average_scaled']['c2'])
        
        decrypted_sum = self.elgamal.decrypt(sum_encrypted)
        decrypted_avg_scaled = self.elgamal.decrypt(avg_encrypted)
        decrypted_avg = decrypted_avg_scaled / 100.0
        
        print("✓ ElGamal decryption completed")
        
        return {
            'reading_type': stats['reading_type'],
            'total_sum': decrypted_sum,
            'average': decrypted_avg,
            'count': stats['count'],
            'patient_count': stats['patient_count'],
            'verified': True
        }
    
    def display_patient_readings(self, patient_id):
        """Display all readings for a patient"""
        if patient_id not in self.patients:
            print("❌ Patient not found!")
            return
        
        patient = self.patients[patient_id]
        readings = self.encrypted_readings[patient_id]
        
        print(f"\n{'='*70}")
        print(f"Patient: {patient['name']} (Age: {patient['age']}) [ID: {patient_id}]")
        print(f"{'='*70}")
        
        for reading_type, data_list in readings.items():
            if data_list:
                print(f"\n{reading_type.replace('_', ' ').title()}:")
                for i, reading in enumerate(data_list, 1):
                    timestamp = datetime.fromtimestamp(reading['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                    print(f"  {i}. Value: {reading['plaintext_value']} | Time: {timestamp}")
                    print(f"     Hash: {reading['hash'][:32]}...")
        
        print(f"\n{'='*70}")

# ============================================================================
# MENU-DRIVEN INTERFACE
# ============================================================================

def print_menu():
    """Display main menu"""
    print("\n" + "="*70)
    print("          🏥 SECURE HEALTH DATA ANALYTICS SYSTEM 🏥")
    print("     Paillier Homomorphic + ElGamal + SHA-256 Integrity")
    print("="*70)
    print("1. Register Patient")
    print("2. Add Encrypted Health Reading")
    print("3. View Patient Readings")
    print("4. Perform Encrypted Aggregation & Statistics")
    print("5. Prepare Encrypted Transmission to Cloud")
    print("6. Verify Hash Integrity of Data")
    print("7. Decrypt Received Transmission")
    print("8. System Information")
    print("9. Exit")
    print("="*70)

def main():
    system = SecureHealthAnalytics()
    
    # Pre-populate with sample data
    print("📋 Adding sample patient data...\n")
    
    patients_data = [
        ("John Doe", 45),
        ("Jane Smith", 32),
        ("Robert Johnson", 58),
        ("Emily Davis", 41)
    ]
    
    patient_ids = []
    for name, age in patients_data:
        pid = system.register_patient(name, age)
        patient_ids.append(pid)
    
    # Add sample readings
    print("\n💉 Adding sample health readings...")
    sample_readings = [
        (patient_ids[0], 'blood_pressure_systolic', 120),
        (patient_ids[0], 'blood_pressure_systolic', 118),
        (patient_ids[0], 'heart_rate', 72),
        (patient_ids[1], 'blood_pressure_systolic', 130),
        (patient_ids[1], 'blood_pressure_systolic', 128),
        (patient_ids[1], 'heart_rate', 75),
        (patient_ids[2], 'blood_pressure_systolic', 140),
        (patient_ids[2], 'heart_rate', 80),
        (patient_ids[3], 'blood_pressure_systolic', 125),
        (patient_ids[3], 'heart_rate', 68),
    ]
    
    for pid, rtype, value in sample_readings:
        system.add_health_reading(pid, rtype, value)
    
    print("✓ Sample data loaded\n")
    
    current_transmission = None
    
    while True:
        print_menu()
        choice = input("\nEnter your choice (1-9): ").strip()
        
        if choice == '1':
            print("\n--- REGISTER PATIENT ---")
            name = input("Enter patient name: ").strip()
            age = input("Enter patient age: ").strip()
            
            try:
                age = int(age)
                if name and age > 0:
                    patient_id = system.register_patient(name, age)
                else:
                    print("❌ Invalid input!")
            except ValueError:
                print("❌ Age must be a number!")
        
        elif choice == '2':
            print("\n--- ADD ENCRYPTED HEALTH READING ---")
            
            if not system.patients:
                print("❌ No patients registered!")
                continue
            
            print("\nPatients:")
            for pid, pdata in system.patients.items():
                print(f"  {pid}: {pdata['name']}")
            
            patient_id = input("\nEnter Patient ID: ").strip()
            
            print("\nReading Types:")
            print("  1. Blood Pressure (Systolic)")
            print("  2. Blood Pressure (Diastolic)")
            print("  3. Heart Rate")
            print("  4. Blood Sugar")
            print("  5. Temperature")
            
            reading_choice = input("\nSelect reading type (1-5): ").strip()
            
            reading_map = {
                '1': 'blood_pressure_systolic',
                '2': 'blood_pressure_diastolic',
                '3': 'heart_rate',
                '4': 'blood_sugar',
                '5': 'temperature'
            }
            
            if reading_choice in reading_map:
                value = input("Enter reading value: ").strip()
                try:
                    value = int(value)
                    reading_type = reading_map[reading_choice]
                    success, message = system.add_health_reading(patient_id, reading_type, value)
                    
                    if success:
                        print(f"\n✓ {message}")
                        print("🔒 Reading encrypted using Paillier encryption")
                        print("📊 Ready for homomorphic computation")
                    else:
                        print(f"\n❌ {message}")
                except ValueError:
                    print("❌ Value must be a number!")
            else:
                print("❌ Invalid reading type!")
        
        elif choice == '3':
            print("\n--- VIEW PATIENT READINGS ---")
            
            if not system.patients:
                print("❌ No patients registered!")
                continue
            
            print("\nPatients:")
            for pid, pdata in system.patients.items():
                print(f"  {pid}: {pdata['name']}")
            
            patient_id = input("\nEnter Patient ID: ").strip()
            system.display_patient_readings(patient_id)
        
        elif choice == '4':
            print("\n--- PERFORM ENCRYPTED AGGREGATION ---")
            
            print("\nSelect reading type to aggregate:")
            print("  1. Blood Pressure (Systolic)")
            print("  2. Heart Rate")
            print("  3. Blood Sugar")
            
            reading_choice = input("\nSelect (1-3): ").strip()
            
            reading_map = {
                '1': 'blood_pressure_systolic',
                '2': 'heart_rate',
                '3': 'blood_sugar'
            }
            
            if reading_choice in reading_map:
                reading_type = reading_map[reading_choice]
                
                # Use all patients
                patient_list = list(system.patients.keys())
                
                encrypted_sum, count, readings = system.perform_encrypted_aggregation(
                    patient_list, reading_type
                )
                
                if encrypted_sum is None:
                    print("❌ No readings found for this type!")
                    continue
                
                # Decrypt for display
                decrypted_sum = system.paillier.decrypt(encrypted_sum)
                average = decrypted_sum / count if count > 0 else 0
                
                print(f"✓ Aggregation completed on ENCRYPTED data!")
                print(f"\n📊 Results:")
                print(f"   Reading Type: {reading_type.replace('_', ' ').title()}")
                print(f"   Number of Readings: {count}")
                print(f"   Total Sum: {decrypted_sum}")
                print(f"   Average: {average:.2f}")
                print(f"\n   Note: Computation was performed on encrypted values!")
            else:
                print("❌ Invalid selection!")
        
        elif choice == '5':
            print("\n--- PREPARE ENCRYPTED TRANSMISSION TO CLOUD ---")
            
            print("\nSelect reading type:")
            print("  1. Blood Pressure (Systolic)")
            print("  2. Heart Rate")
            
            reading_choice = input("\nSelect (1-2): ").strip()
            
            reading_map = {
                '1': 'blood_pressure_systolic',
                '2': 'heart_rate'
            }
            
            if reading_choice in reading_map:
                reading_type = reading_map[reading_choice]
                patient_list = list(system.patients.keys())
                
                print(f"\n🔒 Processing {reading_type}...")
                print("   Step 1: Encrypted aggregation using Paillier...")
                print("   Step 2: Computing statistics...")
                print("   Step 3: Re-encrypting with ElGamal for transmission...")
                print("   Step 4: Computing SHA-256 hash for integrity...\n")
                
                package = system.compute_statistics(patient_list, reading_type)
                
                if package:
                    current_transmission = package
                    print("✓ Transmission package prepared!")
                    print(f"\n📦 Package Contents:")
                    print(f"   Reading Type: {package['metadata']['reading_type']}")
                    print(f"   Data Points: {package['metadata']['count']}")
                    print(f"   Patients: {package['metadata']['patient_count']}")
                    print(f"   Integrity Hash: {package['integrity_hash'][:32]}...")
                    print(f"\n✓ Data is encrypted with ElGamal and ready for cloud transmission")
                else:
                    print("❌ No data available!")
            else:
                print("❌ Invalid selection!")
        
        elif choice == '6':
            print("\n--- VERIFY HASH INTEGRITY ---")
            
            if current_transmission is None:
                print("❌ No transmission package available! Create one first (Option 5)")
                continue
            
            print("\n🔍 Verifying data integrity using SHA-256...")
            
            stats = current_transmission['plaintext_statistics']
            expected_hash = current_transmission['integrity_hash']
            computed_hash = system.compute_hash(stats)
            
            print(f"\nExpected Hash: {expected_hash[:32]}...")
            print(f"Computed Hash: {computed_hash[:32]}...")
            
            if computed_hash == expected_hash:
                print("\n✅ VERIFICATION PASSED - Data integrity confirmed!")
                print("   No tampering detected during transmission")
            else:
                print("\n❌ VERIFICATION FAILED - Data may be corrupted!")
        
        elif choice == '7':
            print("\n--- DECRYPT RECEIVED TRANSMISSION ---")
            
            if current_transmission is None:
                print("❌ No transmission package available! Create one first (Option 5)")
                continue
            
            result = system.verify_and_decrypt_transmission(current_transmission)
            
            if result:
                print(f"\n📊 Decrypted Results:")
                print(f"   Reading Type: {result['reading_type'].replace('_', ' ').title()}")
                print(f"   Total Sum: {result['total_sum']}")
                print(f"   Average: {result['average']:.2f}")
                print(f"   Data Points: {result['count']}")
                print(f"   Patients: {result['patient_count']}")
                print(f"\n✅ Data successfully verified and decrypted!")
        
        elif choice == '8':
            print("\n--- SYSTEM INFORMATION ---")
            print("\n🔐 Encryption Schemes:")
            print("   • Paillier (Homomorphic Addition) - For encrypted computation")
            print("   • ElGamal - For secure cloud transmission")
            print("\n🔒 Integrity Verification:")
            print("   • SHA-256 Hashing - Detect data tampering")
            print("\n📊 Statistics:")
            print(f"   Total Patients: {len(system.patients)}")
            total_readings = sum(
                sum(len(readings) for readings in patient_data.values())
                for patient_data in system.encrypted_readings.values()
            )
            print(f"   Total Encrypted Readings: {total_readings}")
            print("\n💡 Capabilities:")
            print("   ✓ Homomorphic computation on encrypted data")
            print("   ✓ Privacy-preserving analytics")
            print("   ✓ Secure cloud transmission")
            print("   ✓ Data integrity verification")
        
        elif choice == '9':
            print("\n🔒 Securing health data system...")
            print("Thank you for using Secure Health Data Analytics!")
            print("Goodbye!\n")
            break
        
        else:
            print("\n❌ Invalid choice! Please enter a number between 1 and 9.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()