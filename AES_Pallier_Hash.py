"""
Smart Healthcare Data Analysis System - Menu-Based Interface
Implements AES-256 encryption, Paillier homomorphic encryption, and SHA-256 hashing
for privacy-preserving health data analysis.

Required libraries:
pip install pycryptodome phe
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import json
from phe import paillier
import base64
import os


class HealthcarePrivacySystem:
    """Privacy-preserving healthcare data analysis system"""
    
    def __init__(self):
        # Generate AES-256 key
        self.aes_key = get_random_bytes(32)  # 256 bits
        
        # Paillier keys (lazy initialization)
        self.public_key = None
        self.private_key = None
        self.paillier_initialized = False
        
        self.patients = []
        self.encrypted_patients = []
        self.data_hash = None
    
    def initialize_paillier(self):
        """Initialize Paillier keypair (only when needed)"""
        if not self.paillier_initialized:
            print("\n🔐 Generating Paillier keypair (this may take a moment)...")
            self.public_key, self.private_key = paillier.generate_paillier_keypair(n_length=2048)
            self.paillier_initialized = True
            print("✓ Keypair generated successfully!")
        
    def add_patient(self, name, age, heart_rate, blood_pressure, glucose):
        """Add a patient record"""
        patient = {
            'id': len(self.patients) + 1,
            'name': name,
            'age': age,
            'heart_rate': heart_rate,
            'blood_pressure': blood_pressure,
            'glucose': glucose
        }
        self.patients.append(patient)
        print(f"✓ Added patient: {name} (ID: {patient['id']})")
        return patient
    
    def view_patients(self):
        """View all patient records"""
        if not self.patients:
            print("\n⚠ No patients in the system!")
            return
        
        print("\n" + "="*70)
        print("PATIENT RECORDS")
        print("="*70)
        for patient in self.patients:
            print(f"\nID: {patient['id']}")
            print(f"Name: {patient['name']}")
            print(f"Age: {patient['age']} years")
            print(f"Heart Rate: {patient['heart_rate']} bpm")
            print(f"Blood Pressure: {patient['blood_pressure']} mmHg")
            print(f"Glucose Level: {patient['glucose']} mg/dL")
            print("-"*70)
    
    def encrypt_data_aes(self, data):
        """Encrypt data using AES-256 in CBC mode"""
        json_data = json.dumps(data).encode('utf-8')
        iv = get_random_bytes(16)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(json_data, AES.block_size))
        return base64.b64encode(iv + encrypted).decode('utf-8')
    
    def decrypt_data_aes(self, encrypted_data):
        """Decrypt AES-256 encrypted data"""
        encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return json.loads(decrypted.decode('utf-8'))
    
    def encrypt_all_patients(self):
        """Encrypt all patient data using AES-256"""
        if not self.patients:
            print("\n⚠ No patients to encrypt!")
            return
        
        print("\n" + "="*70)
        print("AES-256 ENCRYPTION")
        print("="*70)
        
        self.encrypted_patients = []
        for patient in self.patients:
            encrypted = {
                'id': patient['id'],
                'encrypted_data': self.encrypt_data_aes(patient)
            }
            self.encrypted_patients.append(encrypted)
            print(f"✓ Encrypted patient {patient['id']}: {patient['name']}")
        
        print(f"\n✓ Successfully encrypted {len(self.encrypted_patients)} patient records")
        
        # Generate hash for integrity verification
        self.generate_hash()
    
    def view_encrypted_data(self):
        """View encrypted patient data"""
        if not self.encrypted_patients:
            print("\n⚠ No encrypted data available! Please encrypt patients first.")
            return
        
        print("\n" + "="*70)
        print("ENCRYPTED PATIENT DATA (AES-256)")
        print("="*70)
        for encrypted in self.encrypted_patients:
            print(f"\nPatient ID: {encrypted['id']}")
            print(f"Encrypted Data: {encrypted['encrypted_data'][:80]}...")
            print("-"*70)
        
        if self.data_hash:
            print(f"\nData Hash (SHA-256): {self.data_hash}")
    
    def generate_hash(self):
        """Generate SHA-256 hash of encrypted data for integrity verification"""
        if not self.encrypted_patients:
            print("\n⚠ No encrypted data to hash!")
            return
        
        data_string = json.dumps(self.encrypted_patients, sort_keys=True)
        self.data_hash = hashlib.sha256(data_string.encode('utf-8')).hexdigest()
        print(f"\n✓ Generated SHA-256 hash: {self.data_hash}")
    
    def verify_integrity(self):
        """Verify data integrity using SHA-256 hash"""
        if not self.encrypted_patients or not self.data_hash:
            print("\n⚠ No data or hash to verify!")
            return False
        
        print("\n" + "="*70)
        print("DATA INTEGRITY VERIFICATION")
        print("="*70)
        
        current_data = json.dumps(self.encrypted_patients, sort_keys=True)
        current_hash = hashlib.sha256(current_data.encode('utf-8')).hexdigest()
        
        is_valid = current_hash == self.data_hash
        
        print(f"\nOriginal hash:  {self.data_hash}")
        print(f"Current hash:   {current_hash}")
        print(f"\n{'✓' if is_valid else '✗'} Data integrity: {'VERIFIED ✓' if is_valid else 'COMPROMISED ✗'}")
        
        return is_valid
    
    def homomorphic_analysis(self):
        """Perform homomorphic analysis on encrypted health metrics"""
        if not self.patients:
            print("\n⚠ No patients to analyze!")
            return
        
        # Initialize Paillier if needed
        self.initialize_paillier()
        
        print("\n" + "="*70)
        print("PAILLIER HOMOMORPHIC ENCRYPTION & ANALYSIS")
        print("="*70)
        
        # Encrypt health metrics using Paillier
        print("\n🔒 Encrypting metrics with Paillier...")
        encrypted_metrics = []
        
        for patient in self.patients:
            encrypted = {
                'id': patient['id'],
                'heart_rate': self.public_key.encrypt(patient['heart_rate']),
                'blood_pressure': self.public_key.encrypt(patient['blood_pressure']),
                'glucose': self.public_key.encrypt(patient['glucose'])
            }
            encrypted_metrics.append(encrypted)
            print(f"  ✓ Encrypted metrics for patient {patient['id']}")
        
        # Perform homomorphic addition (on encrypted data!)
        print("\n🧮 Performing homomorphic addition on encrypted data...")
        
        sum_heart_rate = encrypted_metrics[0]['heart_rate']
        sum_blood_pressure = encrypted_metrics[0]['blood_pressure']
        sum_glucose = encrypted_metrics[0]['glucose']
        
        for i in range(1, len(encrypted_metrics)):
            sum_heart_rate += encrypted_metrics[i]['heart_rate']
            sum_blood_pressure += encrypted_metrics[i]['blood_pressure']
            sum_glucose += encrypted_metrics[i]['glucose']
        
        print("  ✓ Homomorphic addition completed (no decryption needed!)")
        
        # Decrypt only the final sums
        print("\n🔓 Decrypting only the final aggregated results...")
        total_heart_rate = self.private_key.decrypt(sum_heart_rate)
        total_blood_pressure = self.private_key.decrypt(sum_blood_pressure)
        total_glucose = self.private_key.decrypt(sum_glucose)
        
        # Calculate averages
        num_patients = len(self.patients)
        avg_heart_rate = total_heart_rate / num_patients
        avg_blood_pressure = total_blood_pressure / num_patients
        avg_glucose = total_glucose / num_patients
        
        # Display results
        print("\n" + "="*70)
        print("HOMOMORPHIC ANALYSIS RESULTS")
        print("="*70)
        print(f"Number of patients:        {num_patients}")
        print(f"Average Heart Rate:        {avg_heart_rate:.1f} bpm")
        print(f"Average Blood Pressure:    {avg_blood_pressure:.1f} mmHg")
        print(f"Average Glucose Level:     {avg_glucose:.1f} mg/dL")
        print("="*70)
        
        print("\n💡 Note: These averages were computed WITHOUT decrypting individual patient data!")
        
        return {
            'num_patients': num_patients,
            'avg_heart_rate': avg_heart_rate,
            'avg_blood_pressure': avg_blood_pressure,
            'avg_glucose': avg_glucose
        }
    
    def decrypt_patient(self, patient_id):
        """Decrypt and display a specific patient's data"""
        if not self.encrypted_patients:
            print("\n⚠ No encrypted data available!")
            return
        
        encrypted_patient = next((p for p in self.encrypted_patients if p['id'] == patient_id), None)
        
        if not encrypted_patient:
            print(f"\n⚠ Patient {patient_id} not found!")
            return
        
        print("\n" + "="*70)
        print(f"DECRYPTING PATIENT {patient_id}")
        print("="*70)
        
        print(f"\nEncrypted data (truncated):")
        print(f"{encrypted_patient['encrypted_data'][:80]}...")
        
        decrypted = self.decrypt_data_aes(encrypted_patient['encrypted_data'])
        
        print(f"\n🔓 Decrypted data:")
        print(json.dumps(decrypted, indent=2))
    
    def simulate_tampering(self):
        """Simulate data tampering for demonstration"""
        if not self.encrypted_patients:
            print("\n⚠ No encrypted data available!")
            return
        
        print("\n" + "="*70)
        print("SIMULATING DATA TAMPERING")
        print("="*70)
        print("\n⚠ Modifying encrypted data...")
        self.encrypted_patients[0]['encrypted_data'] = self.encrypted_patients[0]['encrypted_data'][:-10] + "TAMPERED!!"
        print("✓ Data has been tampered with")
        print("\nNow run 'Verify Data Integrity' to detect the tampering!")
    
    def add_sample_patients(self):
        """Add sample patient data"""
        print("\n📝 Adding sample patients...")
        self.add_patient("Alice Johnson", 45, 72, 120, 95)
        self.add_patient("Bob Smith", 52, 78, 135, 110)
        self.add_patient("Carol Williams", 38, 68, 115, 88)
        self.add_patient("David Brown", 61, 82, 145, 125)
        self.add_patient("Eve Davis", 29, 65, 108, 85)
        print(f"\n✓ Added 5 sample patients")


def clear_screen():
    """Clear the console screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_menu():
    """Display the main menu"""
    print("\n" + "="*70)
    print(" 🏥 SMART HEALTHCARE PRIVACY SYSTEM 🔐")
    print(" AES-256 + Paillier Homomorphic + SHA-256 Hashing")
    print("="*70)
    print("\n📋 MAIN MENU:")
    print("\n  Patient Management:")
    print("    1. Add Patient")
    print("    2. View All Patients")
    print("    3. Add Sample Patients (Demo)")
    print("\n  Encryption & Security:")
    print("    4. Encrypt All Patients (AES-256)")
    print("    5. View Encrypted Data")
    print("    6. Decrypt Specific Patient")
    print("\n  Privacy-Preserving Analysis:")
    print("    7. Homomorphic Analysis (Paillier)")
    print("\n  Data Integrity:")
    print("    8. Verify Data Integrity (SHA-256)")
    print("    9. Simulate Data Tampering (Demo)")
    print("\n  System:")
    print("    10. Clear Screen")
    print("    0. Exit")
    print("\n" + "="*70)


def get_patient_input():
    """Get patient data from user input"""
    print("\n📝 Enter Patient Information:")
    name = input("  Name: ").strip()
    
    try:
        age = int(input("  Age: "))
        heart_rate = int(input("  Heart Rate (bpm): "))
        blood_pressure = int(input("  Blood Pressure (mmHg): "))
        glucose = int(input("  Glucose Level (mg/dL): "))
        return name, age, heart_rate, blood_pressure, glucose
    except ValueError:
        print("\n⚠ Invalid input! Please enter numeric values for age and health metrics.")
        return None


def main():
    """Main menu-based application"""
    system = HealthcarePrivacySystem()
    
    clear_screen()
    print("\n🎉 Welcome to Smart Healthcare Privacy System!")
    print("This system demonstrates privacy-preserving healthcare data analysis.")
    
    while True:
        print_menu()
        
        choice = input("\n👉 Enter your choice (0-10): ").strip()
        
        if choice == '1':
            # Add Patient
            patient_data = get_patient_input()
            if patient_data:
                system.add_patient(*patient_data)
        
        elif choice == '2':
            # View All Patients
            system.view_patients()
        
        elif choice == '3':
            # Add Sample Patients
            system.add_sample_patients()
        
        elif choice == '4':
            # Encrypt All Patients
            system.encrypt_all_patients()
        
        elif choice == '5':
            # View Encrypted Data
            system.view_encrypted_data()
        
        elif choice == '6':
            # Decrypt Specific Patient
            if not system.encrypted_patients:
                print("\n⚠ No encrypted data available! Please encrypt patients first.")
            else:
                try:
                    patient_id = int(input("\n👉 Enter Patient ID to decrypt: "))
                    system.decrypt_patient(patient_id)
                except ValueError:
                    print("\n⚠ Invalid Patient ID!")
        
        elif choice == '7':
            # Homomorphic Analysis
            system.homomorphic_analysis()
        
        elif choice == '8':
            # Verify Data Integrity
            system.verify_integrity()
        
        elif choice == '9':
            # Simulate Tampering
            system.simulate_tampering()
        
        elif choice == '10':
            # Clear Screen
            clear_screen()
            continue
        
        elif choice == '0':
            # Exit
            print("\n👋 Thank you for using Smart Healthcare Privacy System!")
            print("Stay secure! 🔐\n")
            break
        
        else:
            print("\n⚠ Invalid choice! Please enter a number between 0 and 10.")
        
        input("\n⏎ Press Enter to continue...")


if __name__ == "__main__":
    main()