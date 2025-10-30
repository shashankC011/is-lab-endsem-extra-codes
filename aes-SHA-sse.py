import hashlib
import json
import os
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import re
'''Encrypted Search Engine (Searchable Encryption + Hashing + AES)

Implement a searchable encryption prototype:

Store encrypted documents using AES.

Index words using SHA-256 hashes.

Implement search queries using a Searchable Symmetric Encryption (SSE) approach to return matches without decrypting.'''

class EncryptedSearchEngine:
    def __init__(self):
        self.master_key = get_random_bytes(32)  # 256-bit AES key
        self.documents = {}  # {doc_id: encrypted_data}
        self.inverted_index = {}  # {word_hash: [doc_ids]}
        self.doc_metadata = {}  # {doc_id: {title, iv, word_hashes}}
        self.doc_counter = 0
        
    def _aes_encrypt(self, plaintext, key):
        """Encrypt data using AES-256 in CBC mode"""
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
        return b64encode(iv).decode('utf-8'), b64encode(ciphertext).decode('utf-8')
    
    def _aes_decrypt(self, iv, ciphertext, key):
        """Decrypt data using AES-256 in CBC mode"""
        iv = b64decode(iv)
        ciphertext = b64decode(ciphertext)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode('utf-8')
    
    def _hash_word(self, word):
        """Create SHA-256 hash of a word for indexing"""
        return hashlib.sha256(word.lower().encode('utf-8')).hexdigest()
    
    def _tokenize(self, text):
        """Extract words from text"""
        # Remove punctuation and convert to lowercase
        words = re.findall(r'\b[a-zA-Z]+\b', text.lower())
        return set(words)  # Return unique words
    
    def add_document(self, title, content):
        """Add a new encrypted document to the database"""
        self.doc_counter += 1
        doc_id = f"doc_{self.doc_counter}"
        
        # Encrypt the document content
        iv, encrypted_content = self._aes_encrypt(content, self.master_key)
        
        # Store encrypted document
        self.documents[doc_id] = encrypted_content
        
        # Extract and index words
        words = self._tokenize(content)
        word_hashes = []
        
        for word in words:
            word_hash = self._hash_word(word)
            word_hashes.append(word_hash)
            
            # Update inverted index
            if word_hash not in self.inverted_index:
                self.inverted_index[word_hash] = []
            self.inverted_index[word_hash].append(doc_id)
        
        # Store metadata
        self.doc_metadata[doc_id] = {
            'title': title,
            'iv': iv,
            'word_hashes': word_hashes
        }
        
        return doc_id
    
    def search(self, query):
        """Search for documents containing the query term without decryption"""
        query_hash = self._hash_word(query)
        
        # Find matching documents using the inverted index
        if query_hash in self.inverted_index:
            matching_doc_ids = self.inverted_index[query_hash]
            results = []
            
            for doc_id in matching_doc_ids:
                results.append({
                    'doc_id': doc_id,
                    'title': self.doc_metadata[doc_id]['title']
                })
            
            return results
        
        return []
    
    def retrieve_document(self, doc_id):
        """Decrypt and return a specific document"""
        if doc_id not in self.documents:
            return None
        
        iv = self.doc_metadata[doc_id]['iv']
        encrypted_content = self.documents[doc_id]
        
        # Decrypt the document
        decrypted_content = self._aes_decrypt(iv, encrypted_content, self.master_key)
        
        return {
            'doc_id': doc_id,
            'title': self.doc_metadata[doc_id]['title'],
            'content': decrypted_content
        }
    
    def list_all_documents(self):
        """List all document titles without decrypting content"""
        return [
            {
                'doc_id': doc_id,
                'title': metadata['title']
            }
            for doc_id, metadata in self.doc_metadata.items()
        ]
    
    def get_statistics(self):
        """Display system statistics"""
        return {
            'total_documents': len(self.documents),
            'unique_words_indexed': len(self.inverted_index),
            'encryption_algorithm': 'AES-256-CBC',
            'hashing_algorithm': 'SHA-256'
        }


def print_menu():
    """Display the main menu"""
    print("\n" + "="*60)
    print("       ENCRYPTED SEARCH ENGINE (SSE + AES)")
    print("="*60)
    print("1. Add New Document")
    print("2. Search Documents")
    print("3. Retrieve Document (Decrypt)")
    print("4. List All Documents")
    print("5. System Statistics")
    print("6. Exit")
    print("="*60)


def main():
    engine = EncryptedSearchEngine()
    
    # Pre-populate with sample documents
    print("\n🔒 Initializing Encrypted Search Engine...")
    print("📄 Adding sample documents...\n")
    
    sample_docs = [
        ("Cryptography Basics", "Cryptography is the practice of secure communication in the presence of adversaries. It involves encryption and decryption techniques."),
        ("Machine Learning Introduction", "Machine learning is a subset of artificial intelligence that enables systems to learn from data and improve performance."),
        ("Blockchain Technology", "Blockchain is a decentralized ledger technology that ensures secure and transparent transactions using cryptography."),
        ("Quantum Computing", "Quantum computing leverages quantum mechanics to process information in fundamentally different ways than classical computers.")
    ]
    
    for title, content in sample_docs:
        doc_id = engine.add_document(title, content)
        print(f"✓ Added: {title} [{doc_id}]")
    
    # Main menu loop
    while True:
        print_menu()
        choice = input("\nEnter your choice (1-6): ").strip()
        
        if choice == '1':
            print("\n--- ADD NEW DOCUMENT ---")
            title = input("Enter document title: ").strip()
            print("Enter document content (press Enter twice to finish):")
            lines = []
            while True:
                line = input()
                if line == "" and lines and lines[-1] == "":
                    break
                lines.append(line)
            content = "\n".join(lines[:-1])  # Remove last empty line
            
            if title and content:
                doc_id = engine.add_document(title, content)
                print(f"\n✓ Document encrypted and added successfully! [ID: {doc_id}]")
            else:
                print("\n✗ Error: Title and content cannot be empty!")
        
        elif choice == '2':
            print("\n--- SEARCH DOCUMENTS ---")
            query = input("Enter search term: ").strip()
            
            if query:
                print(f"\n🔍 Searching for '{query}' using SHA-256 hash...")
                results = engine.search(query)
                
                if results:
                    print(f"\n✓ Found {len(results)} matching document(s):")
                    for i, result in enumerate(results, 1):
                        print(f"  {i}. [{result['doc_id']}] {result['title']}")
                else:
                    print(f"\n✗ No documents found containing '{query}'")
            else:
                print("\n✗ Please enter a search term!")
        
        elif choice == '3':
            print("\n--- RETRIEVE DOCUMENT ---")
            doc_id = input("Enter document ID: ").strip()
            
            doc = engine.retrieve_document(doc_id)
            
            if doc:
                print(f"\n🔓 Decrypting document...")
                print(f"\nTitle: {doc['title']}")
                print(f"ID: {doc['doc_id']}")
                print("-" * 60)
                print(doc['content'])
                print("-" * 60)
            else:
                print(f"\n✗ Document '{doc_id}' not found!")
        
        elif choice == '4':
            print("\n--- ALL DOCUMENTS ---")
            docs = engine.list_all_documents()
            
            if docs:
                print(f"\nTotal Documents: {len(docs)}\n")
                for i, doc in enumerate(docs, 1):
                    print(f"  {i}. [{doc['doc_id']}] {doc['title']}")
            else:
                print("\n✗ No documents in the system!")
        
        elif choice == '5':
            print("\n--- SYSTEM STATISTICS ---")
            stats = engine.get_statistics()
            print(f"\nTotal Documents: {stats['total_documents']}")
            print(f"Unique Words Indexed: {stats['unique_words_indexed']}")
            print(f"Encryption: {stats['encryption_algorithm']}")
            print(f"Hashing: {stats['hashing_algorithm']}")
        
        elif choice == '6':
            print("\n🔒 Securing system and exiting...")
            print("Goodbye!\n")
            break
        
        else:
            print("\n✗ Invalid choice! Please enter a number between 1 and 6.")
        
        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()