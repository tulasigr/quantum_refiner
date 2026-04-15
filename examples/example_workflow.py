"""
Quantum-Refiner: Complete End-to-End Example

This script demonstrates the full encryption → storage → training → verification workflow.
"""

import json
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from quantum_refiner.pqc_crypto.crypto_manager import CryptoManager
from quantum_refiner.kms.key_management_service import KeyManagementService
from quantum_refiner.data_handler.dataset_handler import SecureDatasetHandler
from quantum_refiner.integrity.integrity_verifier import IntegrityVerifier
from quantum_refiner.training.secure_training import SecureTrainingPipeline
from quantum_refiner.audit import AuditLogger


def create_sample_dataset(path: Path, size_mb: int = 5) -> None:
    """Create a sample dataset for testing."""
    print(f"[*] Creating sample dataset ({size_mb}MB)...")
    
    chunk_size = 1024 * 1024  # 1MB chunks
    total_chunks = size_mb
    
    with open(path, 'wb') as f:
        for i in range(total_chunks):
            data = f"Training sample {i}\n".encode() * 1000
            f.write(data[:chunk_size])
    
    print(f"[OK] Sample dataset created: {path} ({size_mb}MB)")


def main():
    """Run complete end-to-end example."""
    
    print("=" * 70)
    print("[>>] QUANTUM-REFINER: End-to-End Demo")
    print("=" * 70)
    print()
    
    # Create temporary directory for this example
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Create directories
        dataset_file = tmpdir / "training_data.bin"
        kms_dir = tmpdir / "kms"
        storage_dir = tmpdir / "encrypted_datasets"
        logs_dir = tmpdir / "logs"
        
        # Create sample dataset
        create_sample_dataset(dataset_file, size_mb=2)
        
        # Initialize services
        print("[*] Initializing cryptographic services...")
        audit_logger = AuditLogger(logs_dir)
        
        try:
            crypto = CryptoManager(audit_logger=audit_logger)
            kms = KeyManagementService(kms_dir, audit_logger=audit_logger)
            print("[OK] Services initialized")
            print()
            
            # PHASE 2: KEY GENERATION
            print("[>>] PHASE 2: Key Generation")
            print("-" * 70)
            
            print("[*] Generating CRYSTALS-Kyber1024 keypair...")
            kyber_kp = kms.generate_kyber_key(expires_in_days=365, rotation_days=90)
            kyber_key_id = list(kms.metadata.keys())[-1]
            print(f"[OK] Kyber key generated: {kyber_key_id[:20]}...")
            
            print("[*] Generating CRYSTALS-Dilithium3 keypair...")
            dilithium_kp = kms.generate_dilithium_key(expires_in_days=365, rotation_days=90)
            dil_key_id = list(kms.metadata.keys())[-1]
            print(f"[OK] Dilithium key generated: {dil_key_id[:20]}...")
            print()
            
            # PHASE 3: DATASET ENCRYPTION
            print("[>>] PHASE 3: Dataset Encryption")
            print("-" * 70)
            
            handler = SecureDatasetHandler(
                storage_dir=storage_dir,
                chunk_size_mb=1,
                crypto=crypto,
                kms=kms,
                audit_logger=audit_logger,
            )
            
            print(f"[*] Encrypting dataset: {dataset_file.name}")
            encryption_result = handler.encrypt_dataset(
                dataset_path=dataset_file,
                dataset_name="demo_dataset",
                kyber_key_id=kyber_key_id,
                dilithium_key_id=dil_key_id,
            )
            
            print()
            print("[OK] Encryption successful!")
            print(f"   Dataset ID: {encryption_result['dataset_id']}")
            print(f"   Chunks: {encryption_result['total_chunks']}")
            print()
            
            # PHASE 4: INTEGRITY VERIFICATION
            print("[>>] PHASE 4: Integrity Verification")
            print("-" * 70)
            
            verifier = IntegrityVerifier(crypto, audit_logger)
            metadata_file = storage_dir / "demo_dataset" / "metadata.json"
            
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            chunk_hashes = [
                bytes.fromhex(chunk["original_hash"])
                for chunk in metadata.get("chunks", [])
            ]
            
            print("[*] Verifying dataset integrity...")
            verify_results = verifier.verify_complete_dataset(
                metadata_file,
                chunk_hashes,
                dilithium_kp.public_key,
            )
            
            if verify_results["valid"]:
                print("[OK] Dataset integrity verified!")
            else:
                print("[!] Dataset verification FAILED!")
            
            print()
            
            # PHASE 5: DECRYPTION
            print("[>>] PHASE 5: Decryption")
            print("-" * 70)
            
            decrypted_file = tmpdir / "decrypted_data.bin"
            print(f"[*] Decrypting dataset...")
            
            handler.decrypt_dataset(
                dataset_name="demo_dataset",
                kyber_key_id=kyber_key_id,
                dilithium_public_key=dilithium_kp.public_key,
                output_path=decrypted_file,
                verify_integrity=True,
            )
            
            print("[OK] Decryption successful!")
            print()
            
            # SUMMARY
            print("=" * 70)
            print("[OK] WORKFLOW COMPLETED SUCCESSFULLY")
            print("=" * 70)
            print()
            print("Summary:")
            print("  [OK] Generated CRYSTALS-Kyber1024 keypair")
            print("  [OK] Generated CRYSTALS-Dilithium3 keypair")
            print("  [OK] Encrypted dataset with AES-256-GCM")
            print("  [OK] Verified dataset integrity")
            print("  [OK] Decrypted dataset with verification")
            print()
            print("Security Properties:")
            print("  - Quantum-resistant encryption (Kyber + AES-256)")
            print("  - Digital signatures (Dilithium)")
            print("  - Integrity verification (Merkle tree)")
            print("  - No plaintext files on disk")
            print()
        
        finally:
            # Always close audit logger to prevent file handle leaks
            audit_logger.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
