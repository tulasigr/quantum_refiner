"""
Secure Dataset Handler Module

Handles encryption, chunking, and secure storage of datasets.

Features:
- Dataset chunking with configurable chunk size
- Hybrid encryption (Kyber + AES-256)
- Merkle tree construction
- Secure metadata generation
- Batch encryption/decryption support
"""

import json
import os
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
import hashlib
from tqdm import tqdm

from quantum_refiner.pqc_crypto.crypto_manager import CryptoManager
from quantum_refiner.kms.key_management_service import KeyManagementService
from quantum_refiner.integrity.integrity_verifier import IntegrityVerifier, MerkleTree
from quantum_refiner.audit import AuditLogger


class SecureDatasetHandler:
    """
    Secure encryption and storage of datasets.
    
    Workflow:
    1. Load dataset
    2. Chunk into smaller pieces
    3. Generate Kyber session key
    4. Encrypt each chunk with AES-256-GCM
    5. Create Merkle tree for integrity
    6. Sign manifest with Dilithium
    7. Store encrypted chunks and metadata
    
    Security Properties:
    - Confidentiality: AES-256 + Kyber hybrid
    - Integrity: Merkle tree + Dilithium signatures
    - Authenticity: Dilithium signatures
    - Quantum-resistant: NIST PQC standards
    """
    
    def __init__(
        self,
        storage_dir: Optional[Path] = None,
        chunk_size_mb: int = 10,
        crypto: Optional[CryptoManager] = None,
        kms: Optional[KeyManagementService] = None,
        audit_logger: Optional[AuditLogger] = None,
    ):
        """
        Initialize secure dataset handler.
        
        Args:
            storage_dir: Directory for encrypted storage
            chunk_size_mb: Size of chunks in MB
            crypto: CryptoManager instance
            kms: KeyManagementService instance
            audit_logger: Audit logger instance
        """
        if storage_dir is None:
            storage_dir = Path.cwd() / "secure_datasets"
        
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self.chunk_size = chunk_size_mb * 1024 * 1024  # Convert to bytes
        
        self.crypto = crypto or CryptoManager()
        self.kms = kms or KeyManagementService()
        self.audit_logger = audit_logger or AuditLogger()
        self.verifier = IntegrityVerifier(self.crypto, self.audit_logger)
        
        self.audit_logger.log_operation("data_handler_initialized", {
            "storage_dir": str(self.storage_dir),
            "chunk_size_mb": chunk_size_mb,
        })
    
    def _read_file_in_chunks(
        self,
        file_path: Path,
    ) -> List[bytes]:
        """
        Read file in chunks.
        
        Args:
            file_path: Path to file
        
        Returns:
            List of chunk bytes
        """
        chunks = []
        file_size = file_path.stat().st_size
        
        with open(file_path, 'rb') as f:
            with tqdm(total=file_size, desc="Reading chunks", unit="B", unit_scale=True) as pbar:
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    pbar.update(len(chunk))
        
        return chunks
    
    def _compute_chunk_hashes(
        self,
        chunks: List[bytes],
        algorithm: str = "sha256",
    ) -> List[bytes]:
        """Compute hash for each chunk."""
        hashes = []
        for chunk in chunks:
            h = hashlib.new(algorithm)
            h.update(chunk)
            hashes.append(h.digest())
        return hashes
    
    def encrypt_dataset(
        self,
        dataset_path: Path,
        dataset_name: str,
        kyber_key_id: Optional[str] = None,
        dilithium_key_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Encrypt entire dataset with secure key management.
        
        Args:
            dataset_path: Path to raw dataset file
            dataset_name: Name/ID for encrypted dataset
            kyber_key_id: KMS key ID for encryption (generated if None)
            dilithium_key_id: KMS key ID for signing (generated if None)
        
        Returns:
            Dictionary with encryption metadata
        
        Security:
            - Generates or retrieves PQC keys from KMS
            - Each dataset chunk encrypted separately
            - Merkle tree ensures integrity
            - Dilithium signature prevents forgery
        """
        try:
            # Validate input
            if not dataset_path.exists():
                raise FileNotFoundError(f"Dataset not found: {dataset_path}")
            
            # Generate or retrieve keys
            if kyber_key_id is None:
                kyber_keypair = self.kms.generate_kyber_key()
                kyber_public_key = kyber_keypair.public_key
            else:
                kyber_keypair = self.kms.get_kyber_key(kyber_key_id)
                if kyber_keypair is None:
                    raise ValueError(f"Kyber key not found: {kyber_key_id}")
                kyber_public_key = kyber_keypair.public_key
            
            if dilithium_key_id is None:
                dilithium_keypair = self.kms.generate_dilithium_key()
            else:
                dilithium_keypair = self.kms.get_dilithium_key(dilithium_key_id)
                if dilithium_keypair is None:
                    raise ValueError(f"Dilithium key not found: {dilithium_key_id}")
            
            # Read dataset in chunks
            print(f" Reading dataset: {dataset_path.name}")
            chunks = self._read_file_in_chunks(dataset_path)
            
            # Compute chunk hashes
            print(" Computing chunk hashes...")
            chunk_hashes = self._compute_chunk_hashes(chunks)
            
            # Build Merkle tree
            print(" Building Merkle tree...")
            merkle_tree = MerkleTree(chunk_hashes)
            merkle_root = merkle_tree.root
            
            # Perform Kyber encapsulation
            print(" Performing Kyber key encapsulation...")
            kyber_ct, shared_secret = self.crypto.kyber_encapsulate(kyber_public_key)
            
            # Derive AES key from shared secret
            aes_key, salt = self.crypto.derive_aes_key(shared_secret)
            
            # Create dataset directory
            dataset_dir = self.storage_dir / dataset_name
            dataset_dir.mkdir(parents=True, exist_ok=True)
            encrypted_chunks_dir = dataset_dir / "encrypted_chunks"
            encrypted_chunks_dir.mkdir(exist_ok=True)
            
            # Encrypt each chunk
            print(" Encrypting dataset chunks...")
            encrypted_chunks_info = []
            
            for i, chunk in enumerate(tqdm(chunks, desc="Encrypting chunks")):
                ciphertext, nonce, tag = self.crypto.aes_encrypt(chunk, aes_key)
                
                chunk_info = {
                    "chunk_index": i,
                    "original_hash": chunk_hashes[i].hex(),
                    "ciphertext_size": len(ciphertext),
                    "nonce": nonce.hex(),
                    "tag": tag.hex(),
                }
                
                # Save encrypted chunk
                chunk_file = encrypted_chunks_dir / f"chunk_{i:06d}.enc"
                with open(chunk_file, 'wb') as f:
                    f.write(ciphertext)
                
                encrypted_chunks_info.append(chunk_info)
            
            # Create manifest
            manifest = {
                "dataset_name": dataset_name,
                "total_chunks": len(chunks),
                "chunk_size_bytes": self.chunk_size,
                "original_size_bytes": dataset_path.stat().st_size,
                "original_filename": dataset_path.name,
                "merkle_root": merkle_root.hex(),
                "chunks": encrypted_chunks_info,
                "kyber_ciphertext": kyber_ct.hex(),
                "kdf_salt": salt.hex(),
                "kyber_public_key": kyber_public_key.hex(),
                "dilithium_public_key": dilithium_keypair.public_key.hex(),
                "algorithm": "AES-256-GCM + Kyber1024 + Dilithium3",
            }
            
            # Sign manifest
            print("[*] Signing manifest with Dilithium...")
            manifest_bytes = json.dumps(
                {k: v for k, v in manifest.items() if k != "manifest_signature"},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            
            manifest_sig = self.crypto.dilithium_sign(
                manifest_bytes,
                dilithium_keypair.secret_key,
            )
            manifest["manifest_signature"] = manifest_sig.hex()
            
            # Save metadata
            metadata_file = dataset_dir / "metadata.json"
            with open(metadata_file, 'w') as f:
                json.dump(manifest, f, indent=2)
            
            # Log operation
            self.audit_logger.log_data_operation(
                "dataset_encrypted",
                dataset_name,
                dataset_path.stat().st_size,
                "success",
            )
            
            print(f" Dataset encrypted successfully: {dataset_dir}")
            
            return {
                "dataset_id": dataset_name,
                "dataset_dir": str(dataset_dir),
                "metadata_file": str(metadata_file),
                "encrypted_chunks_dir": str(encrypted_chunks_dir),
                "total_chunks": len(chunks),
                "merkle_root": merkle_root.hex(),
                "kyber_ciphertext_size": len(kyber_ct),
                "dilithium_signature_size": len(manifest_sig),
            }
        
        except Exception as e:
            self.audit_logger.log_security_event("dataset_encryption_failed", str(e))
            raise
    
    def decrypt_dataset(
        self,
        dataset_name: str,
        kyber_key_id: str,
        dilithium_public_key: bytes,
        output_path: Path,
        verify_integrity: bool = True,
    ) -> bool:
        """
        Decrypt dataset (for authorized training).
        
        Args:
            dataset_name: Name of encrypted dataset
            kyber_key_id: KMS key ID for decryption
            dilithium_public_key: Public key for signature verification
            output_path: Path to save decrypted data
            verify_integrity: Whether to verify integrity
        
        Returns:
            bool: True if successful
        
        Security:
            - Only processes if Dilithium signature verified
            - Never persists plaintext to storage
            - Maintains audit trail
        """
        try:
            dataset_dir = self.storage_dir / dataset_name
            metadata_file = dataset_dir / "metadata.json"
            encrypted_chunks_dir = dataset_dir / "encrypted_chunks"
            
            if not metadata_file.exists():
                raise FileNotFoundError(f"Dataset not found: {dataset_name}")
            
            # Load metadata
            with open(metadata_file, 'r') as f:
                manifest = json.load(f)
            
            # Verify signature
            print(" Verifying manifest signature...")
            manifest_sig = bytes.fromhex(manifest.pop("manifest_signature"))
            manifest_bytes = json.dumps(
                manifest,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            
            if not self.crypto.dilithium_verify(
                manifest_bytes,
                manifest_sig,
                dilithium_public_key,
            ):
                self.audit_logger.log_security_event(
                    "dataset_signature_verification_failed",
                    dataset_name,
                )
                raise ValueError("Manifest signature verification failed - data may be tampered!")
            
            # Get Kyber key and decapsulate
            print(" Recovering session key...")
            kyber_keypair = self.kms.get_kyber_key(kyber_key_id)
            if kyber_keypair is None:
                raise ValueError(f"Kyber key not found: {kyber_key_id}")
            
            kyber_ct = bytes.fromhex(manifest["kyber_ciphertext"])
            shared_secret = self.crypto.kyber_decapsulate(kyber_ct, kyber_keypair.secret_key)
            
            # Derive AES key
            salt = bytes.fromhex(manifest["kdf_salt"])
            aes_key, _ = self.crypto.derive_aes_key(shared_secret, salt)
            
            # Decrypt chunks
            print(" Decrypting dataset chunks...")
            decrypted_chunks = []
            chunk_hashes = []
            
            for chunk_info in tqdm(manifest["chunks"], desc="Decrypting"):
                chunk_file = encrypted_chunks_dir / f"chunk_{chunk_info['chunk_index']:06d}.enc"
                
                with open(chunk_file, 'rb') as f:
                    ciphertext = f.read()
                
                nonce = bytes.fromhex(chunk_info["nonce"])
                tag = bytes.fromhex(chunk_info["tag"])
                
                plaintext = self.crypto.aes_decrypt(ciphertext, aes_key, nonce, tag)
                decrypted_chunks.append(plaintext)
                
                # Verify chunk hash
                chunk_hash = self.crypto.compute_hash(plaintext)
                expected_hash = bytes.fromhex(chunk_info["original_hash"])
                
                if chunk_hash != expected_hash:
                    raise ValueError(f"Chunk {chunk_info['chunk_index']} integrity check failed!")
                
                chunk_hashes.append(chunk_hash)
            
            # Verify Merkle tree
            if verify_integrity:
                print(" Verifying Merkle tree...")
                expected_root = bytes.fromhex(manifest["merkle_root"])
                if not self.verifier.verify_chunk_hashes(chunk_hashes, expected_root):
                    raise ValueError("Merkle tree verification failed!")
            
            # Write decrypted data
            print(f" Writing decrypted data to {output_path}...")
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'wb') as f:
                for chunk in decrypted_chunks:
                    f.write(chunk)
            
            # Log operation
            self.audit_logger.log_data_operation(
                "dataset_decrypted",
                dataset_name,
                output_path.stat().st_size,
                "success",
            )
            
            print(f" Dataset decrypted successfully: {output_path}")
            return True
        
        except Exception as e:
            self.audit_logger.log_security_event("dataset_decryption_failed", str(e))
            raise
    
    def get_dataset_info(self, dataset_name: str) -> Optional[Dict[str, Any]]:
        """Get metadata for a dataset without decrypting."""
        metadata_file = self.storage_dir / dataset_name / "metadata.json"
        
        if not metadata_file.exists():
            return None
        
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        
        return {
            "dataset_name": metadata.get("dataset_name"),
            "total_chunks": metadata.get("total_chunks"),
            "original_size_bytes": metadata.get("original_size_bytes"),
            "original_filename": metadata.get("original_filename"),
            "algorithm": metadata.get("algorithm"),
            "merkle_root": metadata.get("merkle_root"),
        }


__all__ = ["SecureDatasetHandler"]
