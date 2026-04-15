"""
Integrity Verification Module

Verifies authenticity and integrity of encrypted datasets.

Features:
- Merkle tree construction for chunk integrity
- Dilithium signature verification
- Tamper detection
- Dataset root hash validation
"""

import json
import hashlib
from typing import List, Optional, Dict, Any
from pathlib import Path

from quantum_refiner.pqc_crypto.crypto_manager import CryptoManager
from quantum_refiner.audit import AuditLogger


class MerkleTree:
    """
    Merkle tree for dataset chunk verification.
    
    Allows efficient verification of dataset integrity without
    requiring re-hashing entire dataset.
    """
    
    def __init__(self, chunk_hashes: List[bytes], algorithm: str = "sha256"):
        """
        Build Merkle tree from chunk hashes.
        
        Args:
            chunk_hashes: List of hashes for each chunk
            algorithm: Hash algorithm to use
        """
        self.chunk_hashes = chunk_hashes
        self.algorithm = algorithm
        self.tree = self._build_tree()
        self.root = self.tree[-1][0] if self.tree else b""
    
    def _build_tree(self) -> List[List[bytes]]:
        """Build Merkle tree structure."""
        if not self.chunk_hashes:
            return []
        
        current_level = self.chunk_hashes[:]
        levels = [current_level]
        
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    combined = current_level[i] + current_level[i + 1]
                else:
                    combined = current_level[i] + current_level[i]
                
                h = hashlib.new(self.algorithm)
                h.update(combined)
                next_level.append(h.digest())
            
            levels.append(next_level)
            current_level = next_level
        
        return levels
    
    def verify_chunk(self, chunk_index: int, chunk_hash: bytes) -> bool:
        """
        Verify that a chunk belongs to this tree.
        
        Args:
            chunk_index: Index of chunk
            chunk_hash: Hash of chunk
        
        Returns:
            bool: True if chunk is valid
        """
        if chunk_index >= len(self.chunk_hashes):
            return False
        
        return self.chunk_hashes[chunk_index] == chunk_hash
    
    def get_proof(self, chunk_index: int) -> List[bytes]:
        """
        Get Merkle proof for a chunk (for compact verification).
        
        Args:
            chunk_index: Index of chunk
        
        Returns:
            List of hashes needed to verify this chunk
        """
        if chunk_index >= len(self.chunk_hashes):
            return []
        
        proof = []
        index = chunk_index
        
        for level in self.tree[:-1]:
            if index % 2 == 0:
                if index + 1 < len(level):
                    proof.append(level[index + 1])
            else:
                proof.append(level[index - 1])
            
            index //= 2
        
        return proof
    
    def verify_proof(
        self,
        chunk_index: int,
        chunk_hash: bytes,
        proof: List[bytes],
    ) -> bool:
        """
        Verify a chunk using Merkle proof.
        
        Args:
            chunk_index: Index of chunk
            chunk_hash: Hash of chunk
            proof: Merkle proof
        
        Returns:
            bool: True if proof is valid
        """
        current_hash = chunk_hash
        index = chunk_index
        
        for proof_hash in proof:
            if index % 2 == 0:
                combined = current_hash + proof_hash
            else:
                combined = proof_hash + current_hash
            
            h = hashlib.new(self.algorithm)
            h.update(combined)
            current_hash = h.digest()
            index //= 2
        
        return current_hash == self.root


class IntegrityVerifier:
    """
    Verifies dataset integrity using Merkle tree and Dilithium signatures.
    
    Security:
    - Detects any dataset tampering
    - Prevents unauthorized modifications
    - Quantum-resistant (Dilithium)
    """
    
    def __init__(
        self,
        crypto: Optional[CryptoManager] = None,
        audit_logger: Optional[AuditLogger] = None,
    ):
        """
        Initialize integrity verifier.
        
        Args:
            crypto: CryptoManager instance
            audit_logger: Audit logger instance
        """
        self.crypto = crypto or CryptoManager()
        self.audit_logger = audit_logger or AuditLogger()
    
    def verify_dataset_signature(
        self,
        manifest_data: Dict[str, Any],
        signature: bytes,
        public_key: bytes,
    ) -> bool:
        """
        Verify dataset manifest signature.
        
        Args:
            manifest_data: Dataset manifest dictionary
            signature: Dilithium signature
            public_key: Dilithium public key
        
        Returns:
            bool: True if signature is valid
        
        Security:
            - Uses quantum-resistant Dilithium
            - Prevents forged manifests
            - Returns False for invalid (doesn't raise exception for security)
        """
        try:
            # Serialize manifest
            manifest_bytes = json.dumps(
                manifest_data,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            
            # Verify signature
            is_valid = self.crypto.dilithium_verify(
                manifest_bytes,
                signature,
                public_key,
            )
            
            if is_valid:
                self.audit_logger.log_operation("manifest_signature_valid", {
                    "pubkey_size": len(public_key),
                })
            else:
                self.audit_logger.log_security_event(
                    "manifest_signature_invalid",
                    "Signature verification failed",
                )
            
            return is_valid
        except Exception as e:
            self.audit_logger.log_security_event("manifest_verification_error", str(e))
            return False
    
    def verify_chunk_hashes(
        self,
        chunk_hashes: List[bytes],
        expected_root: bytes,
        algorithm: str = "sha256",
    ) -> bool:
        """
        Verify Merkle tree root matches expected root.
        
        Args:
            chunk_hashes: List of chunk hashes
            expected_root: Expected Merkle root hash
            algorithm: Hash algorithm
        
        Returns:
            bool: True if root matches
        """
        tree = MerkleTree(chunk_hashes, algorithm)
        
        if tree.root == expected_root:
            self.audit_logger.log_operation("merkle_root_valid", {
                "chunks": len(chunk_hashes),
            })
            return True
        else:
            self.audit_logger.log_security_event(
                "merkle_root_mismatch",
                f"Expected {expected_root.hex()}, got {tree.root.hex()}",
            )
            return False
    
    def verify_individual_chunk(
        self,
        chunk_data: bytes,
        expected_hash: bytes,
        chunk_index: int = 0,
        algorithm: str = "sha256",
    ) -> bool:
        """
        Verify integrity of individual chunk.
        
        Args:
            chunk_data: Chunk content
            expected_hash: Expected hash
            chunk_index: Index of chunk (for audit)
            algorithm: Hash algorithm
        
        Returns:
            bool: True if chunk is valid
        """
        actual_hash = self.crypto.compute_hash(chunk_data, algorithm)
        
        is_valid = actual_hash == expected_hash
        
        event = "chunk_integrity_valid" if is_valid else "chunk_integrity_failed"
        self.audit_logger.log_operation(event, {
            "chunk_index": chunk_index,
            "hash_algorithm": algorithm,
        })
        
        return is_valid
    
    def verify_complete_dataset(
        self,
        metadata_path: Path,
        chunk_hashes: List[bytes],
        public_key: bytes,
    ) -> Dict[str, Any]:
        """
        Complete dataset integrity verification.
        
        Args:
            metadata_path: Path to metadata.json
            chunk_hashes: List of all chunk hashes
            public_key: Public key for signature verification
        
        Returns:
            Dictionary with verification results
        """
        results = {
            "valid": False,
            "errors": [],
            "checks": {
                "signature_valid": False,
                "merkle_valid": False,
                "chunks_count_valid": False,
            }
        }
        
        try:
            # Load metadata
            if not metadata_path.exists():
                results["errors"].append("Metadata file not found")
                return results
            
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            # Check chunk count
            if len(chunk_hashes) != metadata.get("total_chunks", 0):
                results["errors"].append(
                    f"Chunk count mismatch: {len(chunk_hashes)} vs {metadata.get('total_chunks')}"
                )
            else:
                results["checks"]["chunks_count_valid"] = True
            
            # Verify signature
            if "manifest_signature" in metadata:
                sig_bytes = bytes.fromhex(metadata["manifest_signature"])
                manifest_data = {
                    k: v for k, v in metadata.items()
                    if k != "manifest_signature"
                }
                
                sig_valid = self.verify_dataset_signature(
                    manifest_data,
                    sig_bytes,
                    public_key,
                )
                results["checks"]["signature_valid"] = sig_valid
                
                if not sig_valid:
                    results["errors"].append("Manifest signature verification failed")
            
            # Verify Merkle tree
            if "merkle_root" in metadata:
                expected_root = bytes.fromhex(metadata["merkle_root"])
                merkle_valid = self.verify_chunk_hashes(
                    chunk_hashes,
                    expected_root,
                )
                results["checks"]["merkle_valid"] = merkle_valid
                
                if not merkle_valid:
                    results["errors"].append("Merkle tree root mismatch")
            
            # Overall result
            results["valid"] = all(results["checks"].values())
            
            if results["valid"]:
                self.audit_logger.log_operation("dataset_verified", {
                    "chunks": len(chunk_hashes),
                })
            else:
                self.audit_logger.log_security_event(
                    "dataset_verification_failed",
                    json.dumps(results["errors"]),
                )
            
            return results
        except Exception as e:
            results["errors"].append(f"Verification error: {str(e)}")
            self.audit_logger.log_security_event("verification_error", str(e))
            return results
    
    def detect_tampering(
        self,
        original_hashes: List[bytes],
        current_hashes: List[bytes],
    ) -> Dict[int, bool]:
        """
        Detect which chunks have been tampered with.
        
        Args:
            original_hashes: Original chunk hashes
            current_hashes: Current chunk hashes
        
        Returns:
            Dictionary mapping chunk index to tamper status
        """
        tampering = {}
        
        for i, (orig, curr) in enumerate(zip(original_hashes, current_hashes)):
            if orig != curr:
                tampering[i] = True
                self.audit_logger.log_security_event(
                    "tampering_detected",
                    f"Chunk {i} has been modified",
                )
            else:
                tampering[i] = False
        
        return tampering


__all__ = ["IntegrityVerifier", "MerkleTree"]
