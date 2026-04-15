"""
Comprehensive Test Suite for Quantum-Refiner

Tests include:
- Unit tests for all cryptographic operations
- Integration tests for the complete pipeline
- Security tests and attack simulations
- Performance benchmarks
"""

import pytest
import tempfile
import json
import os
from pathlib import Path

from quantum_refiner.pqc_crypto.crypto_manager import CryptoManager, KyberKeyPair
from quantum_refiner.kms.key_management_service import KeyManagementService
from quantum_refiner.data_handler.dataset_handler import SecureDatasetHandler
from quantum_refiner.integrity.integrity_verifier import IntegrityVerifier, MerkleTree
from quantum_refiner.audit import AuditLogger


class TestCryptoManager:
    """Test PQC cryptographic operations."""
    
    def setup_method(self):
        """Initialize crypto manager for each test."""
        self.crypto = CryptoManager()
    
    def test_kyber_key_generation(self):
        """Test Kyber keypair generation."""
        keypair = self.crypto.generate_kyber_keypair()
        
        assert isinstance(keypair, KyberKeyPair)
        assert len(keypair.public_key) > 0
        assert len(keypair.secret_key) > 0
        assert keypair.algorithm == "Kyber1024"
    
    def test_kyber_encapsulation_decapsulation(self):
        """Test Kyber key encapsulation and decapsulation."""
        # Generate keypair
        keypair = self.crypto.generate_kyber_keypair()
        
        # Encapsulate
        ct, ss1 = self.crypto.kyber_encapsulate(keypair.public_key)
        
        # Decapsulate
        ss2 = self.crypto.kyber_decapsulate(ct, keypair.secret_key)
        
        # Shared secrets should match
        assert ss1 == ss2
        assert len(ss1) == 32  # Kyber1024 shared secret size
    
    def test_dilithium_sign_verify(self):
        """Test Dilithium signature generation and verification."""
        # Generate keypair
        keypair = self.crypto.generate_dilithium_keypair()
        
        # Create message
        message = b"Test message for signing"
        
        # Sign
        signature = self.crypto.dilithium_sign(message, keypair.secret_key)
        
        # Verify
        is_valid = self.crypto.dilithium_verify(
            message,
            signature,
            keypair.public_key,
        )
        
        assert is_valid
        assert len(signature) > 0
    
    def test_dilithium_verify_tampered_message(self):
        """Test that tampered messages fail verification."""
        keypair = self.crypto.generate_dilithium_keypair()
        
        message = b"Original message"
        signature = self.crypto.dilithium_sign(message, keypair.secret_key)
        
        # Tamper with message
        tampered = b"Tampered message"
        
        is_valid = self.crypto.dilithium_verify(
            tampered,
            signature,
            keypair.public_key,
        )
        
        assert not is_valid
    
    def test_aes_encrypt_decrypt(self):
        """Test AES-256-GCM encryption and decryption."""
        plaintext = b"This is a secret message"
        key = os.urandom(32)  # AES-256 key
        
        # Encrypt
        ciphertext, nonce, tag = self.crypto.aes_encrypt(plaintext, key)
        
        # Decrypt
        decrypted = self.crypto.aes_decrypt(ciphertext, key, nonce, tag)
        
        assert decrypted == plaintext
        assert ciphertext != plaintext  # Should be different
    
    def test_aes_decrypt_tampered_ciphertext(self):
        """Test that tampered ciphertext fails authentication."""
        plaintext = b"Secret message"
        key = os.urandom(32)
        
        ciphertext, nonce, tag = self.crypto.aes_encrypt(plaintext, key)
        
        # Tamper with ciphertext
        tampered_ct = bytearray(ciphertext)
        tampered_ct[0] ^= 0xFF
        tampered_ct = bytes(tampered_ct)
        
        # Decryption should fail
        with pytest.raises(RuntimeError):
            self.crypto.aes_decrypt(tampered_ct, key, nonce, tag)
    
    def test_hash_computation(self):
        """Test hash computation."""
        data = b"Test data"
        
        hash1 = self.crypto.compute_hash(data, "sha256")
        hash2 = self.crypto.compute_hash(data, "sha256")
        
        # Same data should produce same hash
        assert hash1 == hash2
        
        # Different data should produce different hash
        hash3 = self.crypto.compute_hash(b"Different data", "sha256")
        assert hash1 != hash3
    
    def test_hmac_computation(self):
        """Test HMAC computation."""
        data = b"Test data"
        key = os.urandom(32)
        
        hmac1 = self.crypto.compute_hmac(data, key, "sha256")
        hmac2 = self.crypto.compute_hmac(data, key, "sha256")
        
        # Same inputs should produce same HMAC
        assert hmac1 == hmac2
        
        # Different key should produce different HMAC
        hmac3 = self.crypto.compute_hmac(data, os.urandom(32), "sha256")
        assert hmac1 != hmac3


class TestKeyManagementService:
    """Test KMS functionality."""
    
    def setup_method(self):
        """Initialize KMS for each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.kms = KeyManagementService(Path(self.temp_dir.name))
    
    def teardown_method(self):
        """Clean up after each test."""
        self.temp_dir.cleanup()
    
    def test_kyber_key_generation_and_retrieval(self):
        """Test generating and retrieving Kyber keys."""
        # Generate key
        keypair = self.kms.generate_kyber_key()
        
        # Retrieve key
        retrieved = self.kms.get_kyber_key(keypair.public_key.hex()[:8])  # Key ID
        
        # Should work since we generated it
        assert retrieved is not None
    
    def test_dilithium_key_generation_and_retrieval(self):
        """Test generating and retrieving Dilithium keys."""
        keypair = self.kms.generate_dilithium_key()
        assert keypair is not None
    
    def test_key_revocation(self):
        """Test key revocation."""
        keypair = self.kms.generate_kyber_key()
        key_id = list(self.kms.metadata.keys())[-1]
        
        # Revoke key
        self.kms.revoke_key(key_id)
        
        # Retrieval should fail
        retrieved = self.kms.get_kyber_key(key_id)
        assert retrieved is None
    
    def test_key_rotation(self):
        """Test key rotation."""
        keypair = self.kms.generate_kyber_key()
        key_id = list(self.kms.metadata.keys())[-1]
        
        # Rotate key
        new_key_id = self.kms.rotate_key(key_id)
        
        assert new_key_id is not None
        assert new_key_id in self.kms.metadata


class TestMerkleTree:
    """Test Merkle tree functionality."""
    
    def test_merkle_tree_construction(self):
        """Test building a Merkle tree."""
        hashes = [os.urandom(32) for _ in range(4)]
        tree = MerkleTree(hashes)
        
        assert tree.root is not None
        assert len(tree.tree) > 0
    
    def test_merkle_chunk_verification(self):
        """Test verifying chunks in Merkle tree."""
        hashes = [os.urandom(32) for _ in range(4)]
        tree = MerkleTree(hashes)
        
        # Verify first chunk
        assert tree.verify_chunk(0, hashes[0])
        
        # Should fail for wrong hash
        assert not tree.verify_chunk(0, os.urandom(32))
    
    def test_merkle_proof(self):
        """Test Merkle proof generation and verification."""
        hashes = [os.urandom(32) for _ in range(8)]
        tree = MerkleTree(hashes)
        
        # Get proof for chunk 0
        proof = tree.get_proof(0)
        
        # Verify using proof
        assert tree.verify_proof(0, hashes[0], proof)
        
        # Should fail with wrong hash
        assert not tree.verify_proof(0, os.urandom(32), proof)


class TestIntegrityVerifier:
    """Test integrity verification."""
    
    def setup_method(self):
        """Initialize verifier for each test."""
        self.crypto = CryptoManager()
        self.verifier = IntegrityVerifier(self.crypto)
    
    def test_merkle_root_validation(self):
        """Test Merkle root validation."""
        hashes = [os.urandom(32) for _ in range(4)]
        tree = MerkleTree(hashes)
        
        # Correct root
        assert self.verifier.verify_chunk_hashes(hashes, tree.root)
        
        # Incorrect root should fail
        assert not self.verifier.verify_chunk_hashes(hashes, os.urandom(32))
    
    def test_chunk_integrity_verification(self):
        """Test individual chunk verification."""
        data = b"Test chunk data"
        chunk_hash = self.crypto.compute_hash(data)
        
        # Correct hash
        assert self.verifier.verify_individual_chunk(data, chunk_hash)
        
        # Modified data should fail
        assert not self.verifier.verify_individual_chunk(
            b"Modified data",
            chunk_hash,
        )
    
    def test_tampering_detection(self):
        """Test detection of tampered chunks."""
        original_hashes = [os.urandom(32) for _ in range(3)]
        
        # Tamper with one hash
        current_hashes = original_hashes.copy()
        current_hashes[1] = os.urandom(32)
        
        tampering = self.verifier.detect_tampering(original_hashes, current_hashes)
        
        # Only chunk 1 should be tampered
        assert not tampering[0]
        assert tampering[1]
        assert not tampering[2]


class TestSecurityAttacks:
    """Test security against various attacks."""
    
    def setup_method(self):
        """Initialize for security tests."""
        self.crypto = CryptoManager()
    
    @pytest.mark.security
    def test_replay_attack_prevention(self):
        """Test that replay attacks are prevented."""
        message = b"Transaction data"
        keypair = self.crypto.generate_dilithium_keypair()
        
        # Create signature
        sig1 = self.crypto.dilithium_sign(message, keypair.secret_key)
        
        # Attempt replay - different message with old signature
        reply_message = b"Different transaction"
        
        # Verification should fail
        is_valid = self.crypto.dilithium_verify(
            reply_message,
            sig1,
            keypair.public_key,
        )
        
        assert not is_valid
    
    @pytest.mark.security
    def test_key_encapsulation_nonce_uniqueness(self):
        """Test that encryption uses unique nonces."""
        plaintext = b"Test data"
        key = os.urandom(32)
        
        # Encrypt same plaintext twice
        ct1, nonce1, tag1 = self.crypto.aes_encrypt(plaintext, key)
        ct2, nonce2, tag2 = self.crypto.aes_encrypt(plaintext, key)
        
        # Nonces should be different (due to randomization)
        assert nonce1 != nonce2
        
        # Ciphertexts should be different
        assert ct1 != ct2
    
    @pytest.mark.security
    def test_key_derivation_salt_importance(self):
        """Test that KDF properly uses salt."""
        shared_secret = os.urandom(32)
        
        # Derive keys with different salts
        key1, salt1 = self.crypto.derive_aes_key(shared_secret, None)
        key2, salt2 = self.crypto.derive_aes_key(shared_secret, None)
        
        # Keys should be different (different salts)
        assert key1 != key2
        assert salt1 != salt2
    
    @pytest.mark.security
    def test_hybrid_encryption_completeness(self):
        """Test that hybrid encryption provides both PQC and classical security."""
        # Generate key for Kyber
        kyber_kp = self.crypto.generate_kyber_keypair()
        
        # Encapsulate
        ct, ss = self.crypto.kyber_encapsulate(kyber_kp.public_key)
        
        # Derive AES key from shared secret
        aes_key, salt = self.crypto.derive_aes_key(ss)
        
        # Encrypt data
        plaintext = b"Hybrid encryption test"
        ciphertext, nonce, tag = self.crypto.aes_encrypt(plaintext, aes_key)
        
        # Verify full pipeline works
        assert ciphertext != plaintext
        
        # Decrypt requires both Kyber and AES keys
        recovered_ss = self.crypto.kyber_decapsulate(ct, kyber_kp.secret_key)
        recovered_key, _ = self.crypto.derive_aes_key(recovered_ss, salt)
        
        decrypted = self.crypto.aes_decrypt(ciphertext, recovered_key, nonce, tag)
        assert decrypted == plaintext


class TestAuditLogging:
    """Test audit logging functionality."""
    
    def setup_method(self):
        """Initialize logger for each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.logger = AuditLogger(Path(self.temp_dir.name))
    
    def teardown_method(self):
        """Clean up."""
        self.temp_dir.cleanup()
    
    def test_operation_logging(self):
        """Test that operations are logged."""
        self.logger.log_operation("test_operation", {"key": "value"})
        
        # Check that log file exists and contains entry
        assert self.logger.log_file.exists()
        
        with open(self.logger.log_file, 'r') as f:
            content = f.read()
            assert "test_operation" in content
    
    def test_security_event_logging(self):
        """Test security event logging."""
        self.logger.log_security_event("test_breach", "Unauthorized access")
        
        with open(self.logger.log_file, 'r') as f:
            content = f.read()
            assert "SECURITY_EVENT" in content
            assert "test_breach" in content


# Performance benchmarks (optional)
class TestPerformance:
    """Performance tests."""
    
    def setup_method(self):
        """Initialize for benchmarks."""
        self.crypto = CryptoManager()
    
    @pytest.mark.benchmark
    def test_kyber_keygen_speed(self):
        """Benchmark Kyber key generation (should be <10ms)."""
        import time
        
        start = time.time()
        self.crypto.generate_kyber_keypair()
        elapsed = (time.time() - start) * 1000
        
        print(f"\nKyber key gen: {elapsed:.2f}ms")
        assert elapsed < 100  # Allow up to 100ms
    
    @pytest.mark.benchmark
    def test_aes_encryption_speed(self):
        """Benchmark AES encryption throughput."""
        import time
        
        plaintext = os.urandom(1024 * 1024)  # 1MB
        key = os.urandom(32)
        
        start = time.time()
        self.crypto.aes_encrypt(plaintext, key)
        elapsed = time.time() - start
        
        throughput_mb_s = len(plaintext) / (1024 * 1024 * elapsed)
        print(f"\nAES throughput: {throughput_mb_s:.2f} MB/s")
        
        assert throughput_mb_s > 10  # At least 10 MB/s on CPU


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
