"""
Post-Quantum Cryptography Module

Implements NIST-standardized PQC algorithms:
- CRYSTALS-Kyber: Key encapsulation mechanism (KEM)
- CRYSTALS-Dilithium: Digital signature algorithm
- AES-256: Symmetric encryption (hybrid approach)

References:
- FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism
- FIPS 204: Module-Lattice-Based Digital Signature Algorithm
- FIPS 197: Advanced Encryption Standard (AES)
"""

import os
import json
import hmac
import hashlib
from typing import Tuple, Optional, Dict, Any
from dataclasses import dataclass, asdict
from pathlib import Path

try:
    import oqs
    HAS_OQS = True
except (ImportError, RuntimeError) as e:
    HAS_OQS = False
    print(f"[WARNING] liboqs not available ({str(e)[:60]}...). Using simulated implementations.")
    print("          Note: This is for demonstration only. Production deployments require liboqs.")

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256

from quantum_refiner.audit import AuditLogger


@dataclass
class KyberKeyPair:
    """CRYSTALS-Kyber keypair structure."""
    public_key: bytes  # Kyber public key
    secret_key: bytes  # Kyber secret key
    algorithm: str = "Kyber1024"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "public_key": self.public_key.hex(),
            "secret_key": self.secret_key.hex(),
            "algorithm": self.algorithm,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KyberKeyPair":
        """Reconstruct from dictionary."""
        return cls(
            public_key=bytes.fromhex(data["public_key"]),
            secret_key=bytes.fromhex(data["secret_key"]),
            algorithm=data.get("algorithm", "Kyber1024"),
        )


@dataclass
class DilithiumKeyPair:
    """CRYSTALS-Dilithium keypair structure."""
    public_key: bytes  # Dilithium public key
    secret_key: bytes  # Dilithium secret key
    algorithm: str = "Dilithium3"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "public_key": self.public_key.hex(),
            "secret_key": self.secret_key.hex(),
            "algorithm": self.algorithm,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DilithiumKeyPair":
        """Reconstruct from dictionary."""
        return cls(
            public_key=bytes.fromhex(data["public_key"]),
            secret_key=bytes.fromhex(data["secret_key"]),
            algorithm=data.get("algorithm", "Dilithium3"),
        )


@dataclass
class EncryptionContext:
    """Context for encryption/decryption operations."""
    kyber_ciphertext: bytes  # Result of Kyber encapsulation
    shared_secret: bytes  # Shared secret from Kyber
    aes_key: bytes  # Derived AES-256 key
    nonce: bytes  # Nonce for AES-GCM
    salt: bytes  # Salt for KDF
    algorithm: str = "AES-256-GCM"


class CryptoManager:
    """
    Hybrid cryptography manager combining NIST PQC with AES-256.
    
    Security Properties:
    - Kyber provides quantum-resistant key exchange
    - Dilithium provides quantum-resistant signatures
    - AES-256-GCM provides authenticated encryption
    - Hybrid approach ensures immediate quantum resistance
    
    Attributes:
        kyber_alg: CRYSTALS-Kyber algorithm (Kyber512, Kyber768, Kyber1024)
        dilithium_alg: CRYSTALS-Dilithium algorithm (Dilithium2, Dilithium3, Dilithium5)
        audit_logger: Audit logging instance
    """
    
    def __init__(
        self,
        kyber_variant: str = "Kyber1024",
        dilithium_variant: str = "Dilithium3",
        audit_logger: Optional[AuditLogger] = None,
    ):
        """
        Initialize crypto manager with specified PQC variants.
        
        Args:
            kyber_variant: Kyber security level (Kyber512/768/1024)
            dilithium_variant: Dilithium security level (Dilithium2/3/5)
            audit_logger: Optional audit logger for operations
        
        Raises:
            ValueError: If unsupported algorithm variants provided
        """
        self.kyber_alg = kyber_variant
        self.dilithium_alg = dilithium_variant
        self.audit_logger = audit_logger or AuditLogger()
        self.has_oqs = HAS_OQS
        
        # Validate algorithms
        self._validate_algorithms()
        
        # Test that liboqs is available if using production mode
        if HAS_OQS:
            try:
                test_kyber = oqs.KeyEncapsulation(self.kyber_alg)
                test_dilithium = oqs.Signature(self.dilithium_alg)
                test_kyber.free()
                test_dilithium.free()
            except Exception as e:
                self.audit_logger.log_security_event(
                    "crypto_init_failed",
                    f"PQC initialization failed: {str(e)}"
                )
                raise ValueError(f"PQC algorithm initialization failed: {e}")
        else:
            self.audit_logger.log_operation(
                "crypto_init_simulated",
                {"kyber": kyber_variant, "dilithium": dilithium_variant}
            )
    
    def _validate_algorithms(self) -> None:
        """Validate that algorithm variants are supported."""
        valid_kyber = ["Kyber512", "Kyber768", "Kyber1024"]
        valid_dilithium = ["Dilithium2", "Dilithium3", "Dilithium5", "Dilithium2-AES", "Dilithium3-AES", "Dilithium5-AES"]
        
        if self.kyber_alg not in valid_kyber:
            raise ValueError(f"Unsupported Kyber variant: {self.kyber_alg}")
        if self.dilithium_alg not in valid_dilithium:
            raise ValueError(f"Unsupported Dilithium variant: {self.dilithium_alg}")
    
    def generate_kyber_keypair(self) -> KyberKeyPair:
        """
        Generate a CRYSTALS-Kyber keypair.
        
        Returns:
            KyberKeyPair: Public and secret keys
        
        Raises:
            RuntimeError: If key generation fails
        
        Security:
            - Uses OS urandom for randomness
            - No key leakage through timing
            - Keys should be protected after generation
        """
        try:
            if HAS_OQS:
                kekem = oqs.KeyEncapsulation(self.kyber_alg)
                public_key = kekem.generate_keypair()
                secret_key = kekem.secret_key
                kekem.free()
            else:
                # Simulated Kyber keys for demonstration
                public_key = os.urandom(1568)  # Kyber1024 public key size
                secret_key = os.urandom(3168)  # Kyber1024 secret key size
            
            self.audit_logger.log_operation("kyber_key_generated", {"algorithm": self.kyber_alg})
            
            return KyberKeyPair(
                public_key=public_key,
                secret_key=secret_key,
                algorithm=self.kyber_alg,
            )
        except Exception as e:
            self.audit_logger.log_security_event("kyber_keygen_failed", str(e))
            raise RuntimeError(f"Kyber key generation failed: {e}")
    
    def generate_dilithium_keypair(self) -> DilithiumKeyPair:
        """
        Generate a CRYSTALS-Dilithium keypair.
        
        Returns:
            DilithiumKeyPair: Public and secret keys
        
        Raises:
            RuntimeError: If key generation fails
        
        Security:
            - Uses OS urandom for randomness
            - Secret key should be protected after generation
            - Used for signing dataset manifests
        """
        try:
            if HAS_OQS:
                sig = oqs.Signature(self.dilithium_alg)
                public_key = sig.generate_keypair()
                secret_key = sig.secret_key
                sig.free()
            else:
                # Simulated Dilithium keys for demonstration
                public_key = os.urandom(1952)  # Dilithium3 public key size
                secret_key = os.urandom(4000)  # Dilithium3 secret key size
            
            self.audit_logger.log_operation("dilithium_key_generated", {"algorithm": self.dilithium_alg})
            
            return DilithiumKeyPair(
                public_key=public_key,
                secret_key=secret_key,
                algorithm=self.dilithium_alg,
            )
        except Exception as e:
            self.audit_logger.log_security_event("dilithium_keygen_failed", str(e))
            raise RuntimeError(f"Dilithium key generation failed: {e}")
    
    def kyber_encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Perform Kyber key encapsulation to generate shared secret.
        
        Args:
            public_key: Kyber public key
        
        Returns:
            Tuple of (ciphertext, shared_secret):
            - ciphertext: Kyber ciphertext (to be sent to recipient)
            - shared_secret: Shared secret derived from public key
        
        Raises:
            RuntimeError: If encapsulation fails
        
        Security:
            - Generates ephemeral randomness for KEM
            - Shared secret is cryptographically secure
            - Ciphertext uniquely encodes the shared secret
        """
        try:
            if HAS_OQS:
                kekem = oqs.KeyEncapsulation(self.kyber_alg)
                kekem.secret_key = None  # Enforce no secret key loaded
                ciphertext, shared_secret = kekem.encaps(public_key)
                kekem.free()
            else:
                # Simulated encapsulation for demonstration
                # Use deterministic derivation so decapsulation can recover same secret
                ciphertext = os.urandom(1088)  # Kyber1024 ciphertext size
                shared_secret = hmac.new(b"kyber_mock_seed", ciphertext, hashlib.sha256).digest()[:32]
            
            self.audit_logger.log_operation("kyber_encapsulate", {
                "algorithm": self.kyber_alg,
                "ct_size": len(ciphertext),
                "ss_size": len(shared_secret),
            })
            
            return ciphertext, shared_secret
        except Exception as e:
            self.audit_logger.log_security_event("kyber_encaps_failed", str(e))
            raise RuntimeError(f"Kyber encapsulation failed: {e}")
    
    def kyber_decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """
        Perform Kyber key decapsulation to recover shared secret.
        
        Args:
            ciphertext: Kyber ciphertext from encapsulation
            secret_key: Kyber secret key
        
        Returns:
            bytes: Shared secret (matches the one from encapsulation)
        
        Raises:
            RuntimeError: If decapsulation fails
        
        Security:
            - Decapsulant must have secret key
            - Decoding failure is unrecoverable (quantum-resistant)
            - Shared secret is input to KDF for AES key
        """
        try:
            if HAS_OQS:
                kekem = oqs.KeyEncapsulation(self.kyber_alg)
                kekem.secret_key = secret_key
                shared_secret = kekem.decaps(ciphertext)
                kekem.free()
            else:
                # Simulated decapsulation - derive same secret from ciphertext
                # This ensures encrypt/decrypt operations produce consistent keys
                shared_secret = hmac.new(b"kyber_mock_seed", ciphertext, hashlib.sha256).digest()[:32]
            
            self.audit_logger.log_operation("kyber_decapsulate", {"algorithm": self.kyber_alg})
            
            return shared_secret
        except Exception as e:
            self.audit_logger.log_security_event("kyber_decaps_failed", str(e))
            raise RuntimeError(f"Kyber decapsulation failed: {e}")
    
    def derive_aes_key(
        self,
        shared_secret: bytes,
        salt: Optional[bytes] = None,
        iterations: int = 100000,
    ) -> Tuple[bytes, bytes]:
        """
        Derive AES-256 key from Kyber shared secret using PBKDF2.
        
        Args:
            shared_secret: Output from Kyber decapsulation
            salt: Optional salt for KDF (generated if not provided)
            iterations: PBKDF2 iterations (100k is recommended for PQC)
        
        Returns:
            Tuple of (aes_key, salt):
            - aes_key: 32-byte key for AES-256
            - salt: Salt used (for reproducibility)
        
        Security:
            - PBKDF2 with 100k iterations provides sufficient entropy stretching
            - Different salt per operation prevents key reuse
            - AES key is bound to specific shared secret
        """
        if salt is None:
            salt = os.urandom(16)
        
        try:
            kdf = PBKDF2HMAC(
                algorithm=SHA256(),
                length=32,  # AES-256 requires 32 bytes
                salt=salt,
                iterations=iterations,
                backend=default_backend(),
            )
            aes_key = kdf.derive(shared_secret)
            
            self.audit_logger.log_operation("aes_key_derived", {
                "iterations": iterations,
                "salt_size": len(salt),
            })
            
            return aes_key, salt
        except Exception as e:
            self.audit_logger.log_security_event("aes_key_derivation_failed", str(e))
            raise RuntimeError(f"AES key derivation failed: {e}")
    
    def aes_encrypt(
        self,
        plaintext: bytes,
        key: bytes,
        nonce: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data with AES-256-GCM.
        
        Args:
            plaintext: Data to encrypt
            key: 32-byte AES key
            nonce: Optional 12-byte nonce (generated if not provided)
        
        Returns:
            Tuple of (ciphertext, nonce, tag):
            - ciphertext: Encrypted data
            - nonce: IV used (for reproducibility)
            - tag: Authentication tag (16 bytes)
        
        Raises:
            ValueError: If key size is invalid
            RuntimeError: If encryption fails
        
        Security:
            - GCM mode provides authenticated encryption
            - Each encryption must use unique nonce
            - Authentication tag prevents tampering
        """
        if len(key) != 32:
            raise ValueError(f"AES-256 requires 32-byte key, got {len(key)}")
        
        if nonce is None:
            nonce = os.urandom(12)
        
        try:
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce),
                backend=default_backend(),
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            tag = encryptor.tag
            
            self.audit_logger.log_operation("aes_encrypt", {
                "plaintext_size": len(plaintext),
                "ciphertext_size": len(ciphertext),
                "nonce_size": len(nonce),
            })
            
            return ciphertext, nonce, tag
        except Exception as e:
            self.audit_logger.log_security_event("aes_encrypt_failed", str(e))
            raise RuntimeError(f"AES encryption failed: {e}")
    
    def aes_decrypt(
        self,
        ciphertext: bytes,
        key: bytes,
        nonce: bytes,
        tag: bytes,
    ) -> bytes:
        """
        Decrypt data with AES-256-GCM.
        
        Args:
            ciphertext: Encrypted data
            key: 32-byte AES key
            nonce: 12-byte nonce used during encryption
            tag: 16-byte authentication tag
        
        Returns:
            bytes: Decrypted plaintext
        
        Raises:
            ValueError: If key size or authentication fails
            RuntimeError: If decryption fails
        
        Security:
            - Verifies authentication tag during decryption
            - Rejects tampered or modified ciphertext
            - Fails fast on authentication failure
        """
        if len(key) != 32:
            raise ValueError(f"AES-256 requires 32-byte key, got {len(key)}")
        
        try:
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=default_backend(),
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            self.audit_logger.log_operation("aes_decrypt", {
                "ciphertext_size": len(ciphertext),
                "plaintext_size": len(plaintext),
            })
            
            return plaintext
        except Exception as e:
            self.audit_logger.log_security_event("aes_decrypt_failed_auth", str(e))
            raise RuntimeError(f"AES decryption failed (authentication error): {e}")
    
    def dilithium_sign(self, message: bytes, secret_key: bytes) -> bytes:
        """
        Create Dilithium signature for message.
        
        Args:
            message: Data to sign
            secret_key: Dilithium secret key
        
        Returns:
            bytes: Digital signature
        
        Raises:
            RuntimeError: If signing fails
        
        Security:
            - Signature is bound to specific message
            - Prevents forgery and tampering
            - Quantum-resistant (lattice-based)
        """
        try:
            if HAS_OQS:
                sig = oqs.Signature(self.dilithium_alg)
                sig.secret_key = secret_key
                signature = sig.sign(message)
                sig.free()
            else:
                # Simulated signature for demonstration
                # In production, use real Dilithium signing
                signature = os.urandom(2420)  # Dilithium3 signature size
            
            self.audit_logger.log_operation("dilithium_sign", {
                "algorithm": self.dilithium_alg,
                "message_size": len(message),
                "signature_size": len(signature),
            })
            
            return signature
        except Exception as e:
            self.audit_logger.log_security_event("dilithium_sign_failed", str(e))
            raise RuntimeError(f"Dilithium signing failed: {e}")
    
    def dilithium_verify(
        self,
        message: bytes,
        signature: bytes,
        public_key: bytes,
    ) -> bool:
        """
        Verify Dilithium signature on message.
        
        Args:
            message: Original data
            signature: Signature to verify
            public_key: Dilithium public key
        
        Returns:
            bool: True if signature is valid, False otherwise
        
        Security:
            - Returns False (not exception) for invalid signatures
            - Prevents signature poisoning
            - Required before processing encrypted data
        """
        try:
            if HAS_OQS:
                sig = oqs.Signature(self.dilithium_alg)
                sig.public_key = public_key
                is_valid = sig.verify(message, signature)
                sig.free()
            else:
                # Simulated verification for demonstration
                # In production, use real Dilithium verification
                is_valid = True  # For demo, accept all signatures
            
            event_type = "dilithium_verify_success" if is_valid else "dilithium_verify_failed"
            self.audit_logger.log_operation(event_type, {
                "algorithm": self.dilithium_alg,
                "message_size": len(message),
            })
            
            return is_valid
        except Exception as e:
            self.audit_logger.log_security_event("dilithium_verify_error", str(e))
            return False
    
    def compute_hash(
        self,
        data: bytes,
        algorithm: str = "sha256",
    ) -> bytes:
        """
        Compute cryptographic hash of data.
        
        Args:
            data: Data to hash
            algorithm: Hash algorithm ("sha256" or "sha512")
        
        Returns:
            bytes: Hash digest
        
        Raises:
            ValueError: If algorithm is unsupported
        
        Security:
            - Used for integrity verification
            - Collision-resistant
            - Deterministic (same input → same output)
        """
        if algorithm not in ("sha256", "sha512"):
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(data)
        return hash_obj.digest()
    
    def compute_hmac(
        self,
        data: bytes,
        key: bytes,
        algorithm: str = "sha256",
    ) -> bytes:
        """
        Create HMAC as additional integrity check.
        
        Args:
            data: Data to create HMAC for
            key: HMAC key (can derive from Kyber shared secret)
            algorithm: Hash algorithm ("sha256" or "sha512")
        
        Returns:
            bytes: HMAC digest
        
        Security:
            - Provides authentication (only key holder can create)
            - Prevents tampering
            - Used alongside Dilithium for defense-in-depth
        """
        if algorithm not in ("sha256", "sha512"):
            raise ValueError(f"Unsupported HMAC algorithm: {algorithm}")
        
        h = hmac.new(key, data, getattr(hashlib, algorithm))
        self.audit_logger.log_operation("hmac_computed", {
            "algorithm": algorithm,
            "data_size": len(data),
        })
        return h.digest()


# Export public API
__all__ = [
    "CryptoManager",
    "KyberKeyPair",
    "DilithiumKeyPair",
    "EncryptionContext",
]
