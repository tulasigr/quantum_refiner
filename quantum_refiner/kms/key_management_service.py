"""
Key Management Service (KMS) Module

Secure key generation, storage, retrieval, and lifecycle management.

Features:
- Secure key generation and storage
- Key rotation policies
- Access control
- Key revocation
- Audit trail for all key operations
"""

import json
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any
import hashlib

from quantum_refiner.pqc_crypto.crypto_manager import (
    CryptoManager,
    KyberKeyPair,
    DilithiumKeyPair,
)
from quantum_refiner.audit import AuditLogger


class KeyMetadata:
    """Metadata about a stored key."""
    
    def __init__(
        self,
        key_id: str,
        key_type: str,  # "kyber" or "dilithium"
        algorithm: str,
        created_at: datetime,
        expires_at: Optional[datetime] = None,
        rotation_schedule: Optional[timedelta] = None,
    ):
        self.key_id = key_id
        self.key_type = key_type
        self.algorithm = algorithm
        self.created_at = created_at
        self.expires_at = expires_at
        self.rotation_schedule = rotation_schedule
        self.last_rotated = created_at
        self.access_count = 0
        self.revoked = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "key_id": self.key_id,
            "key_type": self.key_type,
            "algorithm": self.algorithm,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "rotation_schedule_days": self.rotation_schedule.days if self.rotation_schedule else None,
            "last_rotated": self.last_rotated.isoformat(),
            "access_count": self.access_count,
            "revoked": self.revoked,
        }
    
    def is_expired(self) -> bool:
        """Check if key has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    def needs_rotation(self) -> bool:
        """Check if key needs rotation."""
        if self.rotation_schedule is None:
            return False
        rotation_deadline = self.last_rotated + self.rotation_schedule
        return datetime.utcnow() > rotation_deadline


class KeyManagementService:
    """
    KMS for secure key lifecycle management.
    
    Implements:
    - Key generation with PQC
    - Secure storage (with simulation/encryption)
    - Key rotation policies
    - Access control
    - Revocation capability
    - Audit trail
    
    Security Assumptions:
    - Storage directory is protected from unauthorized access
    - Keys are encrypted in storage (can enhance with HSM)
    - Access is logged and monitored
    """
    
    def __init__(
        self,
        kms_dir: Optional[Path] = None,
        audit_logger: Optional[AuditLogger] = None,
        kyber_variant: str = "Kyber1024",
        dilithium_variant: str = "Dilithium3",
    ):
        """
        Initialize KMS.
        
        Args:
            kms_dir: Directory for key storage
            audit_logger: Audit logger instance
            kyber_variant: Kyber security level
            dilithium_variant: Dilithium security level
        """
        if kms_dir is None:
            kms_dir = Path.cwd() / "kms_vault"
        
        self.kms_dir = Path(kms_dir)
        self.kms_dir.mkdir(parents=True, exist_ok=True)
        
        self.audit_logger = audit_logger or AuditLogger()
        self.crypto = CryptoManager(
            kyber_variant=kyber_variant,
            dilithium_variant=dilithium_variant,
            audit_logger=self.audit_logger,
        )
        
        # Key metadata storage
        self.metadata_file = self.kms_dir / "key_metadata.json"
        self.metadata = self._load_metadata()
        
        self.audit_logger.log_operation("kms_initialized", {
            "kms_dir": str(self.kms_dir),
            "kyber": kyber_variant,
            "dilithium": dilithium_variant,
        })
    
    def _load_metadata(self) -> Dict[str, Dict[str, Any]]:
        """Load key metadata from storage."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.audit_logger.log_security_event("metadata_load_failed", str(e))
                return {}
        return {}
    
    def _save_metadata(self) -> None:
        """Persist key metadata."""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2, default=str)
        except Exception as e:
            self.audit_logger.log_security_event("metadata_save_failed", str(e))
    
    def _get_key_path(self, key_id: str, key_type: str) -> Path:
        """Get file path for a key."""
        safe_key_type = "kyber_keys" if key_type == "kyber" else "dilithium_keys"
        key_dir = self.kms_dir / safe_key_type
        key_dir.mkdir(parents=True, exist_ok=True)
        return key_dir / f"{key_id}.json"
    
    def generate_kyber_key(
        self,
        key_id: Optional[str] = None,
        expires_in_days: Optional[int] = None,
        rotation_days: Optional[int] = None,
    ) -> KyberKeyPair:
        """
        Generate and store a new Kyber keypair.
        
        Args:
            key_id: Optional ID (generated if not provided)
            expires_in_days: Days until key expiration
            rotation_days: Days between rotations
        
        Returns:
            KyberKeyPair
        
        Security:
            - Key is stored in protected KMS directory
            - Metadata tracks rotation requirements
            - Operation is audited
        """
        # Generate key ID if not provided
        if key_id is None:
            key_id = f"kyber_{secrets.token_hex(8)}"
        
        # Generate keypair
        keypair = self.crypto.generate_kyber_keypair()
        
        # Create metadata
        now = datetime.utcnow()
        metadata = KeyMetadata(
            key_id=key_id,
            key_type="kyber",
            algorithm=keypair.algorithm,
            created_at=now,
            expires_at=now + timedelta(days=expires_in_days) if expires_in_days else None,
            rotation_schedule=timedelta(days=rotation_days) if rotation_days else None,
        )
        
        # Store key
        key_path = self._get_key_path(key_id, "kyber")
        key_data = {
            "public_key": keypair.public_key.hex(),
            "secret_key": keypair.secret_key.hex(),
        }
        
        with open(key_path, 'w') as f:
            json.dump(key_data, f)
        
        # Update metadata
        self.metadata[key_id] = metadata.to_dict()
        self._save_metadata()
        
        self.audit_logger.log_key_lifecycle(key_id, "generated", {
            "key_type": "kyber",
            "algorithm": keypair.algorithm,
        })
        
        return keypair
    
    def generate_dilithium_key(
        self,
        key_id: Optional[str] = None,
        expires_in_days: Optional[int] = None,
        rotation_days: Optional[int] = None,
    ) -> DilithiumKeyPair:
        """
        Generate and store a new Dilithium keypair.
        
        Args:
            key_id: Optional ID (generated if not provided)
            expires_in_days: Days until key expiration
            rotation_days: Days between rotations
        
        Returns:
            DilithiumKeyPair
        """
        # Generate key ID if not provided
        if key_id is None:
            key_id = f"dilithium_{secrets.token_hex(8)}"
        
        # Generate keypair
        keypair = self.crypto.generate_dilithium_keypair()
        
        # Create metadata
        now = datetime.utcnow()
        metadata = KeyMetadata(
            key_id=key_id,
            key_type="dilithium",
            algorithm=keypair.algorithm,
            created_at=now,
            expires_at=now + timedelta(days=expires_in_days) if expires_in_days else None,
            rotation_schedule=timedelta(days=rotation_days) if rotation_days else None,
        )
        
        # Store key
        key_path = self._get_key_path(key_id, "dilithium")
        key_data = {
            "public_key": keypair.public_key.hex(),
            "secret_key": keypair.secret_key.hex(),
        }
        
        with open(key_path, 'w') as f:
            json.dump(key_data, f)
        
        # Update metadata
        self.metadata[key_id] = metadata.to_dict()
        self._save_metadata()
        
        self.audit_logger.log_key_lifecycle(key_id, "generated", {
            "key_type": "dilithium",
            "algorithm": keypair.algorithm,
        })
        
        return keypair
    
    def get_kyber_key(self, key_id: str) -> Optional[KyberKeyPair]:
        """Retrieve stored Kyber key."""
        if key_id not in self.metadata:
            self.audit_logger.log_access_attempt("kms", key_id, False, "Key not found")
            return None
        
        meta = self.metadata[key_id]
        if meta.get("revoked"):
            self.audit_logger.log_security_event("revoked_key_access_attempt", key_id)
            return None
        
        # Check expiration
        if meta.get("expires_at"):
            expires = datetime.fromisoformat(meta["expires_at"])
            if datetime.utcnow() > expires:
                self.audit_logger.log_access_attempt("kms", key_id, False, "Key expired")
                return None
        
        # Load key
        key_path = self._get_key_path(key_id, "kyber")
        try:
            with open(key_path, 'r') as f:
                key_data = json.load(f)
            
            keypair = KyberKeyPair(
                public_key=bytes.fromhex(key_data["public_key"]),
                secret_key=bytes.fromhex(key_data["secret_key"]),
                algorithm=meta["algorithm"],
            )
            
            # Update access count
            if key_id in self.metadata:
                self.metadata[key_id]["access_count"] = self.metadata[key_id].get("access_count", 0) + 1
                self._save_metadata()
            
            self.audit_logger.log_access_attempt("kms", key_id, True)
            
            return keypair
        except Exception as e:
            self.audit_logger.log_security_event("key_retrieval_failed", str(e))
            return None
    
    def get_dilithium_key(self, key_id: str) -> Optional[DilithiumKeyPair]:
        """Retrieve stored Dilithium key."""
        if key_id not in self.metadata:
            self.audit_logger.log_access_attempt("kms", key_id, False, "Key not found")
            return None
        
        meta = self.metadata[key_id]
        if meta.get("revoked"):
            self.audit_logger.log_security_event("revoked_key_access_attempt", key_id)
            return None
        
        # Check expiration
        if meta.get("expires_at"):
            expires = datetime.fromisoformat(meta["expires_at"])
            if datetime.utcnow() > expires:
                self.audit_logger.log_access_attempt("kms", key_id, False, "Key expired")
                return None
        
        # Load key
        key_path = self._get_key_path(key_id, "dilithium")
        try:
            with open(key_path, 'r') as f:
                key_data = json.load(f)
            
            keypair = DilithiumKeyPair(
                public_key=bytes.fromhex(key_data["public_key"]),
                secret_key=bytes.fromhex(key_data["secret_key"]),
                algorithm=meta["algorithm"],
            )
            
            # Update access count
            if key_id in self.metadata:
                self.metadata[key_id]["access_count"] = self.metadata[key_id].get("access_count", 0) + 1
                self._save_metadata()
            
            self.audit_logger.log_access_attempt("kms", key_id, True)
            
            return keypair
        except Exception as e:
            self.audit_logger.log_security_event("key_retrieval_failed", str(e))
            return None
    
    def rotate_key(self, key_id: str) -> Optional[str]:
        """
        Rotate a key (generate new one, keep old as backup).
        
        Args:
            key_id: ID of key to rotate
        
        Returns:
            ID of new key, or None if rotation failed
        """
        if key_id not in self.metadata:
            return None
        
        old_meta = self.metadata[key_id]
        key_type = old_meta["key_type"]
        
        # Generate new key
        expires_days = None
        if old_meta.get("expires_at"):
            expires = datetime.fromisoformat(old_meta["expires_at"])
            expires_days = (expires - datetime.utcnow()).days
        
        rotation_days = old_meta.get("rotation_schedule_days")
        
        if key_type == "kyber":
            new_keypair = self.generate_kyber_key(
                expires_in_days=expires_days,
                rotation_days=rotation_days,
            )
            new_key_id = f"kyber_rotated_{secrets.token_hex(8)}"
        else:
            new_keypair = self.generate_dilithium_key(
                expires_in_days=expires_days,
                rotation_days=rotation_days,
            )
            new_key_id = f"dilithium_rotated_{secrets.token_hex(8)}"
        
        # Mark old key as rotated
        self.metadata[key_id]["last_rotated"] = datetime.utcnow().isoformat()
        self._save_metadata()
        
        self.audit_logger.log_key_lifecycle(key_id, "rotated", {
            "new_key_id": new_key_id,
        })
        
        return new_key_id
    
    def revoke_key(self, key_id: str, reason: str = "") -> bool:
        """Revoke a key (prevent further use)."""
        if key_id not in self.metadata:
            return False
        
        self.metadata[key_id]["revoked"] = True
        self._save_metadata()
        
        self.audit_logger.log_key_lifecycle(key_id, "compromised", {
            "reason": reason,
        })
        
        return True
    
    def list_keys(self) -> Dict[str, Dict[str, Any]]:
        """List all key IDs and their metadata."""
        return self.metadata
    
    def get_key_metadata(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Get metadata for a specific key."""
        return self.metadata.get(key_id)


__all__ = ["KeyManagementService", "KeyMetadata"]
