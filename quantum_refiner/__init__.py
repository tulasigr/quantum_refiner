"""
Quantum-Resilient Dataset Protection Framework

A production-ready Post-Quantum Cryptography framework for securing
LLM fine-tuning datasets using NIST PQC standards (CRYSTALS-Kyber,
CRYSTALS-Dilithium) with AES-256 bulk encryption.

Author: Quantum Security Team
Version: 1.0.0
License: MIT
"""

__version__ = "1.0.0"
__author__ = "Quantum Security Team"
__description__ = "Post-Quantum Cryptography Framework for LLM Dataset Security"

from quantum_refiner.pqc_crypto import CryptoManager
from quantum_refiner.kms import KeyManagementService
from quantum_refiner.data_handler import SecureDatasetHandler
from quantum_refiner.integrity import IntegrityVerifier
from quantum_refiner.audit import AuditLogger

__all__ = [
    "CryptoManager",
    "KeyManagementService",
    "SecureDatasetHandler",
    "IntegrityVerifier",
    "AuditLogger",
]
