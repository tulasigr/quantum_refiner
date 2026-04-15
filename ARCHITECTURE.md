# Quantum-Resilient Dataset Protection Framework
## Post-Quantum Cryptography for LLM Fine-Tuning Security

---

## 1. System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        LLM Fine-Tuning Pipeline                 │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
   ┌─────────┐          ┌──────────┐          ┌──────────┐
   │  Data   │          │ Training │          │ Model    │
   │Ingestion│          │ Pipeline │          │ Serving  │
   └────┬────┘          └────┬─────┘          └──────────┘
        │                    │
        ▼                    ▼
   ┌──────────────────────────────────┐
   │  Quantum-Resilient Security      │
   │        Framework                  │
   └──────────────────────────────────┘
        │          │          │          │
        ▼          ▼          ▼          ▼
   ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
   │  Data  │ │  Key   │ │Integrity│Audit & │
   │Encrypt │ │Manage  │ │Verif.   │Logging │
   │Handler │ │Service │ │ System  │        │
   └────────┘ └────────┘ └────────┘ └────────┘
```

---

## 2. Component Detailed Architecture

### 2.1 PQC Cryptography Module
```
┌─────────────────────────────────────┐
│    PQC Crypto Module                │
├─────────────────────────────────────┤
│                                     │
│ ┌─────────────────────────────────┐ │
│ │ CRYSTALS-Kyber (Key Encap)      │ │
│ │ - Generate keypair              │ │
│ │ - Encapsulate shared secret      │ │
│ │ - Decapsulate ciphertext        │ │
│ └─────────────────────────────────┘ │
│                                     │
│ ┌─────────────────────────────────┐ │
│ │ CRYSTALS-Dilithium (Signatures) │ │
│ │ - Sign data                     │ │
│ │ - Verify signature              │ │
│ │ - Key derivation                │ │
│ └─────────────────────────────────┘ │
│                                     │
│ ┌─────────────────────────────────┐ │
│ │ AES-256 (Bulk Encryption)       │ │
│ │ - GCM mode (authenticated)      │ │
│ │ - CBC mode (compatibility)      │ │
│ │ - Stream encryption             │ │
│ └─────────────────────────────────┘ │
│                                     │
└─────────────────────────────────────┘
```

### 2.2 Data Ingestion & Encryption Layer
```
Raw Dataset
    │
    ▼
┌─────────────────────────────────┐
│ Data Validation & Preprocessing │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│ Chunk Dataset (configurable)    │
│ - Hash each chunk (SHA-256)     │
│ - Build Merkle tree             │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│ Hybrid Encryption               │
│ - Session key (Kyber)           │
│ - Chunk encryption (AES-256)    │
│ - Sign with Dilithium           │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│ Encrypted Dataset Metadata      │
│ - Chunk hashes & tree root      │
│ - Signatures (per chunk)        │
│ - KDF parameters                │
└────────────┬────────────────────┘
             │
             ▼
Secure Storage Backend
```

### 2.3 Key Management Service (KMS)
```
┌──────────────────────────────────────┐
│   Key Management Service             │
└──────────────────────────────────────┘
        │           │           │
        ▼           ▼           ▼
   ┌────────┐  ┌────────┐  ┌─────────┐
   │  Key   │  │  Key   │  │  Key    │
   │ Gen    │  │Storage │  │Rotation │
   └────────┘  └────────┘  └─────────┘
        │           │           │
        ▼           ▼           ▼
   ┌────────────────────────────────────┐
   │ Key Hierarchy                      │
   │                                    │
   │ Root Master Key (KMK)              │
   │    │                              │
   │    ├── Dataset Encryption Key     │
   │    ├── Signing Key (Dilithium)    │
   │    └── KMS Key                     │
   │                                    │
   └────────────────────────────────────┘
```

### 2.4 Secure Training Pipeline
```
Encrypted Dataset → Decryption → Training
                       │
        ┌──────────────┼──────────────┐
        │              │              │
        ▼              ▼              ▼
   ┌────────┐    ┌──────────┐   ┌─────────┐
   │ Verify │    │ Stream   │   │ In-Mem  │
   │Integrity   │ Decrypt  │   │ Compute │
   │Signature   │ on-fly   │   │ (no     │
   │           │          │   │ persist)│
   └────────┘    └──────────┘   └─────────┘
```

---

## 3. Threat Model

### 3.1 Assets
- **Raw Training Datasets**: Sensitive, proprietary, personally identifiable information
- **Encryption Keys**: PQC private keys, symmetric session keys
- **Model weights**: Trained parameters (potential IP)
- **Metadata**: Dataset structure, access patterns

### 3.2 Threat Actors
1. **Passive Adversaries**: Eavesdrop on network/storage (wiretapping)
2. **Active Adversaries**: Modify data, inject false data, compromise keys
3. **Quantum Adversaries**: Future quantum computers breaking classical crypto
4. **Insider Threats**: Malicious employees with system access

### 3.3 Attacks & Mitigations

| Attack Vector | Threat | Mitigation |
|---------------|--------|-----------|
| **Store Break-in** | Extract encrypted dataset | AES-256 + Kyber hybrid encryption |
| **Network Eavesdrop** | Observe key exchange | CRYSTALS-Kyber (PQC) key encap |
| **Tampering** | Modify dataset chunks | CRYSTALS-Dilithium digital signatures |
| **Quantum Computer** | Break RSA/ECDSA | NIST PQC standards (Kyber, Dilithium) |
| **Key Compromise** | Decrypt all data | Key rotation support + access logs |
| **Replay Attack** | Reuse old ciphertext | Timestamps + nonces in metadata |
| **Unauthorized Access** | Load unencrypted dataset | Role-based access control + audit logs |
| **Forward Secrecy Loss** | Historical compromise | Session keys isolated per training run |

### 3.4 Security Assumptions
- **Trusted Execution**: KMS runs in trusted environment (can be simulated)
- **Secure Random**: OS `urandom` / `secrets` module
- **PQC Libraries**: liboqs-python assumes correct NIST implementation
- **Key Storage**: Assume keys protected (vault simulation provided)

---

## 4. Data Flow Diagrams

### 4.1 Encryption Pipeline
```
1. Load Raw Data
   ↓
2. Validate & Chunk
   ├─ Generate chunk hashes
   └─ Build Merkle tree root
   ↓
3. Generate Session Key
   ├─ Kyber: Generate KEM keypair
   ├─ Kyber: Encapsulate shared secret
   └─ Use shared secret as AES-256 session key
   ↓
4. Encrypt Each Chunk
   └─ AES-256-GCM with per-chunk nonce
   ↓
5. Sign Encrypted Data
   ├─ Dilithium: Sign dataset manifest
   └─ Dilithium: Sign each chunk hash
   ↓
6. Generate Metadata
   ├─ Merkle tree root
   ├─ Kyber ciphertext
   ├─ Dilithium signature
   └─ Chunk offsets & sizes
   ↓
7. Store Securely
   ├─ Encrypted chunks → encrypted_chunks/
   └─ Metadata + signatures → metadata.json
```

### 4.2 Training Pipeline
```
1. Load Encrypted Dataset Metadata
   ↓
2. Verify Integrity
   ├─ Reconstruct Merkle tree
   ├─ Verify Dilithium signature
   └─ Validate dataset root hash
   ↓
3. Get Session Key
   ├─ Load Kyber private key from KMS
   ├─ Decapsulate ciphertext → shared secret
   └─ Derive AES session key
   ↓
4. Create Data Loader
   ├─ Iterate encrypted chunks
   ├─ Decrypt on-the-fly (no persistence)
   ├─ Validate chunk hash
   └─ Stream to training
   ↓
5. Train Model
   └─ Use plaintext only in GPU memory
   ↓
6. Save Model
   └─ Optionally encrypt weights (AES-256)
```

---

## 5. Key Exchange & Encryption Protocol

### 5.1 Kyber-AES Hybrid Flow
```
Dataset Owner:
1. Generate Kyber keypair (pk_kyber, sk_kyber)
2. Encapsulate shared secret: (ct, shared_secret) = Kyber.Encaps(pk_kyber)
3. Derive AES key: key = KDF(shared_secret, salt)

Trainer:
1. Receive ct from encrypted dataset
2. Load sk_kyber from KMS
3. Decapsulate: shared_secret = Kyber.Decaps(ct, sk_kyber)
4. Derive AES key: key = KDF(shared_secret, salt)
5. Decrypt chunks: plaintext = AES.Dec(key, nonce, ciphertext)
```

### 5.2 Dilithium Signature Protocol
```
Signing (Encryption Phase):
1. dataset_manifest = {chunk_hashes[], merkle_root, timestamp}
2. manifest_hash = SHA256(manifest)
3. sig = Dilithium.Sign(manifest_hash, sk_dilithium)
4. Store sig in metadata.json

Verification (Training Phase):
1. Load sig and pk_dilithium from metadata
2. manifest_hash = SHA256(manifest)
3. Dilithium.Verify(sig, manifest_hash, pk_dilithium) → bool
4. If verification fails, raise SecurityError
```

---

## 6. Security Properties

| Property | Mechanism | Quantum-Safe |
|----------|-----------|-------------|
| **Confidentiality** | AES-256-GCM + Kyber KEM | ✅ Yes |
| **Integrity** | HMAC-SHA256 + Dilithium | ✅ Yes |
| **Authenticity** | CRYSTALS-Dilithium | ✅ Yes |
| **Key Exchange** | CRYSTALS-Kyber (PQC KEM) | ✅ Yes |
| **Forward Secrecy** | Per-session keys + rotation | ✅ Yes |
| **Resistance to Harvest-Now-Decrypt-Later** | PQC encryption immediately | ✅ Yes |

---

## 7. Implementation Strategy

### Technology Stack
- **Language**: Python 3.10+
- **PQC Library**: liboqs-python (NIST PQC finalists)
- **Cryptography**: `cryptography` library (AES, SHA-256, HMAC)
- **ML Framework**: PyTorch (for training demo)
- **CLI**: Click or Typer
- **Testing**: pytest with hypothesis
- **Serialization**: JSON + pickle (for secure storage)

### Module Organization
```
quantum_refiner/
├── pqc_crypto/           # PQC cryptographic primitives
├── kms/                  # Key Management Service
├── data_handler/         # Secure dataset handling
├── training/             # Secure training pipeline
├── integrity/            # Verification system
├── audit/                # Logging & auditing
├── cli/                  # Command-line interface
├── tests/                # Comprehensive test suite
├── config/               # Configuration files
└── examples/             # Example workflows
```

---

## 8. Performance Considerations

### Optimization Strategies
1. **Chunking**: Balance chunk size (smaller = more metadata overhead, larger = more memory)
2. **PQC Overhead**: Kyber KEM (~3KB), Dilithium (~2.5KB) — minimal with AES
3. **Streaming**: Decrypt on-demand during training (no full dataset in RAM)
4. **Caching**: Cache decrypted batches in memory for minibatch training
5. **Parallelization**: Use multiprocessing for chunk encryption
6. **Hardware Acceleration**: Leverage GPU for AES (if available)

### Benchmark Targets
- Kyber key gen: ~1-2ms
- AES-256 encryption: ~100MB/s (CPU)
- Dilithium signing: ~5-10ms per dataset
- Full pipeline: Encrypt 1GB dataset in <2 minutes

---

## 9. Compliance & Standards

- **NIST PQC Standard**: FIPS 203 (Kyber), FIPS 204 (Dilithium)
- **AES-256**: FIPS 197
- **SHA-256**: FIPS 180-4
- **Key Management**: NIST SP 800-57 (partial simulation)

---

## 10. Future Enhancements

1. **Differential Privacy**: Add DP-SGD integration
2. **Secure Enclave**: TEE/SGX integration for KMS
3. **Distributed Training**: Multi-party decryption
4. **Hardware Security Modules**: Real HSM or TPM integration
5. **Audit Trail Encryption**: Encrypt audit logs themselves
6. **Zero-Knowledge Proofs**: Prove dataset integrity without decryption
7. **Fine-grained Access Control**: Attribute-based access control (ABAC)

---

## 11. Success Criteria

✅ Confidentiality: Encrypted dataset unreadable without keys
✅ Quantum-Resilience: NIST PQC standards used
✅ Integrity: Tampered datasets detected
✅ Usability: Simple CLI for end-users
✅ Performance: <2min encryption for 1GB dataset
✅ No Plaintext Leakage: Never persist unencrypted data
✅ Key Management: Secure generation & rotation
✅ Audit Trail: All access logged
