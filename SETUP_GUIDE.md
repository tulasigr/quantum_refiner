# Quantum-Refiner: Setup & Execution Guide

## 🚀 Quick Start (5 minutes)

### Prerequisites
- Python 3.10+
- Windows/macOS/Linux
- ~500MB free disk space

### Installation

```bash
# 1. Navigate to project
cd quantum_refiner

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify installation
python -c "from quantum_refiner import CryptoManager; print('✅ Ready!')"
```

### Run Examples

```bash
# Example 1: Complete end-to-end workflow
python examples/example_workflow.py

# Example 2: Security attack scenarios
python examples/example_attacks.py

# Example 3: CLI interface
quantum-refiner status
quantum-refiner keys list-keys
```

---

## 📋 Complete Installation Steps

### Step 1: System Check

```bash
# Python version
python --version  # Should be 3.10+

# Check pip
pip --version

# Check git (optional)
git --version
```

### Step 2: Clone & Setup

```bash
# Option A: From git
git clone https://github.com/yourusername/quantum_refiner.git
cd quantum_refiner

# Option B: Manual (if downloaded as ZIP)
# Extract ZIP and navigate to folder
cd quantum_refiner
```

### Step 3: Create Virtual Environment

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**macOS/Linux:**
```bash
python -m venv venv
source venv/bin/activate
```

### Step 4: Install Dependencies

```bash
# Install all required packages
pip install -r requirements.txt

# Or for development (with dev dependencies)
pip install -e ".[dev]"
```

### Step 5: Verify Installation

```bash
# Check Python imports
python -c "
import quantum_refiner
from quantum_refiner import CryptoManager, KeyManagementService
print('✅ All imports successful!')
"

# Run status check
quantum-refiner status
```

### Step 6: (Optional) Run Tests

```bash
# Install test dependencies
pip install pytest pytest-cov hypothesis

# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=quantum_refiner --cov-report=html
```

---

## 💻 Usage Workflows

### Workflow 1: Encrypt a Dataset (CLI)

```bash
# 1. Generate encryption key
quantum-refiner keys generate-kyber --key-id my_key --expires-days 365

# 2. Generate signing key
quantum-refiner keys generate-dilithium --key-id sign_key --expires-days 365

# 3. Encrypt dataset
quantum-refiner dataset encrypt \
  /path/to/data.bin \
  my_encrypted_dataset \
  --kyber-key my_key \
  --dilithium-key sign_key

# 4. Verify encryption
quantum-refiner dataset info my_encrypted_dataset
```

### Workflow 2: Decrypt & Train (Python API)

```python
from pathlib import Path
from quantum_refiner import (
    KeyManagementService,
    SecureDatasetHandler,
)

# Setup
kms = KeyManagementService()
handler = SecureDatasetHandler()

# Get keys
kyber_kp = kms.get_kyber_key("my_key")
dilithium_kp = kms.get_dilithium_key("sign_key")

# Decrypt dataset
handler.decrypt_dataset(
    dataset_name="my_encrypted_dataset",
    kyber_key_id="my_key",
    dilithium_public_key=dilithium_kp.public_key,
    output_path=Path("./data/decrypted.bin"),
)

print("✅ Dataset decrypted and ready for training!")
```

### Workflow 3: Secure Training with Streaming

```python
from quantum_refiner.training import SecureTrainingPipeline

# Initialize pipeline
pipeline = SecureTrainingPipeline(
    dataset_dir=Path("~/.quantum_refiner/datasets/my_encrypted_dataset"),
    kyber_key_id="my_key",
)

# Create data loader (on-demand decryption)
loader = pipeline.create_data_loader(batch_size=32)

# Training loop
for epoch in range(3):
    for batch_data in loader.get_batch_iterator():
        # Process batch with your model
        # Plaintext only in memory, never on disk!
        pass
```

---

## 🧪 Testing

### Run Unit Tests

```bash
# All tests
pytest tests/test_complete.py -v

# Security tests only
pytest tests/test_complete.py -v -m security

# Performance benchmarks
pytest tests/test_complete.py -v -m benchmark
```

### Run Example Scripts

```bash
# Complete workflow example
python examples/example_workflow.py

# Security scenario simulations
python examples/example_attacks.py
```

### Manual Testing Checklist

```bash
# 1. Key generation
quantum-refiner keys generate-kyber
quantum-refiner keys generate-dilithium
quantum-refiner keys list-keys

# 2. Dataset encryption
quantum-refiner dataset encrypt ./test_data.bin test_dataset

# 3. Integrity verification
quantum-refiner verify dataset-integrity test_dataset \
  --dilithium-public-key <pubkey_hex>

# 4. Training demo
quantum-refiner train demo test_dataset <kyber_key_id>

# 5. Audit logs
quantum-refiner audit logs
```

---

## 🔍 Troubleshooting

### Issue: Import Error for `oqs`

**Error:** `ModuleNotFoundError: No module named 'oqs'`

**Solution:**
```bash
# Install liboqs-python (PQC library)
pip install liboqs-python

# Verify
python -c "import oqs; print(oqs.has_oqs_build())"
```

### Issue: Directory Permissions

**Error:** `PermissionError: [Errno 13] Permission denied`

**Solution:**
```bash
# Check permissions
ls -la ~/.quantum_refiner/

# Fix if needed
chmod 700 ~/.quantum_refiner/
chmod 700 ~/.quantum_refiner/kms/
chmod 700 ~/.quantum_refiner/datasets/
```

### Issue: Insufficient Disk Space

**Error:** `No space left on device`

**Solution:**
```bash
# Check space
df -h

# Clean old logs
rm ~/.quantum_refiner/logs/*.log

# Consider smaller chunk sizes
# Edit SecureDatasetHandler(chunk_size_mb=5)  # Default 10
```

### Issue: PQC Library Not Found

**Error:** `RuntimeError: PQC algorithm initialization failed`

**Solution:**
```bash
# Reinstall with exact version
pip install --upgrade liboqs-python==0.7.0

# Try alternative installation
pip install liboqs-python --no-cache-dir --force-reinstall
```

### Issue: Slow Performance

**Optimization:**
```python
# Use larger chunks to reduce Merkle tree overhead
handler = SecureDatasetHandler(chunk_size_mb=50)

# Use GPU if available
# Integrate with GPU-accelerated AES

# Parallel encryption
# Use multiprocessing for chunk encryption
```

---

## 📊 Project Structure

```
quantum_refiner/
├── README.md                    # Main documentation
├── ARCHITECTURE.md              # System architecture
├── requirements.txt             # Python dependencies
├── pyproject.toml              # Package configuration
├── pytest.ini                  # Test configuration
│
├── quantum_refiner/            # Main package
│   ├── __init__.py
│   │
│   ├── pqc_crypto/             # PQC cryptography
│   │   ├── __init__.py
│   │   └── crypto_manager.py   # Kyber, Dilithium, AES
│   │
│   ├── kms/                    # Key Management Service
│   │   ├── __init__.py
│   │   └── key_management_service.py
│   │
│   ├── data_handler/           # Dataset encryption
│   │   ├── __init__.py
│   │   └── dataset_handler.py
│   │
│   ├── training/               # Training pipeline
│   │   ├── __init__.py
│   │   └── secure_training.py
│   │
│   ├── integrity/              # Integrity verification
│   │   ├── __init__.py
│   │   └── integrity_verifier.py
│   │
│   ├── audit/                  # Audit logging
│   │   ├── __init__.py
│   │   └── audit_logger.py
│   │
│   └── cli/                    # Command-line interface
│       ├── __init__.py
│       └── main.py
│
├── tests/                      # Test suite
│   ├── __init__.py
│   └── test_complete.py       # Comprehensive tests
│
├── examples/                   # Example scripts
│   ├── example_workflow.py    # End-to-end demo
│   └── example_attacks.py     # Security scenarios
│
└── config/                     # Configuration files
    ├── default_config.yaml    # Default settings
    └── security_policy.json   # Security policies
```

---

## 🔐 Security Best Practices

### Key Management
- ✅ Generate fresh keys for each dataset
- ✅ Use key rotation (90 days recommended)
- ✅ Revoke compromised keys immediately
- ✅ Never share private keys
- ✅ Store KMS directory in protected location

### Dataset Handling
- ✅ Always verify dataset integrity before processing
- ✅ Use fresh nonces for each encryption
- ✅ Never write plaintext to disk
- ✅ Clear decrypted data from memory after use
- ✅ Archive encrypted datasets with metadata

### Audit Trail
- ✅ Monitor audit logs regularly
- ✅ Keep complete audit trail (long-term storage)
- ✅ Archive logs encrypted
- ✅ Review for anomalies
- ✅ Integrate with SIEM if available

### Deployment Checklist
- [ ] Use HSM for real KMS (not file-based simulation)
- [ ] Enable audit logging
- [ ] Configure key rotation policies
- [ ] Test key recovery procedures
- [ ] Monitor disk space
- [ ] Regular backups of encrypted datasets
- [ ] Access control on KMS directory
- [ ] Network isolation if possible
- [ ] Keep dependencies updated
- [ ] Regular security audits

---

## 📈 Performance Tuning

### For Large Datasets (>100GB)

```python
# Increase chunk size to reduce overhead
handler = SecureDatasetHandler(chunk_size_mb=100)

# Use parallel workers
# Implement multiprocessing for chunk encryption

# Consider streaming to external storage
# Stream encrypted chunks to S3/Cloud storage
```

### For Real-Time Training

```python
# Use smaller batches
loader = pipeline.create_data_loader(batch_size=16)

# Pre-warm decryption cache
# Decrypt next chunks while training current batch

# GPU acceleration
# Use GPU-accelerated AES if available
```

### Monitoring & Metrics

```python
# Track encryption throughput
# Monitor decryption latency
# Measure Merkle tree verification overhead
# Count audit log entries

# Implement metrics collection
from quantum_refiner.audit import AuditLogger
audit = AuditLogger()
audit.get_audit_summary()
```

---

## 🚀 Deployment

### Docker Option

```dockerfile
FROM python:3.10-slim

RUN apt-get update && apt-get install -y gcc make libffi-dev openssl

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY quantum_refiner/ ./quantum_refiner/

ENTRYPOINT ["quantum-refiner"]
```

Build: `docker build -t quantum-refiner .`
Run: `docker run quantum-refiner status`

### Kubernetes Option

See `deployment/k8s-manifest.yaml` for Kubernetes deployment config.

---

## 📞 Support & Contact

- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Email**: support@quantum-refiner.io
- **Documentation**: https://doc.quantum-refiner.io

---

**Last Updated**: December 2024
**Version**: 1.0.0
**Status**: Production Ready ✅
