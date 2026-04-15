"""
Command-Line Interface for Quantum-Refiner

CLI commands for secure dataset encryption, training, and key management.
"""

import json
import click
from pathlib import Path
from typing import Optional

from quantum_refiner.pqc_crypto.crypto_manager import CryptoManager
from quantum_refiner.kms.key_management_service import KeyManagementService
from quantum_refiner.data_handler.dataset_handler import SecureDatasetHandler
from quantum_refiner.training.secure_training import SecureTrainingPipeline
from quantum_refiner.integrity.integrity_verifier import IntegrityVerifier
from quantum_refiner.audit import AuditLogger


# Global configuration
DEFAULT_KMS_DIR = Path.home() / ".quantum_refiner" / "kms"
DEFAULT_STORAGE_DIR = Path.home() / ".quantum_refiner" / "datasets"
DEFAULT_LOGS_DIR = Path.home() / ".quantum_refiner" / "logs"


def initialize_services():
    """Initialize all services."""
    DEFAULT_KMS_DIR.mkdir(parents=True, exist_ok=True)
    DEFAULT_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    DEFAULT_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    
    audit_logger = AuditLogger(DEFAULT_LOGS_DIR)
    crypto = CryptoManager(audit_logger=audit_logger)
    kms = KeyManagementService(DEFAULT_KMS_DIR, audit_logger=audit_logger)
    
    return crypto, kms, audit_logger


@click.group()
def cli():
    """🔐 Quantum-Refiner: Post-Quantum Cryptography for LLM Security"""
    pass


@cli.group()
def keys():
    """🔑 Key Management Commands"""
    pass


@keys.command()
@click.option("--key-id", default=None, help="Custom key ID")
@click.option("--expires-days", default=365, help="Days until expiration")
@click.option("--rotate-days", default=90, help="Days between rotations")
def generate_kyber(key_id, expires_days, rotate_days):
    """Generate a new CRYSTALS-Kyber keypair"""
    _, kms, _ = initialize_services()
    
    click.echo("🔑 Generating Kyber1024 keypair...")
    keypair = kms.generate_kyber_key(
        key_id=key_id,
        expires_in_days=expires_days,
        rotation_days=rotate_days,
    )
    
    click.echo(f"✅ Kyber key generated successfully!")
    click.echo(f"   Public key (hex): {keypair.public_key.hex()[:32]}...")
    click.echo(f"   Stored in KMS vault")


@keys.command()
@click.option("--key-id", default=None, help="Custom key ID")
@click.option("--expires-days", default=365, help="Days until expiration")
@click.option("--rotate-days", default=90, help="Days between rotations")
def generate_dilithium(key_id, expires_days, rotate_days):
    """Generate a new CRYSTALS-Dilithium keypair"""
    _, kms, _ = initialize_services()
    
    click.echo("🔑 Generating Dilithium3 keypair...")
    keypair = kms.generate_dilithium_key(
        key_id=key_id,
        expires_in_days=expires_days,
        rotation_days=rotate_days,
    )
    
    click.echo(f"✅ Dilithium key generated successfully!")
    click.echo(f"   Public key (hex): {keypair.public_key.hex()[:32]}...")
    click.echo(f"   Stored in KMS vault")


@keys.command()
def list_keys():
    """List all stored keys"""
    _, kms, _ = initialize_services()
    
    keys_metadata = kms.list_keys()
    
    if not keys_metadata:
        click.echo("No keys found")
        return
    
    click.echo("📋 Stored Keys:")
    click.echo("=" * 80)
    
    for key_id, meta in keys_metadata.items():
        click.echo(f"\n🔑 {key_id}")
        click.echo(f"   Type: {meta.get('key_type').upper()}")
        click.echo(f"   Algorithm: {meta.get('algorithm')}")
        click.echo(f"   Created: {meta.get('created_at')}")
        click.echo(f"   Revoked: {meta.get('revoked')}")
        click.echo(f"   Access Count: {meta.get('access_count')}")


@keys.command()
@click.argument("key_id")
def rotate_key(key_id):
    """Rotate a key"""
    _, kms, _ = initialize_services()
    
    click.echo(f"🔄 Rotating key: {key_id}")
    new_key_id = kms.rotate_key(key_id)
    
    if new_key_id:
        click.echo(f"✅ Key rotated successfully!")
        click.echo(f"   New key ID: {new_key_id}")
    else:
        click.echo(f"❌ Key rotation failed")


@cli.group()
def dataset():
    """📦 Dataset Management Commands"""
    pass


@dataset.command()
@click.argument("dataset_path", type=click.Path(exists=True))
@click.argument("dataset_name")
@click.option("--kyber-key", default=None, help="Kyber key ID for encryption")
@click.option("--dilithium-key", default=None, help="Dilithium key ID for signing")
def encrypt(dataset_path, dataset_name, kyber_key, dilithium_key):
    """Encrypt a dataset"""
    crypto, kms, audit_logger = initialize_services()
    
    handler = SecureDatasetHandler(
        storage_dir=DEFAULT_STORAGE_DIR,
        crypto=crypto,
        kms=kms,
        audit_logger=audit_logger,
    )
    
    click.echo(f"🔒 Encrypting dataset: {dataset_path}")
    
    try:
        result = handler.encrypt_dataset(
            Path(dataset_path),
            dataset_name,
            kyber_key_id=kyber_key,
            dilithium_key_id=dilithium_key,
        )
        
        click.echo(f"\n✅ Encryption successful!")
        click.echo(f"   Dataset ID: {result['dataset_id']}")
        click.echo(f"   Storage: {result['dataset_dir']}")
        click.echo(f"   Chunks: {result['total_chunks']}")
        click.echo(f"   Merkle Root: {result['merkle_root']}")
    except Exception as e:
        click.echo(f"❌ Encryption failed: {str(e)}", err=True)


@dataset.command()
@click.argument("dataset_name")
@click.argument("output_path")
@click.argument("kyber_key_id")
@click.option("--dilithium-public-key", required=True, help="Public key for verification (hex)")
def decrypt(dataset_name, output_path, kyber_key_id, dilithium_public_key):
    """Decrypt a dataset"""
    crypto, kms, audit_logger = initialize_services()
    
    handler = SecureDatasetHandler(
        storage_dir=DEFAULT_STORAGE_DIR,
        crypto=crypto,
        kms=kms,
        audit_logger=audit_logger,
    )
    
    click.echo(f"🔓 Decrypting dataset: {dataset_name}")
    
    try:
        pubkey = bytes.fromhex(dilithium_public_key)
        handler.decrypt_dataset(
            dataset_name,
            kyber_key_id,
            pubkey,
            Path(output_path),
            verify_integrity=True,
        )
        click.echo(f"✅ Decryption successful: {output_path}")
    except Exception as e:
        click.echo(f"❌ Decryption failed: {str(e)}", err=True)


@dataset.command()
@click.argument("dataset_name")
def info(dataset_name):
    """Get dataset information"""
    _, _, audit_logger = initialize_services()
    
    handler = SecureDatasetHandler(
        storage_dir=DEFAULT_STORAGE_DIR,
        audit_logger=audit_logger,
    )
    
    info_data = handler.get_dataset_info(dataset_name)
    
    if info_data:
        click.echo(f"📊 Dataset Information: {dataset_name}")
        click.echo("=" * 50)
        for key, value in info_data.items():
            click.echo(f"  {key}: {value}")
    else:
        click.echo(f"Dataset not found: {dataset_name}")


@cli.group()
def verify():
    """✓ Integrity Verification Commands"""
    pass


@verify.command()
@click.argument("dataset_name")
@click.option("--dilithium-public-key", required=True, help="Public key for verification (hex)")
def dataset_integrity(dataset_name, dilithium_public_key):
    """Verify dataset integrity"""
    crypto, _, audit_logger = initialize_services()
    
    verifier = IntegrityVerifier(crypto, audit_logger)
    
    metadata_file = DEFAULT_STORAGE_DIR / dataset_name / "metadata.json"
    
    if not metadata_file.exists():
        click.echo(f"❌ Dataset not found: {dataset_name}")
        return
    
    # Load chunk hashes
    with open(metadata_file, 'r') as f:
        metadata = json.load(f)
    
    chunk_hashes = [
        bytes.fromhex(chunk["original_hash"])
        for chunk in metadata.get("chunks", [])
    ]
    
    pubkey = bytes.fromhex(dilithium_public_key)
    
    click.echo(f"🔍 Verifying dataset: {dataset_name}")
    results = verifier.verify_complete_dataset(
        metadata_file,
        chunk_hashes,
        pubkey,
    )
    
    if results["valid"]:
        click.echo("✅ Dataset integrity verified!")
    else:
        click.echo("❌ Dataset integrity check failed!")
        for error in results["errors"]:
            click.echo(f"   - {error}")


@cli.group()
def audit():
    """📋 Audit & Logging Commands"""
    pass


@audit.command()
def logs():
    """Show recent audit logs"""
    _, _, audit_logger = initialize_services()
    
    summary = audit_logger.get_audit_summary()
    
    click.echo("📋 Audit Log Summary")
    click.echo("=" * 50)
    click.echo(f"Total Events: {summary.get('total_events')}")
    click.echo(f"Log File: {summary.get('log_file')}")
    click.echo(f"File Size: {summary.get('file_size_bytes')} bytes")


@cli.group()
def train():
    """🤖 ML Training Commands"""
    pass


@train.command()
@click.argument("dataset_name")
@click.argument("kyber_key_id")
@click.option("--batch-size", default=32, help="Batch size for training")
@click.option("--epochs", default=1, help="Number of epochs")
def demo(dataset_name, kyber_key_id, batch_size, epochs):
    """Run secure training demo"""
    _, kms, audit_logger = initialize_services()
    
    dataset_dir = DEFAULT_STORAGE_DIR / dataset_name
    
    if not dataset_dir.exists():
        click.echo(f"❌ Dataset not found: {dataset_name}")
        return
    
    click.echo(f"🤖 Starting secure training demo")
    click.echo(f"   Dataset: {dataset_name}")
    click.echo(f"   Batch Size: {batch_size}")
    click.echo(f"   Epochs: {epochs}")
    
    try:
        pipeline = SecureTrainingPipeline(
            dataset_dir,
            kyber_key_id,
            audit_logger=audit_logger,
        )
        
        # Custom training function (dummy)
        def train_fn(batch_data):
            # This would normally train a model
            return len(batch_data) // 1024  # Dummy sample count
        
        stats = pipeline.train_secure_model(
            model=None,
            batch_size=batch_size,
            epochs=epochs,
            training_fn=train_fn,
        )
        
        click.echo(f"\n✅ Training completed successfully!")
        click.echo(f"   Batches: {stats['batches_processed']}")
        click.echo(f"   Total Samples: {stats['total_samples']}")
    except Exception as e:
        click.echo(f"❌ Training failed: {str(e)}", err=True)


@cli.command()
def version():
    """Show version information"""
    click.echo("[>>] Quantum-Refiner v1.0.0")
    click.echo("   Post-Quantum Cryptography for LLM Security")
    click.echo("   NIST PQC Standards: CRYSTALS-Kyber + CRYSTALS-Dilithium + AES-256")


@cli.command()
def status():
    """Show system status"""
    from quantum_refiner.pqc_crypto.crypto_manager import CryptoManager
    
    click.echo("[>>] Quantum-Refiner Status")
    click.echo("=" * 60)
    
    try:
        # Test PQC libraries
        crypto = CryptoManager()
        click.echo("[OK] PQC Libraries: AVAILABLE")
        click.echo(f"   - CRYSTALS-Kyber1024")
        click.echo(f"   - CRYSTALS-Dilithium3")
        click.echo(f"   - AES-256-GCM")
    except Exception as e:
        click.echo(f"[ERROR] PQC Libraries: ERROR - {str(e)}")
    
    # Check directories
    click.echo("")
    click.echo("[*] Storage Directories:")
    kms_status = "[OK]" if DEFAULT_KMS_DIR.exists() else "[!]"
    ds_status = "[OK]" if DEFAULT_STORAGE_DIR.exists() else "[!]"
    log_status = "[OK]" if DEFAULT_LOGS_DIR.exists() else "[!]"
    click.echo(f"   - KMS: {kms_status} {DEFAULT_KMS_DIR}")
    click.echo(f"   - Datasets: {ds_status} {DEFAULT_STORAGE_DIR}")
    click.echo(f"   - Logs: {log_status} {DEFAULT_LOGS_DIR}")


if __name__ == "__main__":
    cli()
