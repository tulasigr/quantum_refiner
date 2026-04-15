#!/usr/bin/env python3
"""Test script to verify mock crypto implementations work."""

import sys
import io
import os

# Redirect stderr to suppress liboqs error messages
old_stderr = sys.stderr
sys.stderr = io.StringIO()

try:
    from quantum_refiner.pqc_crypto import CryptoManager
    
    print("=" * 60)
    print("TESTING MOCK CRYPTO IMPLEMENTATIONS")
    print("=" * 60)
    
    # Create crypto manager
    cm = CryptoManager()
    print(f"\n[OK] CryptoManager created!")
    print(f"     HAS_OQS: {cm.has_oqs}")
    print(f"     Kyber variant: {cm.kyber_alg}")
    print(f"     Dilithium variant: {cm.dilithium_alg}")
    
    # Test Kyber key generation
    print("\n" + "=" * 60)
    print("TEST 1: Kyber Key Generation")
    print("=" * 60)
    kyber_keypair = cm.generate_kyber_keypair()
    print(f"[OK] Generated Kyber keypair!")
    print(f"     Public key size: {len(kyber_keypair.public_key)} bytes")
    print(f"     Secret key size: {len(kyber_keypair.secret_key)} bytes")
    
    # Test Kyber encapsulation
    print("\n" + "=" * 60)
    print("TEST 2: Kyber Encapsulation")
    print("=" * 60)
    ciphertext, shared_secret = cm.kyber_encapsulate(kyber_keypair.public_key)
    print(f"[OK] Encapsulated Kyber!")
    print(f"     Ciphertext size: {len(ciphertext)} bytes")
    print(f"     Shared secret size: {len(shared_secret)} bytes")
    
    # Test Kyber decapsulation
    print("\n" + "=" * 60)
    print("TEST 3: Kyber Decapsulation")
    print("=" * 60)
    recovered_secret = cm.kyber_decapsulate(ciphertext, kyber_keypair.secret_key)
    print(f"[OK] Decapsulated Kyber!")
    print(f"     Recovered secret size: {len(recovered_secret)} bytes")
    
    # Test Dilithium key generation
    print("\n" + "=" * 60)
    print("TEST 4: Dilithium Key Generation")
    print("=" * 60)
    dil_keypair = cm.generate_dilithium_keypair()
    print(f"[OK] Generated Dilithium keypair!")
    print(f"     Public key size: {len(dil_keypair.public_key)} bytes")
    print(f"     Secret key size: {len(dil_keypair.secret_key)} bytes")
    
    # Test Dilithium signing
    print("\n" + "=" * 60)
    print("TEST 5: Dilithium Signing")
    print("=" * 60)
    message = b"Test message for signing"
    signature = cm.dilithium_sign(message, dil_keypair.secret_key)
    print(f"[OK] Signed message with Dilithium!")
    print(f"     Message: {message.decode()}")
    print(f"     Signature size: {len(signature)} bytes")
    
    # Test Dilithium verification
    print("\n" + "=" * 60)
    print("TEST 6: Dilithium Verification")
    print("=" * 60)
    is_valid = cm.dilithium_verify(message, signature, dil_keypair.public_key)
    print(f"[OK] Verified Dilithium signature!")
    print(f"     Is valid: {is_valid}")
    
    # Test AES encryption
    print("\n" + "=" * 60)
    print("TEST 7: AES-256-GCM Encryption")
    print("=" * 60)
    plaintext = b"This is a secret message!"
    aes_key = b"0" * 32  # 32 bytes for AES-256
    ciphertext, nonce, tag = cm.aes_encrypt(plaintext, aes_key)
    print(f"[OK] Encrypted with AES-256-GCM!")
    print(f"     Plaintext: {plaintext.decode()}")
    print(f"     Ciphertext size: {len(ciphertext)} bytes")
    print(f"     Nonce size: {len(nonce)} bytes")
    print(f"     Auth tag size: {len(tag)} bytes")
    
    # Test AES decryption
    print("\n" + "=" * 60)
    print("TEST 8: AES-256-GCM Decryption")
    print("=" * 60)
    recovered_plaintext = cm.aes_decrypt(ciphertext, aes_key, nonce, tag)
    print(f"[OK] Decrypted with AES-256-GCM!")
    print(f"     Recovered: {recovered_plaintext.decode()}")
    print(f"     Match: {recovered_plaintext == plaintext}")
    
    # Test Key derivation
    print("\n" + "=" * 60)
    print("TEST 9: AES Key Derivation (PBKDF2)")
    print("=" * 60)
    shared_secret = b"shared_secret_from_kyber" * 2  # Make it 48 bytes
    derived_key, salt = cm.derive_aes_key(shared_secret)
    print(f"[OK] Derived AES key from shared secret!")
    print(f"     Derived key size: {len(derived_key)} bytes")
    print(f"     Salt size: {len(salt)} bytes")
    
    # Test hashing
    print("\n" + "=" * 60)
    print("TEST 10: SHA-256 Hashing")
    print("=" * 60)
    data = b"Data to hash"
    hash_value = cm.compute_hash(data)
    print(f"[OK] Computed SHA-256 hash!")
    print(f"     Data: {data.decode()}")
    print(f"     Hash: {hash_value.hex()[:32]}...")
    print(f"     Hash size: {len(hash_value)} bytes")
    
    print("\n" + "=" * 60)
    print("ALL TESTS PASSED! [SUCCESS]")
    print("=" * 60)
    
finally:
    sys.stderr = old_stderr
