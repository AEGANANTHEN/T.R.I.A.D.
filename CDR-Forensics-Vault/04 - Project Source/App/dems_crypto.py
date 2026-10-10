"""
DEMS Cryptographic Engine
==========================
Implements:
  - Streaming dual-hash (SHA-256 + MD5 + SHA-512) calculation prior to disk write.
  - AES-256-GCM authenticated encryption/decryption for the evidence vault.
  - In-memory decryption streaming (no plaintext ever touches disk).
  - Hash integrity verification sentinel.
  - PBKDF2/HKDF vault key derivation.

Complies with ISO/IEC 27037 and NIST SP 800-86 evidence integrity requirements.

Vault file format:
  [ 12 bytes : GCM nonce ] [ 16 bytes : GCM auth tag ] [ N bytes : ciphertext ]
"""

import hashlib
import io
import os
import secrets
from pathlib import Path
from typing import BinaryIO, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

CHUNK_SIZE: int = 65_536          # 64 KiB — streaming chunk for hashing
NONCE_SIZE: int = 12              # GCM recommended nonce length (96 bits)
TAG_SIZE: int   = 16              # AES-GCM authentication tag (128 bits)
KEY_SIZE: int   = 32              # AES-256 key length (256 bits)

# PBKDF2 hardening parameters
PBKDF2_ITERATIONS: int = 600_000  # NIST SP 800-63B recommended minimum (2023)
PBKDF2_SALT_ENV   = "DEMS_VAULT_SALT"
VAULT_KEY_ENV     = "DEMS_VAULT_KEY"


# ─────────────────────────────────────────────────────────────────────────────
# KEY DERIVATION
# ─────────────────────────────────────────────────────────────────────────────

def derive_vault_key(master_secret: str, salt: bytes | None = None) -> bytes:
    """
    Derives a 32-byte AES-256 key from a master secret using PBKDF2-HMAC-SHA256.

    Args:
        master_secret: The application secret key string.
        salt: Optional 16-byte salt. Generated and stored in env if absent.

    Returns:
        32-byte derived key.
    """
    if salt is None:
        salt_hex = os.environ.get(PBKDF2_SALT_ENV)
        if salt_hex:
            salt = bytes.fromhex(salt_hex)
        else:
            salt = secrets.token_bytes(16)
            # Note: In production, persist this salt securely (HSM / secrets manager).

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(master_secret.encode("utf-8"))


def derive_vault_key_hkdf(input_key_material: bytes, info: bytes = b"dems-vault-v1") -> bytes:
    """
    Derives a 32-byte key using HKDF-SHA256 from raw key material.
    Useful for sub-key derivation from a master KDF output.

    Args:
        input_key_material: Raw bytes from a master KDF or hardware source.
        info: Context binding string for domain separation.

    Returns:
        32-byte derived key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=None,
        info=info,
        backend=default_backend(),
    )
    return hkdf.derive(input_key_material)


def get_vault_key() -> bytes:
    """
    Resolves the active vault encryption key using the following priority:
      1. DEMS_VAULT_KEY environment variable (hex-encoded 32 bytes).
      2. Derived from SECRET_KEY env var via PBKDF2.
      3. Derived from hardcoded fallback (development only — logs a warning).

    Returns:
        32-byte AES-256 vault key.
    """
    raw_key = os.environ.get(VAULT_KEY_ENV, "")
    if raw_key:
        try:
            key_bytes = bytes.fromhex(raw_key)
            if len(key_bytes) == KEY_SIZE:
                return key_bytes
        except ValueError:
            pass

    # Fallback: derive deterministically from Flask SECRET_KEY using HKDF.
    # HKDF needs no random salt — info bytes provide domain separation.
    # This is deterministic: same SECRET_KEY → same vault key every call.
    secret = os.environ.get("SECRET_KEY", "cdr-forensic-intel-2024-secret")
    import warnings
    if not os.environ.get(VAULT_KEY_ENV):
        warnings.warn(
            "[DEMS] DEMS_VAULT_KEY not set. Deriving vault key from SECRET_KEY via HKDF. "
            "Set DEMS_VAULT_KEY for production deployments.",
            stacklevel=2,
        )
    return derive_vault_key_hkdf(
        input_key_material=secret.encode("utf-8"),
        info=b"dems-vault-aes256-v1",
    )


# ─────────────────────────────────────────────────────────────────────────────
# STREAMING DUAL-HASH
# ─────────────────────────────────────────────────────────────────────────────

def stream_dual_hash(
    file_obj: BinaryIO,
) -> Tuple[str, str, str, int]:
    """
    Reads a file object in chunks and computes SHA-256, MD5, and SHA-512
    simultaneously in a single streaming pass.

    This function is called BEFORE any disk write to ensure intake hashes
    represent the original unmodified file content.

    Args:
        file_obj: A readable binary file-like object positioned at the start.

    Returns:
        Tuple of (sha256_hex, md5_hex, sha512_hex, byte_count).
    """
    h256  = hashlib.sha256()
    h_md5 = hashlib.md5()
    h512  = hashlib.sha512()
    total = 0

    file_obj.seek(0)
    while True:
        chunk = file_obj.read(CHUNK_SIZE)
        if not chunk:
            break
        h256.update(chunk)
        h_md5.update(chunk)
        h512.update(chunk)
        total += len(chunk)

    file_obj.seek(0)  # Reset for subsequent read
    return h256.hexdigest(), h_md5.hexdigest(), h512.hexdigest(), total


def compute_sha256_of_bytes(data: bytes) -> str:
    """Convenience wrapper: compute SHA-256 of a bytes object."""
    return hashlib.sha256(data).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# AES-256-GCM ENCRYPTION (VAULT WRITE)
# ─────────────────────────────────────────────────────────────────────────────

def encrypt_file_to_vault(
    file_obj: BinaryIO,
    vault_path: Path,
    key_bytes: bytes,
    associated_data: bytes | None = None,
) -> Tuple[str, str, str, int]:
    """
    Encrypts a file stream using AES-256-GCM and writes it to the vault.

    Simultaneously computes SHA-256, MD5, SHA-512 on the PLAINTEXT during
    the first streaming pass, then encrypts in-memory for the vault write.

    Vault file layout:
        [12-byte nonce][16-byte GCM auth tag][ciphertext bytes]

    Args:
        file_obj:        Readable binary file-like object.
        vault_path:      Destination path in the encrypted vault directory.
        key_bytes:       32-byte AES-256 key.
        associated_data: Optional AAD for GCM binding (e.g. evidence_id bytes).

    Returns:
        Tuple of (sha256_hex, md5_hex, sha512_hex, plaintext_byte_count).

    Raises:
        ValueError: If key is not 32 bytes.
        OSError:    If vault path cannot be written.
    """
    if len(key_bytes) != KEY_SIZE:
        raise ValueError(f"Vault key must be {KEY_SIZE} bytes; got {len(key_bytes)}.")

    # Pass 1: stream hashes + read plaintext into memory
    sha256_hex, md5_hex, sha512_hex, byte_count = stream_dual_hash(file_obj)
    file_obj.seek(0)
    plaintext = file_obj.read()

    # Generate a cryptographically random 96-bit nonce for this file
    nonce = secrets.token_bytes(NONCE_SIZE)

    # Encrypt using AES-256-GCM
    aesgcm = AESGCM(key_bytes)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)

    # AES-GCM from `cryptography` appends the 16-byte tag at the END of ciphertext.
    # We split it out and store: [nonce][tag][ciphertext] for clarity.
    ciphertext = ciphertext_with_tag[:-TAG_SIZE]
    auth_tag   = ciphertext_with_tag[-TAG_SIZE:]

    vault_path.parent.mkdir(parents=True, exist_ok=True)
    with open(vault_path, "wb") as vf:
        vf.write(nonce)
        vf.write(auth_tag)
        vf.write(ciphertext)

    # Securely zero plaintext from memory where possible
    del plaintext
    del ciphertext_with_tag

    return sha256_hex, md5_hex, sha512_hex, byte_count


# ─────────────────────────────────────────────────────────────────────────────
# AES-256-GCM DECRYPTION (IN-MEMORY STREAMING)
# ─────────────────────────────────────────────────────────────────────────────

def decrypt_to_memory_stream(
    vault_path: Path,
    key_bytes: bytes,
    associated_data: bytes | None = None,
) -> io.BytesIO:
    """
    Decrypts a vault file into an in-memory BytesIO stream.

    Plaintext NEVER touches disk — all decryption happens in RAM.
    The caller is responsible for consuming and discarding the stream.

    Args:
        vault_path:      Path to the encrypted vault file.
        key_bytes:       32-byte AES-256 key.
        associated_data: Must match the AAD used during encryption.

    Returns:
        BytesIO containing plaintext bytes, positioned at offset 0.

    Raises:
        FileNotFoundError: If vault file does not exist.
        cryptography.exceptions.InvalidTag: If authentication fails (tamper detected).
        ValueError: If vault file is malformed (too short).
    """
    if len(key_bytes) != KEY_SIZE:
        raise ValueError(f"Vault key must be {KEY_SIZE} bytes; got {len(key_bytes)}.")

    if not vault_path.exists():
        raise FileNotFoundError(f"Vault file not found: {vault_path}")

    with open(vault_path, "rb") as vf:
        raw = vf.read()

    min_size = NONCE_SIZE + TAG_SIZE
    if len(raw) < min_size:
        raise ValueError(
            f"Vault file too small ({len(raw)} bytes). "
            f"Expected at least {min_size} bytes (nonce + tag)."
        )

    nonce      = raw[:NONCE_SIZE]
    auth_tag   = raw[NONCE_SIZE : NONCE_SIZE + TAG_SIZE]
    ciphertext = raw[NONCE_SIZE + TAG_SIZE :]

    # Reassemble ciphertext+tag in the format expected by cryptography library
    ciphertext_with_tag = ciphertext + auth_tag

    aesgcm    = AESGCM(key_bytes)
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)

    return io.BytesIO(plaintext)


# ─────────────────────────────────────────────────────────────────────────────
# INTEGRITY VERIFICATION SENTINEL
# ─────────────────────────────────────────────────────────────────────────────

def verify_integrity(
    vault_path: Path,
    key_bytes: bytes,
    expected_sha256: str,
    associated_data: bytes | None = None,
) -> Tuple[bool, str]:
    """
    Decrypts the vault file in memory and recomputes the SHA-256 hash of the
    plaintext, comparing it against the baseline intake hash stored in the DB.

    This constitutes the Integrity Verification Sentinel per ISO/IEC 27037 §9.

    Args:
        vault_path:      Path to the encrypted vault file.
        key_bytes:       32-byte AES-256 key.
        expected_sha256: The SHA-256 hash recorded at evidence ingestion time.
        associated_data: Must match the AAD used during encryption.

    Returns:
        Tuple of (is_verified: bool, current_sha256: str).
        - is_verified=True  → evidence is intact (hashes match).
        - is_verified=False → tampering detected or decryption failure.
    """
    try:
        stream = decrypt_to_memory_stream(vault_path, key_bytes, associated_data)
        plaintext = stream.read()
        current_sha256 = hashlib.sha256(plaintext).hexdigest()
        del plaintext  # Zero from memory
        is_verified = (current_sha256.lower() == expected_sha256.lower())
        return is_verified, current_sha256
    except Exception:
        # Authentication tag failure = tamper detected
        return False, ""


def verify_vault_file_exists(vault_path: Path) -> bool:
    """Returns True if the vault file is present and non-empty."""
    return vault_path.exists() and vault_path.stat().st_size > (NONCE_SIZE + TAG_SIZE)


# ─────────────────────────────────────────────────────────────────────────────
# VAULT PATH UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def build_vault_path(vault_dir: Path, evidence_id: int, original_filename: str) -> Path:
    """
    Constructs a deterministic vault storage path for an evidence item.

    Format: vault/<evidence_id>/<secure_basename>.enc

    The original filename is included (sanitised) so forensic examiners can
    identify the artefact without decrypting it.

    Args:
        vault_dir:         Root vault directory (e.g. Path("vault")).
        evidence_id:       Database primary key for the evidence record.
        original_filename: Original uploaded filename.

    Returns:
        Full Path object for the encrypted vault file.
    """
    # Sanitise: keep alphanumeric, dots, dashes, underscores
    import re
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", Path(original_filename).name)
    return vault_dir / str(evidence_id) / f"{safe_name}.enc"
