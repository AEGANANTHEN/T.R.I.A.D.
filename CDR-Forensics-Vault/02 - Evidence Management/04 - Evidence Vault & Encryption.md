---
title: Evidence Vault & Encryption
type: project-documentation
project: T.R.I.A.D.
tags: [cdr-forensics, dems, cybersecurity]
---

# Evidence Vault & Encryption

## Storage concept

DEMS stores evidence in the `vault/` directory in encrypted form.

The documented vault format is:

```text
[12-byte nonce]
[16-byte GCM authentication tag]
[ciphertext]
```

## Encryption

The implementation uses **AES-256-GCM**.

GCM provides both confidentiality and authenticated integrity of the encrypted payload when used correctly.

## Associated Data (AAD)

The DEMS integration binds evidence metadata using:

```text
evidence:<evidence_id>:<evidence_tag>
```

AAD is authenticated by GCM but is not encrypted.

If the wrong AAD is supplied during decryption, authentication should fail.

## Decryption

`decrypt_to_memory_stream()` reads the encrypted vault file, reconstructs the ciphertext+tag expected by the cryptography library and decrypts to a `BytesIO` stream.

## Secure download

The download route:

1. authenticates the user
2. checks download permission
3. decrypts in memory
4. logs a DOWNLOAD CoC event
5. streams the plaintext response

## Important caveat

The Python encryption function currently reads the entire plaintext into memory before encryption. That is fine for small prototype files but should be redesigned for very large evidence items.
