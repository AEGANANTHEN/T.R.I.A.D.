---
title: Key Management & Cryptography
type: project-documentation
project: T.R.I.A.D.
tags: [cdr-forensics, dems, cybersecurity]
---

# Key Management & Cryptography

## Vault key priority

`get_vault_key()` resolves the key in this order:

1. `DEMS_VAULT_KEY` — 32-byte hex key
2. derive from `SECRET_KEY`
3. development fallback if neither is configured

## PBKDF2 path

`derive_vault_key()` uses PBKDF2-HMAC-SHA256 with:

- 600,000 iterations
- 32-byte output
- configurable salt through `DEMS_VAULT_SALT`

## HKDF path

The current fallback derives an AES-256 key using HKDF-SHA256 with context information:

```text
dems-vault-aes256-v1
```

This provides domain separation for the derived key.

## Production rule

A production system should use a dedicated secret-management system or HSM/KMS rather than depending on a Flask application secret or hardcoded development fallback.

## Key-loss warning

If encrypted evidence exists and the encryption key is lost, the evidence may become unrecoverable.

Therefore key management needs:

- secure storage
- controlled access
- backup/recovery strategy
- rotation plan
- documented ownership
- emergency recovery procedure

## Do not rotate blindly

Changing the vault key without a migration/re-encryption strategy can make existing evidence unreadable.
