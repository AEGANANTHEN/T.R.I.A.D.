---
title: Integrity Verification Sentinel
type: project-documentation
project: T.R.I.A.D.
tags: [cdr-forensics, dems, cybersecurity]
---

# Integrity Verification Sentinel

## Purpose

The integrity-verification endpoint checks whether the evidence currently stored in the vault still decrypts to content matching the original intake SHA-256.

## Workflow

```text
Encrypted vault file
       ↓
Decrypt
       ↓
Plaintext in memory
       ↓
SHA-256
       ↓
Compare with intake hash
       ↓
VERIFIED / TAMPER DETECTED
```

## Stored state

The `Evidence` model records:

- `last_verified_at`
- `last_verified_status`

Possible statuses:

- Not Verified
- Verified
- Tamper Detected
- Error

## CoC integration

Every integrity check is logged as an `INTEGRITY_CHECK` event with the verification status and current hash.

## Failure interpretation

A failed verification can mean:

- encrypted data was altered
- wrong key/AAD was used
- vault file is corrupt
- expected baseline is wrong
- implementation/configuration mismatch

It should trigger technical investigation rather than an immediate conclusion of malicious tampering.
