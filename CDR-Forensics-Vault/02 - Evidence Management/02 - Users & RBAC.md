---
title: Users & RBAC
type: project-documentation
project: T.R.I.A.D.
tags: [cdr-forensics, dems, cybersecurity]
---

# Users & RBAC

## Roles

The project defines four roles:

| Role | Intended privilege |
|---|---|
| Auditor | Read-only inspection of cases/evidence/CoC |
| Forensic Analyst | Analysis, integrity checks and authorized downloads |
| Lead Investigator | Case creation, evidence intake and custody operations |
| Admin | Full system administration |

## Permission model

The code uses explicit permission strings such as:

```text
view_cases
view_evidence
view_coc
export_coc
verify_integrity
run_analysis
download_evidence
create_case
upload_evidence
transfer_custody
check_in
check_out
edit_case
manage_users
system_config
delete_evidence
close_case
```

## How authorization works

A route can require a role or a permission.

For example:

```text
User logs in
   ↓
User has UserRole
   ↓
Route checks role/permission
   ↓
Allow or deny
```

## Security principle

Do not rely only on hidden buttons in the frontend. Authorization must be enforced server-side, which the DEMS route decorators are designed to do.

## Production improvements

- MFA
- SSO
- session timeout
- password policy
- account lockout
- audit login events
- case-level authorization
- least privilege review
