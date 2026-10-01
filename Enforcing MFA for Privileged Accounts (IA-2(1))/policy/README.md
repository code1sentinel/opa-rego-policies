# Enforce MFA for Privileged Accounts (IA-2(1))

Denies any `Administrator`-role user in `input.users` who does not have MFA enabled.

**Control:** NIST SP 800-53 Rev. 5 IA-2(1)

## Input shape

```json
{"users": [{"username": "alice", "role": "Administrator", "mfa_enabled": false}]}
```

## How it works

- `has_mfa(user)` is true only when `mfa_enabled == true`; otherwise it's left **undefined** (no
  fallback) — this is deliberate.
- `unprotected_admins` collects every `Administrator` where `not has_mfa(user)` holds. Negating an
  undefined result is what correctly catches `mfa_enabled: null` as well as `false`. A bare
  `not user.mfa_enabled` would miss the `null` case, since `not null` is itself undefined, not true.
- `deny` turns each unprotected admin into a human-readable message.

## Run it

```bash
opa eval -i iam_config.json -d policy "data.policy.require_mfa.deny" --format pretty
# or
conftest test iam_config.json --policy policy
```

A non-empty `deny` set fails the check.
