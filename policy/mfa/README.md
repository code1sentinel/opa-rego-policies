# MFA Enforcement: one policy, five input adapters

Control: **NIST SP 800-53 Rev. 5 IA-2(1)** — privileged accounts must use multi-factor authentication.

## Why it's split this way

The rule "a privileged account without MFA is a finding" is the same everywhere. What differs per
platform is (a) how you find out whether an account is privileged, and (b) how you find out whether
MFA is enabled. So the repo splits along that line:

- **`lib.rego`** (`package policy.mfa.lib`) — the one piece of actual decision logic. It knows nothing
  about AWS/Azure/GCP/AD/ICS. It only consumes a normalized record:
  `{"id": <string>, "privileged": <boolean>, "mfa_enabled": <boolean>}`.
- **`aws.rego` / `azure.rego` / `gcp.rego` / `onprem_ad.rego` / `ics_ot.rego`** — thin adapters. Each
  one reads its platform's native `input` shape, decides "is this account privileged" and "does it
  have MFA," and calls `lib.deny_messages(accounts)`.

Adding a sixth platform means writing a sixth adapter that produces the same normalized shape —
`lib.rego` never changes.

## Using an adapter with minimal edits

You should not need to edit the `.rego` files at all. Each adapter reads its tunable values (which
IAM policies count as "admin," which AD groups are privileged, etc.) from `data.config.mfa.<platform>`,
with a sane built-in default if you supply nothing. To customize, write your own small `config.json`
and load it alongside the policy:

```bash
opa eval -i your_input.json -d policy/mfa -d config.json "data.policy.mfa.aws.deny"
# or, with conftest:
conftest test your_input.json --policy policy/mfa --data config.json
```

Example `config.json` for the AWS adapter:

```json
{"mfa": {"aws": {"privileged_policy_arns": ["arn:aws:iam::aws:policy/YourCustomAdminPolicy"]}}}
```

See the `METADATA` block at the top of each adapter for its exact expected `input` shape and which
`data.config.mfa.<platform>` keys it honors.

## A deliberate limitation: ICS/OT

`ics_ot.rego` does not (and cannot) check MFA on PLCs, RTUs, or HMIs — most ICS field protocols
(Modbus, DNP3, etc.) have no authentication layer at all, so "require MFA on the device" isn't an
achievable control. Instead it evaluates MFA at the IT/OT boundary: every remote-access path into the
OT network (jump host, PAM broker, VPN concentrator) must require MFA. That maps to IEC 62443-3-3
SR 1.1/1.2 and NIST SP 800-82 Rev. 3 Section 6.2, which is the realistic enforcement point for this
control in an OT environment.

## Running the tests

```bash
opa test -v policy/mfa
```

Each adapter's `_test.rego` is also the clearest usage example — it shows a full sample `input` and
the exact `deny` output it produces.
