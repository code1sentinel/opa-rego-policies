# MFA Enforcement: one policy, five input adapters

Control: **NIST SP 800-53 Rev. 5 IA-2(1)** — privileged accounts must use multi-factor authentication.

## Quick start

```bash
git clone https://github.com/code1sentinel/opa-rego-policies.git
cd opa-rego-policies/policy/mfa
./check.sh aws      # or: azure, gcp
```

`check.sh` runs the matching collector in `collectors/` (which calls your cloud provider's API with
your already-configured CLI credentials — nothing is hardcoded or shipped with this repo), evaluates
the result against the policy, prints any violations, and exits non-zero if it finds any. That exit
code is what you wire into a pipeline gate — see "Wiring into a CI pipeline" below.

`onprem_ad` and `ics_ot` are **templates**, not drop-in scripts — see "Why on-prem and ICS/OT are
templates, not scripts" below for why, and edit the collector before running `./check.sh onprem_ad` /
`./check.sh ics_ot`.

Requires [`opa`](https://www.openpolicyagent.org/docs/#running-opa) and `jq` on your PATH, plus
whichever platform CLI the collector you're using needs (`aws`, `az`, or `curl`+a GCP access token —
see the prerequisites comment at the top of each `collectors/*_collect.sh`).

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
IAM policies count as "admin," which AD groups are privileged, etc.) from `data.mfa.<platform>`,
with a sane built-in default if you supply nothing. To customize, write your own small `config.json`
and pass it to `check.sh` (`./check.sh aws config.json`), or load it directly:

```bash
# using a collector's live output
./collectors/aws_collect.sh | opa eval -I -d . -d config.json "data.policy.mfa.aws.deny"

# or against your own hand-built input.json
opa eval -i your_input.json -d . -d config.json "data.policy.mfa.aws.deny"
# or, with conftest:
conftest test your_input.json --policy . --namespace policy.mfa.aws --data config.json
```

Example `config.json` for the AWS adapter:

```json
{"mfa": {"aws": {"privileged_policy_arns": ["arn:aws:iam::aws:policy/YourCustomAdminPolicy"]}}}
```

See the `METADATA` block at the top of each adapter for its exact expected `input` shape and which
`data.mfa.<platform>` keys it honors.

## A deliberate limitation: ICS/OT

`ics_ot.rego` does not (and cannot) check MFA on PLCs, RTUs, or HMIs — most ICS field protocols
(Modbus, DNP3, etc.) have no authentication layer at all, so "require MFA on the device" isn't an
achievable control. Instead it evaluates MFA at the IT/OT boundary: every remote-access path into the
OT network (jump host, PAM broker, VPN concentrator) must require MFA. That maps to IEC 62443-3-3
SR 1.1/1.2 and NIST SP 800-82 Rev. 3 Section 6.2, which is the realistic enforcement point for this
control in an OT environment.

## Why on-prem AD and ICS/OT are templates, not scripts

`collectors/aws_collect.sh`, `azure_collect.sh`, and `gcp_collect.sh` are real, runnable scripts
because AWS/Azure/GCP each expose one documented API you can call directly. On-prem AD and ICS/OT
don't have that: "which MFA provider" (Duo, RSA, a RADIUS server, Okta...) and "which PAM/VPN tool
brokers OT access" (CyberArk, Claroty, Dragos, a plain VPN concentrator...) vary per organization with
no common API. `collectors/onprem_ad_collect.ps1` and `collectors/ics_ot_collect.sh` get you the AD
half (or the output shape) and leave one function for you to fill in against your own tooling — they
fail loudly with a clear message if you run them before editing that function.

## Wiring into a CI pipeline

Any CI system works the same way: run the collector, pipe it into `opa eval` (or use `check.sh`
directly), and fail the job on a non-zero exit code. For example, in GitHub Actions:

```yaml
- name: Check AWS MFA enforcement (IA-2(1))
  run: policy/mfa/check.sh aws
  env:
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

This isn't a Terraform plan gate — it checks live IAM state, so it belongs in a scheduled/periodic
workflow (e.g. nightly) rather than a per-PR check, unless your PR pipeline actually has live cloud
credentials.

## Running the tests

```bash
opa test -v policy/mfa
```

Each adapter's `_test.rego` is also the clearest usage example — it shows a full sample `input` and
the exact `deny` output it produces.
