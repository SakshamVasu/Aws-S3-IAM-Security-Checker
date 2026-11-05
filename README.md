# AWS S3 & IAM Security Checker

A read-only Python/boto3 scanner that runs 10 S3 and IAM checks, maps each failure to an ISO/IEC 27001:2022 Annex A control, and writes a self-contained HTML report.

## Checks

| ID | What it checks | Default risk | ISO 27001 |
|---|---|---|---|
| `S3_BLOCK_PUBLIC_ACCESS` | All 4 Block Public Access settings are on (bucket OR account level) | High | A.8.9 |
| `S3_BUCKET_POLICY_PUBLIC` | Bucket policy has no unconditional `Principal: "*"` (uses AWS policy-status evaluation) | Critical* | A.8.3 |
| `S3_BUCKET_ACL_PUBLIC` | ACL has no AllUsers / AuthenticatedUsers grants (passes if ACLs are disabled) | Critical* | A.8.3 |
| `S3_DEFAULT_ENCRYPTION` | Default server-side encryption is configured (optionally require SSE-KMS) | Medium | A.8.24 |
| `S3_ACCESS_LOGGING` | Server access logging is enabled | Low | A.8.15 |
| `IAM_ROOT_ACCOUNT` | Root has MFA and no access keys; flags recent root sign-ins | Critical | A.8.2 |
| `IAM_USER_MFA` | Every user with a console password has MFA | High | A.8.5 |
| `IAM_OVERLY_PERMISSIVE` | Managed and inline policies with `*`, `service:*` or `NotAction`; role trust policies open to `*` | Critical/High/Medium | A.5.15 |
| `IAM_ACCESS_KEY_ROTATION` | Active access keys are 90 days old or newer (High if older than 1 year) | Medium | A.5.17 |
| `IAM_UNUSED_CREDENTIALS` | No password or active key unused for 90+ days | Medium | A.5.18 |

\* A public policy or ACL drops to Medium when Block Public Access is currently neutralising it. The setting is still worth fixing, because the exposure goes live if BPA is removed.

Every finding is `PASS`, `FAIL` or `ERROR`. `ERROR` means the resource couldn't be evaluated, for example because of a missing permission. The report lists these separately, so a partial failure never aborts the scan.

## Setup

Requires Python 3.9+.

```bash
python -m venv .venv
```

```bash
.venv\Scripts\activate        # Windows  (macOS/Linux: source .venv/bin/activate)
```

```bash
pip install -r requirements.txt
```

## Credentials and permissions

The scanner uses the standard boto3 credential chain: environment variables, `~/.aws/credentials`, `aws sso login`, instance or container roles. It never stores or hard-codes credentials.

The principal needs only the read actions in [`iam-policy.json`](iam-policy.json). You can also attach the AWS-managed `SecurityAudit` policy, which covers all of them.

`iam:GenerateCredentialReport` is the one non-`Get`/`List` action. It only refreshes the account's credential report (a CSV that AWS caches for 4 hours) and changes no configuration.

Example: create a dedicated audit role/user and attach the policy:

```bash
aws iam create-policy --policy-name S3IamSecurityCheckerReadOnly --policy-document file://iam-policy.json
```

## Run

**One click (Windows):** double-click `run_scan.bat`. A dialog asks for:

- **AWS profile.** Pick an existing profile from the list or type a new name.
- **AWS region.**
- **Sign-in method:**
  - *Already signed in* uses the profile as it is.
  - *AWS SSO* fills in the start URL, SSO region, account ID and role. You only need these the first time; leave them blank after that. It then runs `aws sso login`, which opens your browser.
  - *Access key* saves the key ID and secret to the profile, the same as `aws configure`.

Press **Enter** or **Run scan**. On the first run, the launcher creates `.venv` and installs the requirements. It then runs the scan, opens the HTML report and shows a summary of findings by risk.

The dialog remembers your last non-secret choices in `launcher-settings.json`. Secrets are never stored there.

The SSO and access-key options need the [AWS CLI v2](https://aws.amazon.com/cli/). The bat file is a thin wrapper; the logic is in `launcher.ps1`.

**Command line:**

```bash
python scanner.py --profile audit --region eu-west-1 --output report.html
```

| Option | Meaning |
|---|---|
| `--region` | Region for API calls (default: profile/env region, else `us-east-1`). Each bucket is still queried in its own home region. |
| `--profile` | Named profile; omit to use the default credential chain. |
| `--only-region` | Only scan buckets located in `--region`. |
| `--output` | HTML report path (default `aws_security_report.html`). |
| `--json` | Also write all findings (including passes and errors) as JSON. |
| `--fail-on` | `low`/`medium`/`high`/`critical`: exit code 1 if any finding is at or above that level. Useful in CI. |
| `-v` | Debug logging. |

## Customising

All of these are plain constants at the top of `scanner.py`:

- `ISO_27001_CONTROLS`: check → Annex A control mapping. Edit the dictionary to change it.
- `CHECK_METADATA`: default risk, rationale and remediation text per check.
- `MAX_ACCESS_KEY_AGE_DAYS`, `UNUSED_CREDENTIAL_DAYS`: thresholds (default 90).
- `REQUIRE_SSE_KMS`: set `True` to fail buckets that use only SSE-S3. Since January 2023, AWS applies SSE-S3 by default.
- `SENSITIVE_SERVICES`: services whose `service:*` wildcards rate High instead of Medium.

To add a check, write a function `check_x(ctx) -> list[Finding]`. Then add an entry to `CHECK_METADATA` and `ISO_27001_CONTROLS`, and append the function to `CHECKS`.
