#!/usr/bin/env python3
"""
AWS S3 & IAM security checker.

Runs 10 read-only checks against S3 buckets and IAM configuration in the
current AWS account, maps every failure to an ISO/IEC 27001:2022 Annex A
control, and writes a self-contained HTML report.

Credentials come from the standard boto3 chain (env vars, ~/.aws/credentials,
SSO, instance/role metadata, ...). Nothing is ever written to the account.

    python scanner.py --region eu-west-1 --profile audit --output report.html
"""
from __future__ import annotations

import argparse
import csv
import html
import io
import json
import logging
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable
from urllib.parse import unquote

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

log = logging.getLogger("s3-iam-checker")

# =============================================================================
# Editable configuration
# =============================================================================

# Check ID -> ISO/IEC 27001:2022 Annex A control. Edit freely; the report
# reads straight from this table.
ISO_27001_CONTROLS = {
    "S3_BLOCK_PUBLIC_ACCESS":   {"control": "A.8.9",  "title": "Configuration management"},
    "S3_BUCKET_POLICY_PUBLIC":  {"control": "A.8.3",  "title": "Information access restriction"},
    "S3_BUCKET_ACL_PUBLIC":     {"control": "A.8.3",  "title": "Information access restriction"},
    "S3_DEFAULT_ENCRYPTION":    {"control": "A.8.24", "title": "Use of cryptography"},
    "S3_ACCESS_LOGGING":        {"control": "A.8.15", "title": "Logging"},
    "IAM_ROOT_ACCOUNT":         {"control": "A.8.2",  "title": "Privileged access rights"},
    "IAM_USER_MFA":             {"control": "A.8.5",  "title": "Secure authentication"},
    "IAM_OVERLY_PERMISSIVE":    {"control": "A.5.15", "title": "Access control"},
    "IAM_ACCESS_KEY_ROTATION":  {"control": "A.5.17", "title": "Authentication information"},
    "IAM_UNUSED_CREDENTIALS":   {"control": "A.5.18", "title": "Access rights"},
}

MAX_ACCESS_KEY_AGE_DAYS = 90     # keys older than this fail rotation
UNUSED_CREDENTIAL_DAYS = 90      # passwords/keys idle longer than this fail
REQUIRE_SSE_KMS = False          # True: SSE-S3 (AES256) alone counts as a failure

# Services where a "service:*" grant on all resources enables privilege
# escalation or broad data access, so it is rated High rather than Medium.
SENSITIVE_SERVICES = {"iam", "sts", "organizations", "kms", "s3", "lambda",
                      "ec2", "secretsmanager", "ssm", "cloudtrail"}

RISK_LEVELS = ["Critical", "High", "Medium", "Low"]

# Default risk, rationale and remediation per check. Checks may override the
# risk/rationale for a specific finding (e.g. a public ACL that BPA neutralises).
# Remediation strings are str.format templates filled with per-finding values.
CHECK_METADATA = {
    "S3_BLOCK_PUBLIC_ACCESS": {
        "name": "S3 Block Public Access fully enabled",
        "risk": "High",
        "rationale": "Without all four Block Public Access settings, a single mistaken ACL or "
                     "policy change can expose the bucket to the internet.",
        "remediation": "aws s3api put-public-access-block --bucket {bucket} "
                       "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
                       "BlockPublicPolicy=true,RestrictPublicBuckets=true  (also consider the account-level "
                       "setting: aws s3control put-public-access-block --account-id <id> ...)",
    },
    "S3_BUCKET_POLICY_PUBLIC": {
        "name": "S3 bucket policy does not grant public access",
        "risk": "Critical",
        "rationale": "The bucket policy grants access to anyone on the internet; data can be read "
                     "or modified without authentication.",
        "remediation": "Review 'aws s3api get-bucket-policy --bucket {bucket}' and remove or scope the "
                       "statements with Principal \"*\" (add aws:PrincipalOrgID / aws:SourceVpce conditions or "
                       "named principals). For public websites, serve through CloudFront with Origin Access "
                       "Control instead of a public bucket, then enable Block Public Access.",
    },
    "S3_BUCKET_ACL_PUBLIC": {
        "name": "S3 bucket ACL does not grant public access",
        "risk": "Critical",
        "rationale": "The ACL grants AllUsers/AuthenticatedUsers access, exposing the bucket to "
                     "anonymous or any-AWS-account callers.",
        "remediation": "Disable ACLs entirely: aws s3api put-bucket-ownership-controls --bucket {bucket} "
                       "--ownership-controls 'Rules=[{{ObjectOwnership=BucketOwnerEnforced}}]'  "
                       "(or at minimum: aws s3api put-bucket-acl --bucket {bucket} --acl private).",
    },
    "S3_DEFAULT_ENCRYPTION": {
        "name": "S3 default encryption configured",
        "risk": "Medium",
        "rationale": "Objects may be stored without server-side encryption, weakening protection of "
                     "data at rest and failing most audit baselines.",
        "remediation": "aws s3api put-bucket-encryption --bucket {bucket} --server-side-encryption-configuration "
                       "'{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":{{\"SSEAlgorithm\":\"aws:kms\","
                       "\"KMSMasterKeyID\":\"<kms-key-arn>\"}},\"BucketKeyEnabled\":true}}]}}'",
    },
    "S3_ACCESS_LOGGING": {
        "name": "S3 server access logging enabled",
        "risk": "Low",
        "rationale": "Missing access logs do not expose data directly but prevent reconstruction of "
                     "who accessed which objects during an incident.",
        "remediation": "aws s3api put-bucket-logging --bucket {bucket} --bucket-logging-status "
                       "'{{\"LoggingEnabled\":{{\"TargetBucket\":\"<central-log-bucket>\",\"TargetPrefix\":\"{bucket}/\"}}}}'  "
                       "(or enable CloudTrail S3 data events for this bucket).",
    },
    "IAM_ROOT_ACCOUNT": {
        "name": "Root account has MFA and no access keys",
        "risk": "Critical",
        "rationale": "The root user has unrestricted, unrevokable control of the account; a "
                     "compromised root credential means full account takeover.",
        "remediation": "Sign in as root -> Security credentials: assign a hardware or passkey MFA device "
                       "and delete any root access keys. Use IAM Identity Center or IAM roles for daily work.",
    },
    "IAM_USER_MFA": {
        "name": "IAM console users have MFA enabled",
        "risk": "High",
        "rationale": "A console password without MFA can be phished or brute-forced; a single leaked "
                     "password gives interactive access with the user's permissions.",
        "remediation": "IAM console -> Users -> {user} -> Security credentials -> Assign MFA device. "
                       "Enforce with a policy that denies actions when aws:MultiFactorAuthPresent is false. "
                       "If console access isn't needed: aws iam delete-login-profile --user-name {user}",
    },
    "IAM_OVERLY_PERMISSIVE": {
        "name": "No wildcard IAM permissions or open role trust",
        "risk": "High",
        "rationale": "Wildcard actions/resources grant far more than needed, enabling privilege "
                     "escalation and widening blast radius if the principal is compromised.",
        "remediation": "Replace {target} with least-privilege statements listing specific actions and "
                       "resource ARNs. Use IAM Access Analyzer policy generation (based on CloudTrail activity) "
                       "to draft a scoped policy; for trust policies, name explicit principals and add "
                       "sts:ExternalId or aws:PrincipalOrgID conditions.",
    },
    "IAM_ACCESS_KEY_ROTATION": {
        "name": f"Access keys rotated within {MAX_ACCESS_KEY_AGE_DAYS} days",
        "risk": "Medium",
        "rationale": "Long-lived keys accumulate exposure (laptops, CI logs, repos); an old key that "
                     "leaked stays valid until rotated.",
        "remediation": "aws iam create-access-key --user-name {user}; update consumers; "
                       "aws iam update-access-key --user-name {user} --access-key-id <old-key-id> --status Inactive; "
                       "then aws iam delete-access-key ... Prefer IAM roles / Identity Center over static keys.",
    },
    "IAM_UNUSED_CREDENTIALS": {
        "name": f"No credentials unused for {UNUSED_CREDENTIAL_DAYS}+ days",
        "risk": "Medium",
        "rationale": "Dormant credentials are unmonitored attack surface; nobody notices if they are "
                     "used by an attacker.",
        "remediation": "Disable what isn't needed: aws iam delete-login-profile --user-name {user} and/or "
                       "aws iam update-access-key --user-name {user} --access-key-id <key-id> --status Inactive. "
                       "Delete the user if it belongs to a departed person or retired workload.",
    },
}

# =============================================================================
# Findings
# =============================================================================

PASS, FAIL, ERROR = "PASS", "FAIL", "ERROR"
ACCESS_DENIED_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                       "AllAccessDisabled", "InvalidAccessKeyId", "ExpiredToken"}


@dataclass
class Finding:
    check_id: str
    check_name: str
    resource: str
    status: str                 # PASS / FAIL / ERROR
    description: str = ""
    risk: str = ""              # only set for FAIL
    risk_rationale: str = ""
    remediation: str = ""
    iso_control: str = ""       # e.g. "A.8.24 Use of cryptography"


def iso_label(check_id: str) -> str:
    entry = ISO_27001_CONTROLS.get(check_id)
    return f"{entry['control']} {entry['title']}" if entry else "Unmapped"


def result(check_id: str, resource: str, passed: bool, description: str = "", *,
           risk: str | None = None, rationale: str | None = None, **fmt) -> Finding:
    """Build a PASS/FAIL finding, filling defaults from CHECK_METADATA."""
    meta = CHECK_METADATA[check_id]
    f = Finding(check_id, meta["name"], resource, PASS if passed else FAIL, description,
                iso_control=iso_label(check_id))
    if not passed:
        f.risk = risk or meta["risk"]
        f.risk_rationale = rationale or meta["rationale"]
        try:
            f.remediation = meta["remediation"].format(**fmt)
        except (KeyError, IndexError):
            f.remediation = meta["remediation"]
    return f


def error(check_id: str, resource: str, exc: Exception) -> Finding:
    """Record that a resource could not be evaluated (permissions, API error)."""
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        msg = exc.response.get("Error", {}).get("Message", str(exc))
        hint = " (missing read permission?)" if code in ACCESS_DENIED_CODES else ""
        text = f"{code}: {msg}{hint}"
    else:
        text = f"{type(exc).__name__}: {exc}"
    log.warning("%s on %s: %s", check_id, resource, text)
    return Finding(check_id, CHECK_METADATA[check_id]["name"], resource, ERROR,
                   f"Could not evaluate: {text}", iso_control=iso_label(check_id))


def error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


# =============================================================================
# Shared scan context (clients + cached lookups used by several checks)
# =============================================================================

class ScanContext:
    def __init__(self, session: boto3.Session, region: str, only_region: bool = False):
        self.session = session
        self.region = region
        self.only_region = only_region
        self._config = Config(retries={"max_attempts": 10, "mode": "adaptive"},
                              connect_timeout=10, read_timeout=30)
        self._clients: dict[tuple[str, str], object] = {}
        self._bucket_regions: dict[str, str] = {}
        self._bucket_bpa: dict[str, dict] = {}
        self._buckets: list[str] | None = None
        self._account_bpa: dict | None = None
        self._cred_report: list[dict] | None = None
        self._auth_details: dict | None = None

        ident = self.client("sts").get_caller_identity()
        self.account_id = ident["Account"]
        self.caller_arn = ident["Arn"]

    def client(self, service: str, region: str | None = None):
        key = (service, region or self.region)
        if key not in self._clients:
            self._clients[key] = self.session.client(service, region_name=key[1], config=self._config)
        return self._clients[key]

    # ---------------------------------------------------------------- S3 ---

    def buckets(self) -> list[str]:
        """All bucket names (optionally only those in the configured region)."""
        if self._buckets is None:
            s3 = self.client("s3")
            names: list[str] = []
            if s3.can_paginate("list_buckets"):
                for page in s3.get_paginator("list_buckets").paginate():
                    names += [b["Name"] for b in page.get("Buckets", [])]
            else:
                names = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
            if self.only_region:
                names = [n for n in names if self._safe_bucket_region(n) == self.region]
            self._buckets = sorted(names)
        return self._buckets

    def bucket_region(self, bucket: str) -> str:
        if bucket not in self._bucket_regions:
            loc = self.client("s3").get_bucket_location(Bucket=bucket).get("LocationConstraint")
            # Legacy values: None == us-east-1, "EU" == eu-west-1
            self._bucket_regions[bucket] = {None: "us-east-1", "": "us-east-1", "EU": "eu-west-1"}.get(loc, loc)
        return self._bucket_regions[bucket]

    def _safe_bucket_region(self, bucket: str) -> str | None:
        try:
            return self.bucket_region(bucket)
        except (ClientError, BotoCoreError):
            return None

    def s3_for(self, bucket: str):
        """S3 client in the bucket's home region (avoids redirect errors)."""
        try:
            return self.client("s3", self.bucket_region(bucket))
        except (ClientError, BotoCoreError):
            return self.client("s3")

    def account_bpa(self) -> dict:
        """Account-level Block Public Access settings (all False if unset/unreadable)."""
        if self._account_bpa is None:
            self._account_bpa = {}
            try:
                resp = self.client("s3control").get_public_access_block(AccountId=self.account_id)
                self._account_bpa = resp["PublicAccessBlockConfiguration"]
            except ClientError as exc:
                if error_code(exc) != "NoSuchPublicAccessBlockConfiguration":
                    log.warning("Account-level BPA unreadable: %s", exc)
        return self._account_bpa

    def effective_bpa(self, bucket: str) -> dict:
        """Bucket BPA OR'ed with account BPA - what S3 actually enforces."""
        if bucket not in self._bucket_bpa:
            bucket_cfg: dict = {}
            try:
                bucket_cfg = self.s3_for(bucket).get_public_access_block(Bucket=bucket)[
                    "PublicAccessBlockConfiguration"]
            except ClientError as exc:
                if error_code(exc) != "NoSuchPublicAccessBlockConfiguration":
                    raise
            acct = self.account_bpa()
            self._bucket_bpa[bucket] = {
                k: bool(bucket_cfg.get(k)) or bool(acct.get(k))
                for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
            } | {"_bucket": bucket_cfg, "_account": acct}
        return self._bucket_bpa[bucket]

    # --------------------------------------------------------------- IAM ---

    def credential_report(self) -> list[dict]:
        """IAM credential report rows (generated on demand, polled until ready)."""
        if self._cred_report is None:
            iam = self.client("iam")
            for _ in range(30):
                state = iam.generate_credential_report().get("State")
                if state == "COMPLETE":
                    break
                time.sleep(2)
            for attempt in range(10):
                try:
                    content = iam.get_credential_report()["Content"]
                    break
                except ClientError as exc:
                    if error_code(exc) in ("ReportInProgress", "ReportNotPresent") and attempt < 9:
                        time.sleep(2)
                        continue
                    raise
            text = content.decode("utf-8") if isinstance(content, bytes) else content
            self._cred_report = list(csv.DictReader(io.StringIO(text)))
        return self._cred_report

    def auth_details(self) -> dict:
        """Users, groups, roles and policies with documents, via one paginated API."""
        if self._auth_details is None:
            out = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
            paginator = self.client("iam").get_paginator("get_account_authorization_details")
            for page in paginator.paginate(Filter=["User", "Group", "Role", "LocalManagedPolicy", "AWSManagedPolicy"]):
                for key in out:
                    out[key] += page.get(key, [])
            self._auth_details = out
        return self._auth_details


# =============================================================================
# Helpers
# =============================================================================

def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def load_policy(doc) -> dict:
    """Policy documents arrive as dicts (boto3 decodes them) or URL-encoded JSON."""
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        try:
            return json.loads(unquote(doc))
        except json.JSONDecodeError:
            return json.loads(doc)
    return {}


def is_public_principal(principal) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any(p == "*" for p in as_list(principal.get("AWS")))
    return False


def parse_date(value: str | None) -> datetime | None:
    """Credential-report timestamps; 'N/A', 'no_information' etc. become None."""
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def days_since(dt: datetime | None) -> int | None:
    return None if dt is None else (datetime.now(timezone.utc) - dt).days


def max_risk(risks: list[str]) -> str:
    return min(risks, key=RISK_LEVELS.index) if risks else "Low"


# =============================================================================
# S3 checks
# =============================================================================

def check_s3_block_public_access(ctx: ScanContext) -> list[Finding]:
    cid = "S3_BLOCK_PUBLIC_ACCESS"
    findings = []
    for bucket in ctx.buckets():
        try:
            bpa = ctx.effective_bpa(bucket)
            missing = [k for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy",
                                   "RestrictPublicBuckets") if not bpa[k]]
            if missing:
                desc = ("Block Public Access settings not enforced at bucket or account level: "
                        + ", ".join(missing) + ".")
                findings.append(result(cid, bucket, False, desc, bucket=bucket))
            else:
                src = "account" if all(bpa["_account"].get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls",
                      "BlockPublicPolicy", "RestrictPublicBuckets")) else "bucket/account"
                findings.append(result(cid, bucket, True, f"All four settings enforced ({src} level)."))
        except (ClientError, BotoCoreError) as exc:
            findings.append(error(cid, bucket, exc))
    return findings


def check_s3_bucket_policy_public(ctx: ScanContext) -> list[Finding]:
    cid = "S3_BUCKET_POLICY_PUBLIC"
    findings = []
    for bucket in ctx.buckets():
        s3 = ctx.s3_for(bucket)
        try:
            try:
                policy = load_policy(s3.get_bucket_policy(Bucket=bucket)["Policy"])
            except ClientError as exc:
                if error_code(exc) == "NoSuchBucketPolicy":
                    findings.append(result(cid, bucket, True, "No bucket policy."))
                    continue
                raise

            # Our own scan: Allow + public principal without any Condition.
            public_sids = []
            for i, st in enumerate(as_list(policy.get("Statement"))):
                if st.get("Effect") == "Allow" and is_public_principal(st.get("Principal")) \
                        and not st.get("Condition"):
                    actions = ", ".join(as_list(st.get("Action")) or ["(NotAction)"])
                    public_sids.append(f"{st.get('Sid', f'#{i}')} [{actions}]")

            # AWS's own evaluation is authoritative when available (it understands
            # conditions such as aws:SourceVpc that make a "*" principal non-public).
            aws_public = None
            try:
                aws_public = s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"]["IsPublic"]
            except ClientError as exc:
                log.debug("get_bucket_policy_status failed for %s: %s", bucket, exc)

            is_public = aws_public if aws_public is not None else bool(public_sids)
            if not is_public:
                findings.append(result(cid, bucket, True, "Bucket policy does not grant public access."))
                continue

            desc = "Bucket policy grants access to everyone (Principal \"*\")"
            desc += f": statements {'; '.join(public_sids)}." if public_sids else " per AWS policy-status evaluation."
            bpa = ctx.effective_bpa(bucket)
            if bpa["RestrictPublicBuckets"]:
                findings.append(result(
                    cid, bucket, False, desc + " Currently neutralised by RestrictPublicBuckets.",
                    risk="Medium", bucket=bucket,
                    rationale="The policy is public by design, but Block Public Access (RestrictPublicBuckets) "
                              "currently blocks anonymous use; removing BPA would expose the bucket immediately."))
            else:
                findings.append(result(cid, bucket, False, desc, bucket=bucket))
        except (ClientError, BotoCoreError) as exc:
            findings.append(error(cid, bucket, exc))
    return findings


def check_s3_bucket_acl_public(ctx: ScanContext) -> list[Finding]:
    cid = "S3_BUCKET_ACL_PUBLIC"
    public_uris = {
        "http://acs.amazonaws.com/groups/global/AllUsers": "AllUsers (anyone)",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "AuthenticatedUsers (any AWS account)",
    }
    findings = []
    for bucket in ctx.buckets():
        s3 = ctx.s3_for(bucket)
        try:
            # With BucketOwnerEnforced, ACLs are disabled and cannot grant anything.
            try:
                rules = s3.get_bucket_ownership_controls(Bucket=bucket)["OwnershipControls"]["Rules"]
                if any(r.get("ObjectOwnership") == "BucketOwnerEnforced" for r in rules):
                    findings.append(result(cid, bucket, True, "ACLs disabled (BucketOwnerEnforced)."))
                    continue
            except ClientError as exc:
                if error_code(exc) not in ("OwnershipControlsNotFoundError",) and \
                        error_code(exc) not in ACCESS_DENIED_CODES:
                    raise

            grants = s3.get_bucket_acl(Bucket=bucket).get("Grants", [])
            exposed = sorted({f"{public_uris[g['Grantee']['URI']]}: {g.get('Permission')}"
                              for g in grants if g.get("Grantee", {}).get("URI") in public_uris})
            if not exposed:
                findings.append(result(cid, bucket, True, "ACL has no public grants."))
                continue

            desc = "Bucket ACL grants " + "; ".join(exposed) + "."
            if ctx.effective_bpa(bucket)["IgnorePublicAcls"]:
                findings.append(result(
                    cid, bucket, False, desc + " Currently ignored due to IgnorePublicAcls.",
                    risk="Medium", bucket=bucket,
                    rationale="The ACL is public but IgnorePublicAcls makes S3 disregard it; a latent "
                              "exposure that goes live if Block Public Access is relaxed."))
            else:
                findings.append(result(cid, bucket, False, desc, bucket=bucket))
        except (ClientError, BotoCoreError) as exc:
            findings.append(error(cid, bucket, exc))
    return findings


def check_s3_default_encryption(ctx: ScanContext) -> list[Finding]:
    cid = "S3_DEFAULT_ENCRYPTION"
    findings = []
    for bucket in ctx.buckets():
        try:
            try:
                rules = ctx.s3_for(bucket).get_bucket_encryption(Bucket=bucket)[
                    "ServerSideEncryptionConfiguration"]["Rules"]
            except ClientError as exc:
                if error_code(exc) == "ServerSideEncryptionConfigurationNotFoundError":
                    findings.append(result(cid, bucket, False, "No default encryption configuration.",
                                           bucket=bucket))
                    continue
                raise
            algos = {r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") for r in rules}
            algos.discard(None)
            if not algos:
                findings.append(result(cid, bucket, False, "Encryption rules present but no default algorithm.",
                                       bucket=bucket))
            elif REQUIRE_SSE_KMS and not algos & {"aws:kms", "aws:kms:dsse"}:
                findings.append(result(
                    cid, bucket, False, f"Default encryption is {', '.join(sorted(algos))} (SSE-S3); "
                                        "policy requires SSE-KMS.",
                    risk="Low", bucket=bucket,
                    rationale="Data is encrypted at rest, but with AWS-owned keys: no key-level access "
                              "control or CloudTrail visibility of key use."))
            else:
                findings.append(result(cid, bucket, True, f"Default encryption: {', '.join(sorted(algos))}."))
        except (ClientError, BotoCoreError) as exc:
            findings.append(error(cid, bucket, exc))
    return findings


def check_s3_access_logging(ctx: ScanContext) -> list[Finding]:
    cid = "S3_ACCESS_LOGGING"
    findings = []
    for bucket in ctx.buckets():
        try:
            cfg = ctx.s3_for(bucket).get_bucket_logging(Bucket=bucket).get("LoggingEnabled")
            if cfg:
                findings.append(result(cid, bucket, True,
                                       f"Logging to s3://{cfg.get('TargetBucket')}/{cfg.get('TargetPrefix', '')}"))
            else:
                findings.append(result(cid, bucket, False, "Server access logging is disabled.", bucket=bucket))
        except (ClientError, BotoCoreError) as exc:
            findings.append(error(cid, bucket, exc))
    return findings


# =============================================================================
# IAM checks
# =============================================================================

def check_iam_root_account(ctx: ScanContext) -> list[Finding]:
    cid = "IAM_ROOT_ACCOUNT"
    resource = f"arn:aws:iam::{ctx.account_id}:root"
    try:
        summary = ctx.client("iam").get_account_summary()["SummaryMap"]
        issues = []
        if not summary.get("AccountMFAEnabled"):
            issues.append("root user has no MFA device")
        if summary.get("AccountAccessKeysPresent"):
            issues.append("root user has access keys")
        # Credential report adds detail on recent root usage (best effort).
        try:
            root = next((r for r in ctx.credential_report() if r["user"] == "<root_account>"), None)
            used = days_since(parse_date(root.get("password_last_used"))) if root else None
            if used is not None and used <= 30:
                issues.append(f"root console sign-in {used} day(s) ago")
        except (ClientError, BotoCoreError) as exc:
            log.debug("credential report unavailable for root check: %s", exc)

        hard = [i for i in issues if "sign-in" not in i]
        if hard:
            text = "; ".join(issues)
            return [result(cid, resource, False, text[0].upper() + text[1:] + ".")]
        if issues:
            return [result(cid, resource, False, issues[0][0].upper() + issues[0][1:] + ".", risk="Low",
                           rationale="Root is protected by MFA and has no keys, but routine root use "
                                     "increases exposure of the most privileged credential.")]
        return [result(cid, resource, True, "Root has MFA and no access keys.")]
    except (ClientError, BotoCoreError) as exc:
        return [error(cid, resource, exc)]


def check_iam_user_mfa(ctx: ScanContext) -> list[Finding]:
    cid = "IAM_USER_MFA"
    try:
        rows = ctx.credential_report()
    except (ClientError, BotoCoreError) as exc:
        return [error(cid, "IAM credential report", exc)]
    findings = []
    for row in rows:
        if row["user"] == "<root_account>":
            continue        # covered by IAM_ROOT_ACCOUNT
        user, arn = row["user"], row.get("arn", row["user"])
        if row.get("password_enabled") != "true":
            findings.append(result(cid, arn, True, "No console password (programmatic-only user)."))
        elif row.get("mfa_active") == "true":
            findings.append(result(cid, arn, True, "Console user with MFA."))
        else:
            findings.append(result(cid, arn, False,
                                   f"User '{user}' can sign in to the console with a password but has no MFA.",
                                   user=user))
    return findings


def _policy_issues(doc: dict) -> list[tuple[str, str]]:
    """Return (risk, message) for each overly broad Allow statement."""
    issues = []
    for i, st in enumerate(as_list(load_policy(doc).get("Statement"))):
        if st.get("Effect") != "Allow":
            continue
        sid = st.get("Sid") or f"#{i}"
        cond = " (has Condition - review)" if st.get("Condition") else ""
        resources = as_list(st.get("Resource"))
        all_resources = "*" in resources or bool(st.get("NotResource"))
        if st.get("NotAction"):
            issues.append(("High", f"Statement {sid}: Allow with NotAction grants every action except "
                                   f"{as_list(st['NotAction'])}{cond}"))
            continue
        actions = as_list(st.get("Action"))
        if any(a in ("*", "*:*") for a in actions):
            if all_resources:
                issues.append(("Critical", f"Statement {sid}: Action \"*\" on Resource \"*\" "
                                           f"(full administrator){cond}"))
            else:
                issues.append(("High", f"Statement {sid}: Action \"*\" on {resources}{cond}"))
            continue
        svc_wild = sorted({a.split(":")[0].lower() for a in actions if a.endswith(":*")})
        if svc_wild and all_resources:
            risk = "High" if set(svc_wild) & SENSITIVE_SERVICES else "Medium"
            issues.append((risk, f"Statement {sid}: service-wide wildcards "
                                 f"{', '.join(s + ':*' for s in svc_wild)} on Resource \"*\"{cond}"))
    return issues


def check_iam_overly_permissive(ctx: ScanContext) -> list[Finding]:
    cid = "IAM_OVERLY_PERMISSIVE"
    try:
        details = ctx.auth_details()
    except (ClientError, BotoCoreError) as exc:
        return [error(cid, "IAM authorization details", exc)]

    rationale = {
        "Critical": "Grants full administrator rights (*:* on *); any compromise of an attached principal "
                    "is a full account compromise.",
        "High": "Broad wildcard grants on sensitive services or all actions enable privilege escalation "
                "or wide data access.",
        "Medium": "Service-wide wildcards on all resources exceed least privilege, though on "
                  "lower-impact services.",
        "Low": "Overly broad policy exists but is not attached to any principal.",
    }

    # Which principals each managed policy is attached to (for context in the report).
    attached: dict[str, list[str]] = {}
    for kind, key in (("user", "UserDetailList"), ("group", "GroupDetailList"), ("role", "RoleDetailList")):
        for ent in details[key]:
            name = ent.get("UserName") or ent.get("GroupName") or ent.get("RoleName")
            for p in ent.get("AttachedManagedPolicies", []):
                attached.setdefault(p["PolicyArn"], []).append(f"{kind}:{name}")

    findings = []

    def evaluate(resource: str, doc, target: str, attached_to: list[str] | None, is_unattached: bool = False):
        try:
            issues = _policy_issues(doc)
        except (ValueError, TypeError, AttributeError) as exc:
            findings.append(error(cid, resource, exc))
            return
        if not issues:
            findings.append(result(cid, resource, True, "No wildcard grants."))
            return
        risk = "Low" if is_unattached else max_risk([r for r, _ in issues])
        desc = "; ".join(m for _, m in issues) + "."
        if attached_to:
            desc += f" Attached to: {', '.join(attached_to[:10])}" + (" ..." if len(attached_to) > 10 else "")
        elif is_unattached:
            desc += " Not attached to any principal."
        findings.append(result(cid, resource, False, desc, risk=risk, rationale=rationale[risk], target=target))

    # Managed policies: all customer-managed, plus AWS-managed ones actually in use.
    for pol in details["Policies"]:
        arn = pol["Arn"]
        is_aws = arn.startswith("arn:aws:iam::aws:")
        if is_aws and not pol.get("AttachmentCount"):
            continue
        doc = next((v["Document"] for v in pol.get("PolicyVersionList", []) if v.get("IsDefaultVersion")), None)
        if doc is None:
            continue
        name = pol.get("PolicyName") or arn.rsplit("/", 1)[-1]
        evaluate(arn, doc, f"managed policy {name}", attached.get(arn),
                 is_unattached=not pol.get("AttachmentCount"))

    # Inline policies on users, groups and roles.
    for key, list_key in (("UserDetailList", "UserPolicyList"), ("GroupDetailList", "GroupPolicyList"),
                          ("RoleDetailList", "RolePolicyList")):
        for ent in details[key]:
            for p in ent.get(list_key, []):
                evaluate(f"{ent['Arn']} (inline: {p['PolicyName']})", p["PolicyDocument"],
                         f"inline policy {p['PolicyName']}", None)

    # Role trust policies that let anyone assume the role.
    for role in details["RoleDetailList"]:
        resource = f"{role['Arn']} (trust policy)"
        try:
            trust = load_policy(role.get("AssumeRolePolicyDocument", {}))
            open_stmts = [st.get("Sid") or f"#{i}" for i, st in enumerate(as_list(trust.get("Statement")))
                          if st.get("Effect") == "Allow" and is_public_principal(st.get("Principal"))
                          and not st.get("Condition")]
        except (ValueError, TypeError, AttributeError) as exc:
            findings.append(error(cid, resource, exc))
            continue
        if open_stmts:
            findings.append(result(
                cid, resource, False,
                f"Trust policy allows any AWS principal (Principal \"*\", no Condition) to assume "
                f"role '{role['RoleName']}' (statements {', '.join(open_stmts)}).",
                risk="Critical", target=f"the trust policy of role {role['RoleName']}",
                rationale="Any AWS account in the world can assume this role and obtain its permissions."))
        else:
            findings.append(result(cid, resource, True, "Trust policy names specific principals."))
    return findings


def check_iam_access_key_rotation(ctx: ScanContext) -> list[Finding]:
    cid = "IAM_ACCESS_KEY_ROTATION"
    try:
        rows = ctx.credential_report()
    except (ClientError, BotoCoreError) as exc:
        return [error(cid, "IAM credential report", exc)]
    findings = []
    for row in rows:
        if row["user"] == "<root_account>":
            continue
        user, arn = row["user"], row.get("arn", row["user"])
        for n in (1, 2):
            if row.get(f"access_key_{n}_active") != "true":
                continue
            resource = f"{arn} (access key {n})"
            rotated = parse_date(row.get(f"access_key_{n}_last_rotated"))
            age = days_since(rotated)
            if age is None:
                findings.append(result(cid, resource, True, "Key age unknown."))
            elif age > MAX_ACCESS_KEY_AGE_DAYS:
                risk, rationale = (("High", "Key is over a year old: high likelihood it has been copied to "
                                            "places outside your control and never revoked.")
                                   if age > 365 else (None, None))
                findings.append(result(
                    cid, resource, False,
                    f"Active access key {n} of '{user}' is {age} days old (created {rotated:%Y-%m-%d}); "
                    f"limit is {MAX_ACCESS_KEY_AGE_DAYS}.", risk=risk, rationale=rationale, user=user))
            else:
                findings.append(result(cid, resource, True, f"Key is {age} days old."))
    return findings


def check_iam_unused_credentials(ctx: ScanContext) -> list[Finding]:
    cid = "IAM_UNUSED_CREDENTIALS"
    try:
        rows = ctx.credential_report()
    except (ClientError, BotoCoreError) as exc:
        return [error(cid, "IAM credential report", exc)]
    findings = []
    limit = UNUSED_CREDENTIAL_DAYS
    for row in rows:
        if row["user"] == "<root_account>":
            continue
        user, arn = row["user"], row.get("arn", row["user"])
        issues = []
        if row.get("password_enabled") == "true":
            last = days_since(parse_date(row.get("password_last_used")))
            # Never used: judge by when the password was set instead.
            since_set = days_since(parse_date(row.get("password_last_changed"))
                                   or parse_date(row.get("user_creation_time")))
            if last is not None and last > limit:
                issues.append(f"console password last used {last} days ago")
            elif last is None and since_set is not None and since_set > limit:
                issues.append(f"console password never used (set {since_set} days ago)")
        for n in (1, 2):
            if row.get(f"access_key_{n}_active") != "true":
                continue
            last = days_since(parse_date(row.get(f"access_key_{n}_last_used_date")))
            age = days_since(parse_date(row.get(f"access_key_{n}_last_rotated")))
            if last is not None and last > limit:
                issues.append(f"access key {n} last used {last} days ago")
            elif last is None and age is not None and age > limit:
                issues.append(f"access key {n} never used (created {age} days ago)")
        if issues:
            findings.append(result(cid, arn, False, f"User '{user}': " + "; ".join(issues) + ".", user=user))
        else:
            findings.append(result(cid, arn, True, "All active credentials used recently."))
    return findings


# Order here is the order checks run and appear in the report.
CHECKS: list[tuple[str, Callable[[ScanContext], list[Finding]]]] = [
    ("S3_BLOCK_PUBLIC_ACCESS", check_s3_block_public_access),
    ("S3_BUCKET_POLICY_PUBLIC", check_s3_bucket_policy_public),
    ("S3_BUCKET_ACL_PUBLIC", check_s3_bucket_acl_public),
    ("S3_DEFAULT_ENCRYPTION", check_s3_default_encryption),
    ("S3_ACCESS_LOGGING", check_s3_access_logging),
    ("IAM_ROOT_ACCOUNT", check_iam_root_account),
    ("IAM_USER_MFA", check_iam_user_mfa),
    ("IAM_OVERLY_PERMISSIVE", check_iam_overly_permissive),
    ("IAM_ACCESS_KEY_ROTATION", check_iam_access_key_rotation),
    ("IAM_UNUSED_CREDENTIALS", check_iam_unused_credentials),
]


def run_scan(ctx: ScanContext) -> list[Finding]:
    """Run every check; a crash in one check becomes an ERROR finding, never aborts the scan."""
    findings: list[Finding] = []
    for check_id, fn in CHECKS:
        log.info("Running %s ...", check_id)
        try:
            findings += fn(ctx)
        except Exception as exc:  # noqa: BLE001 - deliberate: isolate check failures
            findings.append(error(check_id, "(entire check)", exc))
    return findings


# =============================================================================
# HTML report
# =============================================================================

REPORT_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1d2330;--muted:#5d6678;--border:#dfe3ea;
--crit:#b3261e;--high:#d9480f;--med:#b07d00;--low:#2b6cb0;--pass:#2f855a;--err:#6b7280}
@media (prefers-color-scheme:dark){:root{--bg:#14161b;--card:#1d2027;--text:#e6e8ee;--muted:#9aa3b5;
--border:#2e333d;--crit:#f2867f;--high:#f4a261;--med:#e9c46a;--low:#7fb3f0;--pass:#6fcf97;--err:#a0a7b4}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
main{max-width:1280px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 12px}
.meta{color:var(--muted);font-size:13px}.meta code{font-size:12px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-top:20px}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px 14px}
.card .n{font-size:26px;font-weight:600;font-variant-numeric:tabular-nums}.card .l{color:var(--muted);font-size:12px}
.card.crit .n{color:var(--crit)}.card.high .n{color:var(--high)}.card.med .n{color:var(--med)}
.card.low .n{color:var(--low)}
.tbl{overflow-x:auto;background:var(--card);border:1px solid var(--border);border-radius:8px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;vertical-align:top;padding:10px 12px;
border-bottom:1px solid var(--border)}th{font-size:12px;color:var(--muted);font-weight:600;white-space:nowrap}
tr:last-child td{border-bottom:0}td.res{font-family:Consolas,Menlo,monospace;font-size:12px;word-break:break-all;
min-width:180px}td.fix{font-size:12.5px;min-width:260px}td.fix code{font-size:12px;word-break:break-word}
.why{color:var(--muted);font-size:12.5px;margin-top:4px}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600;color:#fff;
white-space:nowrap}.Critical{background:var(--crit)}.High{background:var(--high)}.Medium{background:var(--med)}
.Low{background:var(--low)}.PASS{color:var(--pass)}.FAIL{color:var(--crit)}.ERROR{color:var(--err)}
@media (prefers-color-scheme:dark){.badge{color:#111}}
.num{text-align:right;font-variant-numeric:tabular-nums}.empty{padding:16px;color:var(--muted)}
footer{margin-top:32px;color:var(--muted);font-size:12px}
"""


def render_html(findings: list[Finding], ctx_info: dict) -> str:
    e = html.escape
    failed = sorted([f for f in findings if f.status == FAIL],
                    key=lambda f: (RISK_LEVELS.index(f.risk), f.check_id, f.resource))
    errors = [f for f in findings if f.status == ERROR]
    by_risk = {r: sum(1 for f in failed if f.risk == r) for r in RISK_LEVELS}

    cards = [("Checks run", len(CHECKS), ""), ("Resources evaluated", len(findings), ""),
             ("Findings (failed)", len(failed), ""),
             ("Critical", by_risk["Critical"], "crit"), ("High", by_risk["High"], "high"),
             ("Medium", by_risk["Medium"], "med"), ("Low", by_risk["Low"], "low"),
             ("Not evaluated", len(errors), "")]
    cards_html = "".join(f'<div class="card {c}"><div class="n">{n}</div><div class="l">{e(l)}</div></div>'
                         for l, n, c in cards)

    rows = "".join(
        f"<tr><td><span class='badge {e(f.risk)}'>{e(f.risk)}</span><div class='why'>{e(f.risk_rationale)}</div></td>"
        f"<td>{e(f.check_name)}<div class='why'>{e(f.check_id)}</div></td>"
        f"<td class='res'>{e(f.resource)}</td><td>{e(f.description)}</td>"
        f"<td>{e(f.iso_control)}</td><td class='fix'><code>{e(f.remediation)}</code></td></tr>"
        for f in failed)
    findings_html = (f"<div class='tbl'><table><thead><tr><th>Risk &amp; rationale</th><th>Check</th>"
                     f"<th>Resource</th><th>Problem</th><th>ISO 27001</th><th>Remediation</th></tr></thead>"
                     f"<tbody>{rows}</tbody></table></div>") if failed else \
        "<div class='tbl'><div class='empty'>No failed findings.</div></div>"

    cov_rows = ""
    for check_id, _ in CHECKS:
        fs = [f for f in findings if f.check_id == check_id]
        counts = {s: sum(1 for f in fs if f.status == s) for s in (PASS, FAIL, ERROR)}
        cov_rows += (f"<tr><td>{e(CHECK_METADATA[check_id]['name'])}<div class='why'>{e(check_id)}</div></td>"
                     f"<td>{e(iso_label(check_id))}</td><td class='num PASS'>{counts[PASS]}</td>"
                     f"<td class='num FAIL'>{counts[FAIL]}</td><td class='num ERROR'>{counts[ERROR]}</td></tr>")

    err_html = ""
    if errors:
        err_rows = "".join(f"<tr><td>{e(f.check_id)}</td><td class='res'>{e(f.resource)}</td>"
                           f"<td>{e(f.description)}</td></tr>" for f in errors)
        err_html = (f"<h2>Not evaluated ({len(errors)})</h2><p class='meta'>These resources could not be "
                    f"checked, usually due to missing read permissions. They are not counted as findings.</p>"
                    f"<div class='tbl'><table><thead><tr><th>Check</th><th>Resource</th><th>Reason</th></tr>"
                    f"</thead><tbody>{err_rows}</tbody></table></div>")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AWS S3 &amp; IAM Security Report</title><style>{REPORT_CSS}</style></head>
<body><main>
<h1>AWS S3 &amp; IAM Security Report</h1>
<div class="meta">Account <code>{e(ctx_info['account_id'])}</code> &middot; scanned as <code>{e(ctx_info['caller_arn'])}</code>
&middot; region <code>{e(ctx_info['region'])}</code> &middot; {e(ctx_info['generated'])}</div>
<div class="cards">{cards_html}</div>
<h2>Findings ({len(failed)})</h2>
{findings_html}
<h2>Check coverage</h2>
<div class="tbl"><table><thead><tr><th>Check</th><th>ISO/IEC 27001:2022 control</th>
<th class="num">Pass</th><th class="num">Fail</th><th class="num">Error</th></tr></thead>
<tbody>{cov_rows}</tbody></table></div>
{err_html}
<footer>Generated by scanner.py. Read-only scan; risk levels are heuristics &mdash; validate against business context.
ISO control mapping is indicative and editable in ISO_27001_CONTROLS.</footer>
</main></body></html>"""


# =============================================================================
# CLI
# =============================================================================

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Read-only AWS S3 & IAM security checker with ISO 27001 mapping.")
    ap.add_argument("--region", help="AWS region for API calls (default: profile/env region, else us-east-1)")
    ap.add_argument("--profile", help="Named AWS profile from ~/.aws/config (default: standard chain)")
    ap.add_argument("--output", default="aws_security_report.html", help="HTML report path")
    ap.add_argument("--json", dest="json_out", help="Optionally also write all findings as JSON")
    ap.add_argument("--only-region", action="store_true",
                    help="Only scan S3 buckets located in --region (default: all buckets)")
    ap.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"], default="none",
                    help="Exit 1 if any finding is at or above this risk (for CI)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s")
    logging.getLogger("botocore").setLevel(logging.WARNING)

    try:
        session = boto3.Session(profile_name=args.profile)
        region = args.region or session.region_name or "us-east-1"
        ctx = ScanContext(session, region, only_region=args.only_region)
    except NoCredentialsError:
        log.error("No AWS credentials found. Configure them via env vars, 'aws configure' or 'aws sso login'.")
        return 2
    except (ClientError, BotoCoreError) as exc:
        log.error("Cannot start scan (sts:GetCallerIdentity failed): %s", exc)
        return 2

    log.info("Scanning account %s as %s (region %s)", ctx.account_id, ctx.caller_arn, region)
    findings = run_scan(ctx)

    info = {"account_id": ctx.account_id, "caller_arn": ctx.caller_arn, "region": region,
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(render_html(findings, info))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump({"scan": info, "findings": [asdict(f) for f in findings]}, fh, indent=2)

    failed = [f for f in findings if f.status == FAIL]
    counts = ", ".join(f"{r}: {sum(1 for f in failed if f.risk == r)}" for r in RISK_LEVELS)
    log.info("Done. %d resources evaluated, %d findings (%s), %d not evaluated. Report: %s",
             len(findings), len(failed), counts, sum(1 for f in findings if f.status == ERROR), args.output)

    if args.fail_on != "none":
        threshold = RISK_LEVELS.index(args.fail_on.capitalize())
        if any(RISK_LEVELS.index(f.risk) <= threshold for f in failed):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
