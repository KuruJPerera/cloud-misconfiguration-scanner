# Cloud Misconfiguration Scanner

Scans an AWS account for common security misconfigurations. Outputs colour-coded terminal findings and a timestamped JSON report.

---

## What it checks

| Check | Severity | What it looks for |
|---|---|---|
| S3 public access | HIGH | Buckets with public access block settings disabled |
| IAM MFA | HIGH | Console users with no MFA device enrolled |
| Security groups | HIGH | SSH or RDP open to 0.0.0.0/0 |
| CloudTrail | HIGH | No active audit logging in the target region |
| Root account | HIGH | Root account used within the last 30 days |

---

## Requirements

- Python 3.8+
- AWS credentials configured via `aws configure`
- IAM permissions: `SecurityAudit` or `ReadOnlyAccess` minimum

```bash
pip install boto3 colorama
```

---

## Usage

```bash
# Full scan
python scanner.py

# Specific region
python scanner.py --region us-east-1

# Specific checks
python scanner.py --checks s3 iam sg

# Filter by severity
python scanner.py --severity HIGH

# Custom output file
python scanner.py --output report.json
```

---

## Output

```
  Cloud Misconfiguration Scanner
  Region : eu-west-2
  Checks : s3, iam, sg, cloudtrail, root

  [*] S3 public buckets... 1 finding(s)
  [*] IAM MFA............. 1 finding(s)
  [*] Security groups..... clean
  [*] CloudTrail.......... clean
  [*] Root account usage.. 1 finding(s)

  ────────────────────────────────────────────────────────────
  Findings (3)
  ────────────────────────────────────────────────────────────

  [HIGH]  S3 public access not fully blocked
          Resource : s3://jude-test-bucket-2026
          Detail   : One or more public access block settings are disabled.

  [HIGH]  IAM user without MFA
          Resource : iam::user/jude-admin
          Detail   : User has console access but no MFA device enrolled.

  [HIGH]  Root account used recently
          Resource : iam::root
          Detail   : Root account was used 0 day(s) ago.

  ────────────────────────────────────────────────────────────
  Summary  →  3 HIGH  0 MEDIUM  0 LOW
  ────────────────────────────────────────────────────────────

  [+] Report saved → misconfig_report_20260714_173217.json
```

---

## Tech stack

| | |
|---|---|
| Language | Python 3.11 |
| AWS SDK | boto3 |
| CLI | argparse |
| Output | colorama, JSON |

---

## CLI flags

| Flag | Short | Default | Description |
|---|---|---|---|
| `--region` | `-r` | eu-west-2 | AWS region to scan |
| `--checks` | `-c` | all | s3, iam, sg, cloudtrail, root |
| `--severity` | `-s` | all | Filter by HIGH, MEDIUM, LOW |
| `--output` | `-o` | timestamped | JSON report filename |
