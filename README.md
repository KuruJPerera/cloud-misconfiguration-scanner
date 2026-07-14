# Cloud Misconfiguration Scanner

> A Python tool that scans AWS accounts for security misconfigurations and outputs severity-ranked findings with JSON reports.

Built by a Security Engineering student at Royal Holloway (NCSC-certified). Runs five automated checks against real AWS infrastructure using the boto3 SDK.

---

## The problem it solves

Misconfigured AWS accounts are one of the leading causes of cloud data breaches. Public S3 buckets, IAM users without MFA, and open security groups are consistently exploited in real attacks. Manual auditing at scale is slow and error-prone. This tool automates the detection.

---

## What it checks

| Check | Severity | What it looks for |
|---|---|---|
| S3 public access | HIGH | Buckets with public access block settings disabled |
| IAM MFA | HIGH | Console users with no MFA device enrolled |
| Security groups | HIGH | SSH or RDP open to 0.0.0.0/0 (the entire internet) |
| CloudTrail | HIGH | No active audit logging in the target region |
| Root account | HIGH | Root account used within the last 30 days |

---

## Tech stack

| | |
|---|---|
| Language | Python 3.11 |
| AWS SDK | boto3 |
| CLI | argparse |
| Terminal output | colorama (colour-coded severity) |
| Reporting | JSON (timestamped per scan) |
| Auth | AWS IAM + STS |

---

## Quick start

```bash
# Install dependencies
pip install boto3 colorama

# Configure AWS credentials
aws configure

# Run full scan
python scanner.py

# Run against a specific region
python scanner.py --region us-east-1

# Scan specific checks only
python scanner.py --checks s3 iam

# Show HIGH severity findings only
python scanner.py --severity HIGH
```

---

## Real scan output

This was run against a real AWS account. Three HIGH findings were detected, remediated, and verified clean on a second scan.

```
  Cloud Misconfiguration Scanner
  Region : eu-west-2
  Checks : s3, iam, sg, cloudtrail, root
  Filter : ALL

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

After remediation:

```
  [*] S3 public buckets... clean
  [*] IAM MFA............. clean
  [*] Security groups..... clean
  [*] CloudTrail.......... clean
  [*] Root account usage.. 1 finding(s)

  Summary  →  1 HIGH  0 MEDIUM  0 LOW
```

---

## JSON report

Every scan saves a timestamped JSON report automatically.

```json
{
  "scan_timestamp": "2026-07-14T17:32:17+00:00",
  "region": "eu-west-2",
  "total_findings": 3,
  "findings_by_severity": {
    "HIGH": 3,
    "MEDIUM": 0,
    "LOW": 0
  },
  "findings": [
    {
      "check": "S3 public access not fully blocked",
      "severity": "HIGH",
      "resource": "s3://jude-test-bucket-2026",
      "detail": "One or more public access block settings are disabled."
    }
  ]
}
```

---

## CLI reference

| Flag | Short | Description | Default |
|---|---|---|---|
| `--region` | `-r` | AWS region to scan | eu-west-2 |
| `--checks` | `-c` | s3, iam, sg, cloudtrail, root | all |
| `--severity` | `-s` | Filter by HIGH, MEDIUM, LOW | all |
| `--output` | `-o` | Custom JSON report filename | timestamped |

---

## Requirements

- Python 3.8+
- AWS account with IAM credentials configured via `aws configure`
- IAM permissions: `SecurityAudit` or `ReadOnlyAccess` policy minimum

---

## Author

Jude Perera, BSc Computer Science (Information Security), Royal Holloway, University of London — NCSC Academic Centre of Excellence.

[GitHub](https://github.com/KuruJPerera) · [Medium](https://medium.com/@pererajude39) · [LinkedIn](https://linkedin.com/in/Jude-Perera)
