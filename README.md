# Cloud Misconfiguration Scanner

A Python tool that scans AWS accounts for critical security misconfigurations. Connects directly to AWS APIs, runs automated checks, and outputs colour-coded terminal findings with a timestamped JSON report.

---

## What it detects

- S3 buckets with public access enabled
- IAM users with no MFA enrolled
- Security groups with SSH or RDP open to the internet (0.0.0.0/0)
- Missing CloudTrail audit logging
- Root account used within the last 30 days

---

## Built With

- [Python 3.11](https://www.python.org/)
- [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [argparse](https://docs.python.org/3/library/argparse.html)
- [colorama](https://pypi.org/project/colorama/)

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/KuruJPerera/cloud-misconfiguration-scanner.git
cd cloud-misconfiguration-scanner
```

2. Install dependencies:

```bash
pip install boto3 colorama
```

3. Configure AWS credentials:

```bash
aws configure
```

---

## Usage

Run a full scan:

```bash
python scanner.py
```

Scan a specific region:

```bash
python scanner.py --region us-east-1
```

Run specific checks only:

```bash
python scanner.py --checks s3 iam sg
```

Filter by severity:

```bash
python scanner.py --severity HIGH
```

Save to a custom file:

```bash
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

## CLI Flags

| Flag | Short | Default | Description |
|---|---|---|---|
| `--region` | `-r` | eu-west-2 | AWS region to scan |
| `--checks` | `-c` | all | s3, iam, sg, cloudtrail, root |
| `--severity` | `-s` | all | Filter by HIGH, MEDIUM, LOW |
| `--output` | `-o` | timestamped | JSON report filename |

---

## Requirements

- Python 3.8+
- AWS credentials configured via `aws configure`
- IAM permissions: SecurityAudit or ReadOnlyAccess minimum
