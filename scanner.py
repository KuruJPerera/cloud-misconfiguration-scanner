"""
Cloud Misconfiguration Scanner
Checks an AWS account for common security misconfigurations.
Outputs a timestamped JSON report.

Requirements:
    pip install boto3 colorama
    AWS credentials configured via `aws configure` or environment variables.

Usage:
    python cloud_misconfig_scanner.py
    python cloud_misconfig_scanner.py --region us-east-1
    python cloud_misconfig_scanner.py --region eu-west-2 --output report.json
    python cloud_misconfig_scanner.py --checks s3 iam          # run specific checks only
    python cloud_misconfig_scanner.py --severity HIGH           # filter output by severity
"""

import argparse
import boto3
import json
import sys
from colorama import Fore, Style, init
from datetime import datetime, timezone

init(autoreset=True)  # colourised output works on Windows + Unix


# ── colours ──────────────────────────────────────────────────────────────────

def c_high(text):   return f"{Fore.RED}{Style.BRIGHT}{text}{Style.RESET_ALL}"
def c_medium(text): return f"{Fore.YELLOW}{Style.BRIGHT}{text}{Style.RESET_ALL}"
def c_low(text):    return f"{Fore.CYAN}{text}{Style.RESET_ALL}"
def c_ok(text):     return f"{Fore.GREEN}{text}{Style.RESET_ALL}"
def c_info(text):   return f"{Fore.WHITE}{text}{Style.RESET_ALL}"
def c_dim(text):    return f"{Style.DIM}{text}{Style.RESET_ALL}"

def severity_colour(severity, text=None):
    t = text or severity
    if severity == "HIGH":   return c_high(t)
    if severity == "MEDIUM": return c_medium(t)
    if severity == "LOW":    return c_low(t)
    return t


# ── helpers ──────────────────────────────────────────────────────────────────

def new_finding(check, severity, resource, detail):
    return {
        "check": check,
        "severity": severity,   # HIGH / MEDIUM / LOW
        "resource": resource,
        "detail": detail,
    }


# ── checks ───────────────────────────────────────────────────────────────────

def check_s3_public_buckets(session):
    """Flags S3 buckets that have public access enabled."""
    findings = []
    s3 = session.client("s3")
    buckets = s3.list_buckets().get("Buckets", [])

    for bucket in buckets:
        name = bucket["Name"]
        try:
            resp = s3.get_public_access_block(Bucket=name)
            config = resp["PublicAccessBlockConfiguration"]
            # All four settings should be True to block public access
            if not all([
                config.get("BlockPublicAcls"),
                config.get("IgnorePublicAcls"),
                config.get("BlockPublicPolicy"),
                config.get("RestrictPublicBuckets"),
            ]):
                findings.append(new_finding(
                    check="S3 public access not fully blocked",
                    severity="HIGH",
                    resource=f"s3://{name}",
                    detail="One or more public access block settings are disabled.",
                ))
        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            findings.append(new_finding(
                check="S3 public access block missing",
                severity="HIGH",
                resource=f"s3://{name}",
                detail="No public access block configuration found — bucket may be publicly accessible.",
            ))
        except Exception as e:
            findings.append(new_finding(
                check="S3 check error",
                severity="LOW",
                resource=f"s3://{name}",
                detail=str(e),
            ))

    return findings


def check_iam_mfa(session):
    """Flags IAM users with passwords but no MFA device enrolled."""
    findings = []
    iam = session.client("iam")
    paginator = iam.get_paginator("list_users")

    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
            # Only flag users who can log in via console (have a login profile)
            try:
                iam.get_login_profile(UserName=username)
                has_console_access = True
            except iam.exceptions.NoSuchEntityException:
                has_console_access = False

            if has_console_access and not mfa_devices:
                findings.append(new_finding(
                    check="IAM user without MFA",
                    severity="HIGH",
                    resource=f"iam::user/{username}",
                    detail="User has console access but no MFA device enrolled.",
                ))

    return findings


def check_security_groups(session):
    """Flags security groups that allow unrestricted inbound SSH or RDP."""
    findings = []
    ec2 = session.client("ec2")
    sgs = ec2.describe_security_groups().get("SecurityGroups", [])

    risky_ports = {22: "SSH", 3389: "RDP"}

    for sg in sgs:
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", sg_id)

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)

            for port, protocol_name in risky_ports.items():
                if from_port <= port <= to_port:
                    # Check for 0.0.0.0/0 (IPv4) or ::/0 (IPv6)
                    open_to_world = any(
                        r.get("CidrIp") == "0.0.0.0/0"
                        for r in rule.get("IpRanges", [])
                    ) or any(
                        r.get("CidrIpv6") == "::/0"
                        for r in rule.get("Ipv6Ranges", [])
                    )
                    if open_to_world:
                        findings.append(new_finding(
                            check=f"Security group open {protocol_name} to world",
                            severity="HIGH",
                            resource=f"ec2::security-group/{sg_id} ({sg_name})",
                            detail=f"Port {port} ({protocol_name}) is open to 0.0.0.0/0 or ::/0.",
                        ))

    return findings


def check_cloudtrail(session):
    """Flags if CloudTrail is not enabled in this region."""
    findings = []
    ct = session.client("cloudtrail")
    trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])

    active_trails = [
        t for t in trails
        if ct.get_trail_status(Name=t["TrailARN"]).get("IsLogging")
    ]

    if not active_trails:
        region = session.region_name
        findings.append(new_finding(
            check="CloudTrail not enabled",
            severity="HIGH",
            resource=f"cloudtrail::{region}",
            detail="No active CloudTrail found in this region — API activity is not being logged.",
        ))

    return findings


def check_root_account_usage(session):
    """Flags if the root account has been used recently (last 30 days)."""
    findings = []
    iam = session.client("iam")

    summary = iam.get_account_summary().get("SummaryMap", {})
    # get_credential_report gives us root last used info
    try:
        iam.generate_credential_report()
        report = iam.get_credential_report()
        lines = report["Content"].decode("utf-8").splitlines()
        headers = lines[0].split(",")
        for line in lines[1:]:
            fields = dict(zip(headers, line.split(",")))
            if fields.get("user") == "<root_account>":
                last_used = fields.get("password_last_used", "N/A")
                if last_used not in ("N/A", "no_information", "not_supported"):
                    last_used_dt = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
                    days_ago = (datetime.now(timezone.utc) - last_used_dt).days
                    if days_ago <= 30:
                        findings.append(new_finding(
                            check="Root account used recently",
                            severity="HIGH",
                            resource="iam::root",
                            detail=f"Root account was used {days_ago} day(s) ago. Use IAM users instead.",
                        ))
    except Exception as e:
        findings.append(new_finding(
            check="Root account check error",
            severity="LOW",
            resource="iam::root",
            detail=str(e),
        ))

    return findings


# ── runner ───────────────────────────────────────────────────────────────────

ALL_CHECKS = {
    "s3":         ("S3 public buckets",   check_s3_public_buckets),
    "iam":        ("IAM MFA",             check_iam_mfa),
    "sg":         ("Security groups",     check_security_groups),
    "cloudtrail": ("CloudTrail",          check_cloudtrail),
    "root":       ("Root account usage",  check_root_account_usage),
}

def run_scan(region, checks, severity_filter, output_file):
    print(c_info(f"\n  Cloud Misconfiguration Scanner"))
    print(c_dim( f"  Region : {region}"))
    print(c_dim( f"  Checks : {', '.join(checks)}"))
    print(c_dim( f"  Filter : {severity_filter or 'ALL'}\n"))

    session = boto3.Session(region_name=region)
    all_findings = []

    for key in checks:
        label, fn = ALL_CHECKS[key]
        print(c_info(f"  [*] {label}..."), end=" ", flush=True)
        try:
            results = fn(session)
            all_findings.extend(results)
            count = len(results)
            if count:
                print(c_high(f"{count} finding(s)") if any(r["severity"] == "HIGH" for r in results)
                      else c_medium(f"{count} finding(s)"))
            else:
                print(c_ok("clean"))
        except Exception as e:
            print(c_medium(f"ERROR: {e}"))

    # apply severity filter
    displayed = [f for f in all_findings if not severity_filter or f["severity"] == severity_filter]

    # ── print findings ────────────────────────────────────────────────────────
    if displayed:
        print(c_info(f"\n  {'─' * 60}"))
        print(c_info(f"  Findings ({len(displayed)})"))
        print(c_info(f"  {'─' * 60}"))
        for f in displayed:
            sev = severity_colour(f["severity"], f"  [{f['severity']:6}]")
            print(f"{sev}  {f['check']}")
            print(c_dim( f"           Resource : {f['resource']}"))
            print(c_dim( f"           Detail   : {f['detail']}"))
            print()
    else:
        print(c_ok("\n  No findings to display."))

    # ── summary ───────────────────────────────────────────────────────────────
    high   = sum(1 for f in all_findings if f["severity"] == "HIGH")
    medium = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    low    = sum(1 for f in all_findings if f["severity"] == "LOW")

    print(c_info(f"  {'─' * 60}"))
    print(f"  Summary  →  {c_high(f'{high} HIGH')}  {c_medium(f'{medium} MEDIUM')}  {c_low(f'{low} LOW')}")
    print(c_info(f"  {'─' * 60}\n"))

    # ── write JSON report ─────────────────────────────────────────────────────
    report = {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "region": region,
        "total_findings": len(all_findings),
        "findings_by_severity": {"HIGH": high, "MEDIUM": medium, "LOW": low},
        "findings": all_findings,
    }

    filename = output_file or f"misconfig_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    print(c_ok(f"  [+] Report saved → {filename}\n"))
    return report


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="cloud_misconfig_scanner",
        description="Scan an AWS account for common security misconfigurations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python cloud_misconfig_scanner.py
  python cloud_misconfig_scanner.py --region us-east-1
  python cloud_misconfig_scanner.py --checks s3 iam sg
  python cloud_misconfig_scanner.py --severity HIGH
  python cloud_misconfig_scanner.py --region eu-west-2 --output my_report.json
        """
    )
    parser.add_argument(
        "--region", "-r",
        default="eu-west-2",
        help="AWS region to scan (default: eu-west-2)"
    )
    parser.add_argument(
        "--checks", "-c",
        nargs="+",
        choices=ALL_CHECKS.keys(),
        default=list(ALL_CHECKS.keys()),
        metavar="CHECK",
        help=f"Checks to run. Options: {', '.join(ALL_CHECKS.keys())} (default: all)"
    )
    parser.add_argument(
        "--severity", "-s",
        choices=["HIGH", "MEDIUM", "LOW"],
        default=None,
        help="Filter displayed findings by severity (default: show all)"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output filename for JSON report (default: timestamped filename)"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_scan(
        region=args.region,
        checks=args.checks,
        severity_filter=args.severity,
        output_file=args.output,
    )