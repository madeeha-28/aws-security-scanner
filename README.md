# AWS Security Posture Scanner

A beginner-friendly Python tool that scans an AWS account for common security misconfigurations and produces a severity-rated HTML and JSON report. Built with `boto3` using a **read-only** IAM user.

I built this to learn cloud security fundamentals: IAM, S3, EC2 security groups, and how misconfigurations are detected and fixed.

## What it does

1. Connects to AWS using read-only credentials.
2. Runs 7 security checks across S3, EC2 security groups, and IAM.
3. Prints findings in the terminal, sorted by severity.
4. Saves a colour-coded HTML report and a JSON file.

## Checks

| Check ID | Service | What it looks for | Severity |
|---|---|---|---|
| `S3-PublicAccess` | S3 | Block Public Access not fully enabled on a bucket | High |
| `S3-Versioning` | S3 | Bucket versioning disabled | Low |
| `EC2-OpenAllTraffic` | EC2 | Security group allows all traffic from `0.0.0.0/0` | Critical |
| `EC2-OpenAdminPort` | EC2 | SSH (22) or RDP (3389) open to `0.0.0.0/0` | High |
| `IAM-RootMFA` | IAM | MFA not enabled on the root account | Critical |
| `IAM-UserMFA` | IAM | IAM user without an MFA device | Medium |
| `IAM-OldAccessKey` | IAM | Access key older than 90 days | Medium |

## Demo: before and after

I created three deliberate misconfigurations in my own lab account: a bucket with Block Public Access off and versioning disabled, a security group with SSH open to the internet, and an IAM user without MFA. The scanner detected all of them. I then fixed each one in the AWS console and re-scanned.

**Before: 5 findings**

![Before scan](before_report.png)

**After: 1 finding** (the remaining item is my `scanner` user, which has no MFA)

![After scan](after_report.png)

The test resources were deleted after the demo.

## How to run

**Requirements:** Python 3.10+, an AWS account, and the AWS CLI.

1. **Create a read-only IAM user** (for example `scanner`) and attach the AWS managed policies `SecurityAudit` and `ViewOnlyAccess`. Create an access key for it.

2. **Clone the repo and install boto3:**
   ```powershell
   git clone https://github.com/YOUR-USERNAME/aws-security-scanner.git
   cd aws-security-scanner
   python -m venv venv
   venv\Scripts\Activate.ps1
   pip install boto3
   ```

3. **Configure credentials:**
   ```powershell
   aws configure
   ```
   Enter your access key ID, secret key, a default region (for example `ap-south-1`), and output format `json`.

4. **Run the scan:**
   ```powershell
   python scanner.py my-scan
   ```
   This prints the findings and creates `my-scan.html` and `my-scan.json`. If you leave out the name, the files are called `report.html` and `report.json`.

## Security notes

- The scanner only **reads** configuration. It never changes anything in your account.
- Never commit access keys. The `.aws` credentials folder lives outside this project, and `.gitignore` excludes the virtual environment.
- Only scan accounts you own or are authorised to test.

## Limitations

- Only 7 checks, so this is not a full security audit.
- EC2 security groups are checked in a single region, the one set in `aws configure`.
- Only IPv4 `0.0.0.0/0` rules are checked, not IPv6 (`::/0`).
- S3 checks cover Block Public Access and versioning only, not bucket policies or ACLs.
- Findings are not yet mapped to the CIS AWS Foundations Benchmark.
- No automatic remediation. Fixes in the demo were made manually in the console.

## Next steps

- Add CloudTrail, GuardDuty, and S3 encryption checks
- Scan multiple regions
- Map findings to CIS Benchmark controls
- Write Terraform code for remediation
- Add unit tests with `moto`
- Compare results against Prowler

## Tech stack

Python, boto3, AWS IAM, S3, EC2, HTML/JSON reporting
