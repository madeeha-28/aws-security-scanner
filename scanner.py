import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone

findings = []   # every problem we find goes in this list


def add_finding(check, resource, severity, description, fix):
    findings.append({
        "check": check,
        "resource": resource,
        "severity": severity,
        "description": description,
        "fix": fix,
    })


def check_s3():
    s3 = boto3.client("s3")
    for bucket in s3.list_buckets()["Buckets"]:
        name = bucket["Name"]

        # Check 1: is "Block Public Access" fully on?
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all(cfg.values()):
                add_finding("S3-PublicAccess", name, "High",
                            "Block Public Access is not fully enabled.",
                            "Enable all four Block Public Access settings.")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                add_finding("S3-PublicAccess", name, "High",
                            "No Block Public Access configuration exists.",
                            "Enable all four Block Public Access settings.")
            else:
                raise

        # Check 2: is versioning on?
        v = s3.get_bucket_versioning(Bucket=name)
        if v.get("Status") != "Enabled":
            add_finding("S3-Versioning", name, "Low",
                        "Versioning is disabled, so deleted or overwritten data can't be recovered.",
                        "Enable bucket versioning.")


def check_security_groups():
    ec2 = boto3.client("ec2")
    for sg in ec2.describe_security_groups()["SecurityGroups"]:
        for rule in sg["IpPermissions"]:
            open_to_world = any(r.get("CidrIp") == "0.0.0.0/0"
                                for r in rule.get("IpRanges", []))
            if not open_to_world:
                continue

            label = f'{sg["GroupId"]} ({sg["GroupName"]})'
            if rule.get("IpProtocol") == "-1":
                add_finding("EC2-OpenAllTraffic", label, "Critical",
                            "All ports are open to the internet (0.0.0.0/0).",
                            "Restrict the rule to specific IPs and ports.")
            else:
                low, high = rule.get("FromPort"), rule.get("ToPort")
                for port, service in [(22, "SSH"), (3389, "RDP")]:
                    if low is not None and low <= port <= high:
                        add_finding("EC2-OpenAdminPort", label, "High",
                                    f"{service} (port {port}) is open to the internet.",
                                    "Allow only your own IP, or use a VPN or Session Manager.")


def check_iam():
    iam = boto3.client("iam")

    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountMFAEnabled") != 1:
        add_finding("IAM-RootMFA", "root account", "Critical",
                    "MFA is not enabled on the root account.",
                    "Enable MFA on root.")

    for user in iam.list_users()["Users"]:
        name = user["UserName"]

        if not iam.list_mfa_devices(UserName=name)["MFADevices"]:
            add_finding("IAM-UserMFA", name, "Medium",
                        "User has no MFA device.",
                        "Enable MFA for this user.")

        for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
            age = (datetime.now(timezone.utc) - key["CreateDate"]).days
            if age > 90:
                add_finding("IAM-OldAccessKey", f"{name} / {key['AccessKeyId']}", "Medium",
                            f"Access key is {age} days old.",
                            "Rotate the key every 90 days or less.")


if __name__ == "__main__":
    check_s3()
    check_security_groups()
    check_iam()
    print(f"Found {len(findings)} issues")
    for f in findings:
        print(f["severity"], "-", f["check"], "-", f["resource"])