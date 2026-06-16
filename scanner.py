import boto3
import json
from datetime import datetime

def check_s3_buckets():
    """Check S3 buckets for public access misconfigurations"""
    findings = []
    s3 = boto3.client('s3')
    
    try:p
        buckets = s3.list_buckets()['Buckets']
        for bucket in buckets:
            name = bucket['Name']
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl['Grants']:
                    if 'AllUsers' in str(grant) or 'AuthenticatedUsers' in str(grant):
                        findings.append({
                            'resource': f's3://{name}',
                            'issue': 'Bucket has public ACL',
                            'severity': 'HIGH'
                        })
            except Exception as e:
                pass
    except Exception as e:
        findings.append({'resource': 'S3', 'issue': str(e), 'severity': 'ERROR'})
    
    return findings

def check_iam_users():
    """Check IAM users for missing MFA"""
    findings = []
    iam = boto3.client('iam')
    
    try:
        users = iam.list_users()['Users']
        for user in users:
            username = user['UserName']
            mfa = iam.list_mfa_devices(UserName=username)['MFADevices']
            if not mfa:
                findings.append({
                    'resource': f'iam/user/{username}',
                    'issue': 'User has no MFA enabled',
                    'severity': 'MEDIUM'
                })
    except Exception as e:
        findings.append({'resource': 'IAM', 'issue': str(e), 'severity': 'ERROR'})
    
    return findings

def check_security_groups():
    """Check EC2 security groups for open ports"""
    findings = []
    ec2 = boto3.client('ec2')
    
    try:
        sgs = ec2.describe_security_groups()['SecurityGroups']
        for sg in sgs:
            for rule in sg['IpPermissions']:
                for ip in rule.get('IpRanges', []):
                    if ip.get('CidrIp') == '0.0.0.0/0':
                        port = rule.get('FromPort', 'ALL')
                        findings.append({
                            'resource': f'sg/{sg["GroupId"]}',
                            'issue': f'Port {port} open to the world (0.0.0.0/0)',
                            'severity': 'HIGH'
                        })
    except Exception as e:
        findings.append({'resource': 'EC2', 'issue': str(e), 'severity': 'ERROR'})
    
    return findings

def run_scan():
    print("=" * 50)
    print("  Cloud Misconfiguration Scanner")
    print(f"  Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)
    
    all_findings = []
    all_findings += check_s3_buckets()
    all_findings += check_iam_users()
    all_findings += check_security_groups()
    
    if not all_findings:
        print("\n✅ No misconfigurations found!")
    else:
        print(f"\n⚠️  Found {len(all_findings)} issue(s):\n")
        for f in all_findings:
            print(f"[{f['severity']}] {f['resource']}")
            print(f"  → {f['issue']}\n")
    
    print("=" * 50)
    print("Scan complete.")

if _name_=
    run_scan()