# Cloud Misconfiguration Scanner

A Python tool that scans AWS environments for common security misconfigurations.

## Features
- Detects publicly accessible S3 buckets
- Identifies IAM users without MFA enabled
- Flags EC2 security groups with ports open to the world (0.0.0.0/0)

## Requirements
- Python 3.x
- AWS credentials configured (AWS CLI)
- boto3

## Installation
pip install -r requirements.txt

## Usage
python scanner.py

## Author
Israel Okakaobari (Kaka)
BSc Computer Science — University of the People
Specialization: Cloud Computing & Ethical Hacking
GitHub: https://github.com/E279-ai