# AWS Private API Gateway Misconfiguration Scanner

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-scanner-red.svg)](https://github.com/your-repo/api-gateway-scanner)

A comprehensive Python CLI tool designed to identify and assess security misconfigurations in AWS Private API Gateways that could allow unauthorized access from external AWS accounts.

## 🚨 Security Advisory

**Private API Gateways are not inherently secure just because they're labeled "private."** Misconfigured resource policies can expose them to any AWS account worldwide, creating significant security vulnerabilities.

## 📋 Table of Contents

- [Overview](#overview)
- [The Vulnerability](#the-vulnerability)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Authentication](#authentication)
- [Output Formats](#output-formats)
- [Risk Assessment](#risk-assessment)
- [Examples](#examples)
- [Requirements](#requirements)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)
- [License](#license)

## 🔍 Overview

This tool addresses a critical but often overlooked AWS security vulnerability where Private API Gateways can be accessed from external AWS accounts due to misconfigured resource-based policies. The scanner helps security professionals, DevOps teams, and AWS administrators identify these misconfigurations across their AWS infrastructure.

### What it does:
- ✅ Scans all AWS regions for API Gateway endpoints
- ✅ Identifies Private API Gateways with overly permissive policies
- ✅ Analyzes resource-based policies for security issues
- ✅ Provides risk assessment and remediation guidance
- ✅ Exports findings in multiple formats (JSON, CSV)
- ✅ Supports all AWS authentication methods

## 🎯 The Vulnerability

Private API Gateways are designed to be accessible only from within specific VPCs. However, when configured with overly permissive resource policies, they become accessible from any AWS account that can create a VPC endpoint in the same region.

### Common Misconfigurations:
\`\`\`json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",                    // ❌ CRITICAL: Allows ANY AWS account
      "Action": "execute-api:Invoke",
      "Resource": "*"
    }
  ]
}
\`\`\`

### Attack Vector:
1. Attacker discovers a misconfigured Private API Gateway
2. Creates a VPC endpoint in the same AWS region
3. Launches an EC2 instance in their VPC
4. Successfully invokes the "private" API from their AWS account

## ✨ Features

### 🌍 Multi-Region Support
- **All Regions**: `--region all`
- **Single Region**: `--region us-east-1`
- **Multiple Regions**: `--region us-east-1,eu-west-1,ap-southeast-1`

### 🔐 Comprehensive Authentication
- AWS Access Keys and Secret Keys
- Temporary credentials with session tokens
- AWS SSO and named profiles
- IAM roles and cross-account access
- Environment variables and credential files

### 🎨 Rich Output Formatting
- Color-coded risk assessment
- Detailed vulnerability descriptions
- Summary statistics and metrics
- Progress indicators for long scans

### 📊 Export Capabilities
- JSON format for programmatic processing
- CSV format for spreadsheet analysis
- Timestamped output files
- Custom filename support

### ⚡ Performance Optimized
- Concurrent region scanning
- Thread-safe operations
- Efficient API calls
- Graceful error handling

## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- Valid AWS credentials
- Internet connectivity

### Install Dependencies
\`\`\`bash
# Clone the repository
git clone https://github.com/your-org/aws-api-gateway-scanner.git
cd aws-api-gateway-scanner

# Install required packages
pip install -r requirements.txt

# Optional: Install in virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
\`\`\`

### Verify Installation
\`\`\`bash
python api_gateway_scanner.py --help
\`\`\`

## 🏃 Quick Start

\`\`\`bash
# Basic scan of all regions
python api_gateway_scanner.py --region all

# Scan specific region with verbose output
python api_gateway_scanner.py --region us-east-1 --verbose

# Export results to JSON
python api_gateway_scanner.py --region all --export json
\`\`\`

## 📖 Usage

### Basic Syntax
\`\`\`bash
python api_gateway_scanner.py [OPTIONS]
\`\`\`

### Required Arguments
- `--region, -r`: AWS region(s) to scan

### Optional Arguments
- `--access-key`: AWS Access Key ID
- `--secret-key`: AWS Secret Access Key  
- `--session-token`: AWS Session Token (for temporary credentials)
- `--profile`: AWS profile name
- `--export`: Export format (json, csv)
- `--output, -o`: Output filename
- `--verbose, -v`: Enable verbose logging

## 🔑 Authentication

The scanner supports all standard AWS authentication methods:

### 1. Environment Variables
\`\`\`bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_SESSION_TOKEN="your-session-token"  # Optional
python api_gateway_scanner.py --region all
\`\`\`

### 2. Command Line Arguments
\`\`\`bash
python api_gateway_scanner.py --region all \
  --access-key AKIA... \
  --secret-key wJalrXUt... \
  --session-token IQoJb3Jp...
\`\`\`

### 3. AWS Profiles
\`\`\`bash
# Use named profile
python api_gateway_scanner.py --region all --profile production

# Use SSO profile
python api_gateway_scanner.py --region all --profile sso-admin
\`\`\`

### 4. Default Credentials
\`\`\`bash
# Uses ~/.aws/credentials or IAM role
python api_gateway_scanner.py --region all
\`\`\`

## 📄 Output Formats

### Console Output
\`\`\`
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ Region        ┃ API ID               ┃ Name                      ┃ Type          ┃ Status      ┃ Issues      ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━┩
│ us-east-1     │ abc123def456         │ private-api-prod          │ REST API      │ CRITICAL    │ Principal   │
│               │                      │                           │               │             │ set to '*'  │
│ us-west-2     │ ghi789jkl012         │ internal-api              │ REST API      │ SECURE      │ None        │
└───────────────┴──────────────────────┴───────────────────────────┴───────────────┴─────────────┴─────────────┘

Scan Summary:
Total APIs found: 2
Critical issues: 1
High risk issues: 0
Medium risk issues: 0
\`\`\`

### JSON Export
\`\`\`json
[
  {
    "region": "us-east-1",
    "api_id": "abc123def456",
    "api_name": "private-api-prod",
    "api_type": "REST API",
    "endpoint_types": ["PRIVATE"],
    "status": "CRITICAL",
    "issues": [
      "Principal set to '*' (allows any AWS account)",
      "No conditions specified for permissive policy"
    ],
    "policy_document": "{\"Version\":\"2012-10-17\",...}"
  }
]
\`\`\`

## 🎯 Risk Assessment

### Risk Levels

| Level | Color | Description | Action Required |
|-------|-------|-------------|-----------------|
| 🔴 **CRITICAL** | Red | API accessible from any AWS account | **Immediate action required** |
| 🟠 **HIGH** | Orange | Broad access with insufficient conditions | **Review and restrict access** |
| 🟡 **MEDIUM** | Yellow | Minor policy issues or warnings | **Consider improvements** |
| 🟢 **SECURE** | Green | Properly configured | **No action needed** |
| ⚪ **NO_POLICY** | White | Private API without resource policy | **Add resource policy** |
| ❌ **ERROR** | Red | Unable to analyze | **Check permissions** |

### Common Issues Detected

1. **Principal Wildcards**
   - `"Principal": "*"`
   - `"Principal": {"AWS": "*"}`
   - `"Principal": {"AWS": "arn:aws:iam::*:root"}`

2. **Missing Conditions**
   - No `aws:SourceVpc` condition
   - No `aws:SourceVpce` condition
   - No IP address restrictions

3. **Overly Broad Actions**
   - `"Action": "*"`
   - `"Action": "execute-api:*"`

## 💡 Examples

### Comprehensive Security Audit
\`\`\`bash
# Scan all regions with full export
python api_gateway_scanner.py \
  --region all \
  --export json \
  --output security_audit_$(date +%Y%m%d).json \
  --verbose
\`\`\`

### Multi-Account Scanning
\`\`\`bash
# Scan production account
python api_gateway_scanner.py --region all --profile prod-account

# Scan development account  
python api_gateway_scanner.py --region all --profile dev-account

# Scan staging account
python api_gateway_scanner.py --region all --profile staging-account
\`\`\`

### Continuous Integration
\`\`\`bash
#!/bin/bash
# CI/CD pipeline integration
python api_gateway_scanner.py --region all --export json --output scan_results.json

# Check exit code
if [ $? -eq 2 ]; then
    echo "CRITICAL: Security issues found!"
    exit 1
elif [ $? -eq 1 ]; then
    echo "WARNING: High risk issues found!"
    exit 1
else
    echo "SUCCESS: No critical issues detected"
    exit 0
fi
\`\`\`

### Automated Reporting
\`\`\`bash
# Generate daily security report
python api_gateway_scanner.py \
  --region all \
  --export csv \
  --output "daily_scan_$(date +%Y%m%d_%H%M%S).csv"
\`\`\`

## 📋 Requirements

### System Requirements
- **Python**: 3.7 or higher
- **Memory**: 256MB minimum
- **Network**: Internet access to AWS APIs
- **Disk**: 50MB for dependencies

### AWS Permissions
The scanner requires the following IAM permissions:

\`\`\`json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "apigateway:GET",
        "ec2:DescribeRegions"
      ],
      "Resource": "*"
    }
  ]
}
\`\`\`

### Python Dependencies
- `boto3 >= 1.26.0` - AWS SDK for Python
- `rich >= 12.0.0` - Rich text formatting (optional but recommended)

## 🔧 Troubleshooting

### Common Issues

#### Authentication Errors
\`\`\`
Error: Unable to locate credentials
\`\`\`
**Solution**: Ensure AWS credentials are properly configured
\`\`\`bash
aws configure list
# or
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
\`\`\`

#### Permission Denied
\`\`\`
Error: User is not authorized to perform: apigateway:GET
\`\`\`
**Solution**: Add required IAM permissions to your user/role

#### Region Not Found
\`\`\`
Error: Invalid region specified
\`\`\`
**Solution**: Use valid AWS region names
\`\`\`bash
aws ec2 describe-regions --query 'Regions[].RegionName' --output text
\`\`\`

#### No APIs Found
\`\`\`
No API Gateways found.
\`\`\`
**Solution**: Verify you have API Gateways in the specified regions

### Debug Mode
\`\`\`bash
python api_gateway_scanner.py --region us-east-1 --verbose
\`\`\`

### Getting Help
\`\`\`bash
python api_gateway_scanner.py --help
\`\`\`

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
\`\`\`bash
git clone https://github.com/your-org/aws-api-gateway-scanner.git
cd aws-api-gateway-scanner
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
\`\`\`

### Running Tests
\`\`\`bash
python -m pytest tests/
python scripts/test_scanner.py
\`\`\`

### Code Style
\`\`\`bash
black api_gateway_scanner.py
flake8 api_gateway_scanner.py
\`\`\`

## ⚖️ Disclaimer

This tool is designed for legitimate security assessment purposes only. Users are responsible for:

- ✅ Obtaining proper authorization before scanning AWS environments
- ✅ Complying with their organization's security policies
- ✅ Following AWS Acceptable Use Policy
- ✅ Respecting rate limits and API quotas
- ✅ Protecting sensitive information discovered during scans

**The authors are not responsible for any misuse of this tool or any damages resulting from its use.**

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- AWS Security Team for their documentation on API Gateway security
- The open-source community for their contributions and feedback
- Security researchers who identified and disclosed this vulnerability class

## 📞 Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/your-org/aws-api-gateway-scanner/issues)
- 💡 **Feature Requests**: [GitHub Discussions](https://github.com/your-org/aws-api-gateway-scanner/discussions)
- 📧 **Security Issues**: security@yourorg.com
- 📖 **Documentation**: [Wiki](https://github.com/your-org/aws-api-gateway-scanner/wiki)

---

**⭐ If this tool helped secure your AWS environment, please consider giving it a star!**
