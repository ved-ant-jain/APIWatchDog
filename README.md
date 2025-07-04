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
- [Verbose Mode & Debugging](#verbose-mode--debugging)
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
- ✅ Provides detailed verbose logging for troubleshooting
- ✅ Handles multiple policy retrieval methods for compatibility
- ✅ Provides risk assessment and remediation guidance
- ✅ Exports findings in multiple formats (JSON, CSV)
- ✅ Supports all AWS authentication methods

## 🎯 The Vulnerability

Private API Gateways are designed to be accessible only from within specific VPCs. However, when configured with overly permissive resource policies, they become accessible from any AWS account that can create a VPC endpoint in the same region.

### Common Misconfigurations:
```json
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
```

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

### 🔍 Enhanced Debugging & Verbose Mode
- **Detailed Logging**: Step-by-step scan progress
- **Error Analysis**: Specific error messages and troubleshooting hints
- **Policy Retrieval**: Multiple fallback methods for different API configurations
- **Real-time Feedback**: Live updates during scanning process

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
- Efficient API calls with fallback methods
- Graceful error handling and recovery

## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- Valid AWS credentials
- Internet connectivity

### Install Dependencies
```bash
# Clone the repository
git clone https://github.com/your-org/aws-api-gateway-scanner.git
cd aws-api-gateway-scanner

# Install required packages
pip install -r requirements.txt

# Optional: Install in virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Verify Installation
```bash
python api_gateway_scanner.py --help
```

## 🏃 Quick Start

```bash
# Basic scan of all regions
python api_gateway_scanner.py --region all

# Scan with verbose output for debugging
python api_gateway_scanner.py --region us-east-1 --verbose

# Export results to JSON with verbose logging
python api_gateway_scanner.py --region all --verbose --export json
```

## 📖 Usage

### Basic Syntax
```bash
python api_gateway_scanner.py [OPTIONS]
```

### Required Arguments
- `--region, -r`: AWS region(s) to scan

### Optional Arguments
- `--access-key`: AWS Access Key ID
- `--secret-key`: AWS Secret Access Key  
- `--session-token`: AWS Session Token (for temporary credentials)
- `--profile`: AWS profile name
- `--export`: Export format (json, csv)
- `--output, -o`: Output filename
- `--verbose, -v`: Enable verbose logging and debugging

## 🔑 Authentication

The scanner supports all standard AWS authentication methods:

### 1. Environment Variables
```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_SESSION_TOKEN="your-session-token"  # Optional
python api_gateway_scanner.py --region all
```

### 2. Command Line Arguments
```bash
python api_gateway_scanner.py --region all \
  --access-key AKIA... \
  --secret-key wJalrXUt... \
  --session-token IQoJb3Jp...
```

### 3. AWS Profiles
```bash
# Use named profile
python api_gateway_scanner.py --region all --profile production

# Use SSO profile
python api_gateway_scanner.py --region all --profile sso-admin
```

### 4. Default Credentials
```bash
# Uses ~/.aws/credentials or IAM role
python api_gateway_scanner.py --region all
```

## 🔍 Verbose Mode & Debugging

The enhanced verbose mode provides detailed insights into the scanning process and helps troubleshoot issues:

### Enable Verbose Mode
```bash
python api_gateway_scanner.py --region us-east-1 --verbose
```

### Verbose Output Example
```
INFO: Starting scan of region: us-east-1
INFO: Connected to API Gateway service in us-east-1
INFO: Found 3 REST APIs in us-east-1
INFO: Analyzing API 1/3: my-private-api (abc123def456) - Types: ['PRIVATE']
INFO: Policy analysis for abc123def456: CRITICAL - 2 issues found
WARNING: Private API def456ghi789 (internal-api) has no resource policy
ERROR: Failed to analyze private API ghi789jkl012: Parameter validation failed
ERROR: This might be due to API Gateway version compatibility or insufficient permissions
INFO: Direct policy retrieval failed for xyz789abc123, trying alternative method: An error occurred...
INFO: Policy analysis for xyz789abc123: SECURE - 0 issues found
```

### Debug Information Includes:
- **Connection Status**: Confirmation of AWS service connectivity
- **API Discovery**: Number of APIs found in each region
- **Policy Retrieval**: Multiple methods attempted for policy access
- **Error Analysis**: Specific error types and suggested solutions
- **Risk Assessment**: Real-time analysis results

### Save Debug Output
```bash
# Save all output to file for analysis
python api_gateway_scanner.py --region all --verbose 2>&1 | tee debug_output.log

# Run with maximum verbosity
python api_gateway_scanner.py --region all --verbose --export json --output detailed_scan.json
```

## 📄 Output Formats

### Console Output
```
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ Region        ┃ API ID               ┃ Name                      ┃ Type          ┃ Status      ┃ Issues      ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━┩
│ us-east-1     │ abc123def456         │ private-api-prod          │ REST API      │ CRITICAL    │ Principal   │
│               │                      │                           │               │             │ set to '*'  │
│ us-west-2     │ ghi789jkl012         │ internal-api              │ REST API      │ NO_POLICY   │ No resource │
│               │                      │                           │               │             │ policy      │
│ eu-west-1     │ mno345pqr678         │ secure-api                │ REST API      │ SECURE      │ None        │
└───────────────┴──────────────────────┴───────────────────────────┴───────────────┴─────────────┴─────────────┘

Scan Summary:
Total APIs found: 3
Critical issues: 1
High risk issues: 0
Medium risk issues: 0
```

### JSON Export
```json
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
  },
  {
    "region": "us-west-2",
    "api_id": "ghi789jkl012",
    "api_name": "internal-api",
    "api_type": "REST API",
    "endpoint_types": ["PRIVATE"],
    "status": "NO_POLICY",
    "issues": [
      "No resource policy found for private API - this may be a security risk"
    ],
    "policy_document": null
  }
]
```

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

4. **Policy Retrieval Issues**
   - Parameter validation failures
   - Insufficient permissions
   - API Gateway version compatibility

## 💡 Examples

### Comprehensive Security Audit with Debugging
```bash
# Scan all regions with full export and verbose logging
python api_gateway_scanner.py \
  --region all \
  --verbose \
  --export json \
  --output security_audit_$(date +%Y%m%d).json
```

### Troubleshooting Specific Region
```bash
# Debug issues in a specific region
python api_gateway_scanner.py \
  --region us-east-1 \
  --verbose \
  --profile my-profile 2>&1 | tee troubleshoot.log
```

### Multi-Account Scanning with Verbose Output
```bash
# Scan production account with detailed logging
python api_gateway_scanner.py --region all --profile prod-account --verbose

# Scan development account with export
python api_gateway_scanner.py --region all --profile dev-account --verbose --export csv

# Scan staging account with custom output
python api_gateway_scanner.py --region all --profile staging-account --verbose --export json --output staging_scan.json
```

### Continuous Integration with Enhanced Logging
```bash
#!/bin/bash
# CI/CD pipeline integration with verbose output
python api_gateway_scanner.py --region all --verbose --export json --output scan_results.json

# Check exit code and provide detailed feedback
if [ $? -eq 2 ]; then
    echo "CRITICAL: Security issues found! Check scan_results.json for details"
    exit 1
elif [ $? -eq 1 ]; then
    echo "WARNING: High risk issues found! Review scan_results.json"
    exit 1
else
    echo "SUCCESS: No critical issues detected"
    exit 0
fi
```

### Automated Reporting with Debug Information
```bash
# Generate daily security report with full debugging
python api_gateway_scanner.py \
  --region all \
  --verbose \
  --export csv \
  --output "daily_scan_$(date +%Y%m%d_%H%M%S).csv" \
  2>&1 | tee "daily_scan_debug_$(date +%Y%m%d_%H%M%S).log"
```

## 📋 Requirements

### System Requirements
- **Python**: 3.7 or higher
- **Memory**: 256MB minimum
- **Network**: Internet access to AWS APIs
- **Disk**: 50MB for dependencies

### AWS Permissions
The scanner requires the following IAM permissions:

```json
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
```

### Python Dependencies
- `boto3 >= 1.26.0` - AWS SDK for Python
- `rich >= 12.0.0` - Rich text formatting (optional but recommended)

## 🔧 Troubleshooting

### Common Issues and Solutions

#### Authentication Errors
```
Error: Unable to locate credentials
```
**Solution**: Ensure AWS credentials are properly configured
```bash
aws configure list
# or
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
```

#### Permission Denied
```
Error: User is not authorized to perform: apigateway:GET
```
**Solution**: Add required IAM permissions to your user/role

#### Parameter Validation Failed
```
Error checking policy: Parameter validation failed...
```
**Solution**: This is now handled automatically with fallback methods. Use `--verbose` to see detailed information:
```bash
python api_gateway_scanner.py --region us-east-1 --verbose
```

The scanner will attempt multiple methods to retrieve policies and provide detailed feedback about what's happening.

#### Region Not Found
```
Error: Invalid region specified
```
**Solution**: Use valid AWS region names
```bash
aws ec2 describe-regions --query 'Regions[].RegionName' --output text
```

#### No APIs Found
```
No API Gateways found.
```
**Solution**: Verify you have API Gateways in the specified regions. Use `--verbose` to see detailed scan information.

#### Connection Timeouts
```
Error: Connection timeout
```
**Solution**: Check internet connectivity and AWS service status. The scanner includes retry logic for transient failures.

### Enhanced Debugging

#### Enable Maximum Verbosity
```bash
# Get detailed information about every step
python api_gateway_scanner.py --region us-east-1 --verbose

# Save all debug output
python api_gateway_scanner.py --region all --verbose 2>&1 | tee full_debug.log
```

#### Analyze Specific API Issues
The verbose mode now provides specific information about:
- Policy retrieval methods attempted
- Specific error types and causes
- Fallback mechanisms used
- API Gateway version compatibility issues

#### Debug Policy Retrieval
```bash
# Focus on a specific region with detailed policy analysis
python api_gateway_scanner.py --region us-east-1 --verbose --export json --output debug_policies.json
```

### Getting Help
```bash
python api_gateway_scanner.py --help
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/your-org/aws-api-gateway-scanner.git
cd aws-api-gateway-scanner
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### Running Tests
```bash
python -m pytest tests/
python scripts/test_scanner.py
```

### Code Style
```bash
black api_gateway_scanner.py
flake8 api_gateway_scanner.py
```

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

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/ved-ant-jain/aws-api-gateway-scanner/issues)
- 💡 **Feature Requests**: [GitHub Discussions](https://github.com/ved-ant-jain/aws-api-gateway-scanner/discussions)
- 📧 **Security Issues**: [Security Issues](https://github.com/ved-ant-jain/aws-api-gateway-scanner/issues)
- 📖 **Documentation**: [Wiki](https://github.com/ved-ant-jain/aws-api-gateway-scanner/wiki)

---

**⭐ If this tool helped secure your AWS environment, please consider giving it a star!**
