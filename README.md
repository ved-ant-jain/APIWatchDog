# APIWatchDog: AWS API Attack Surface Scanner

> An "Inside-Out" AWS security scanner that analyzes your entire API Gateway environment (REST, HTTP, and WebSocket) to find deep, endpoint-level misconfigurations that traditional scanners miss.

It moves beyond simple policy checks to map the true attack surface of your serverless applications, finding unauthenticated endpoints, integration vulnerabilities (like SSRF), and dozens of other high-risk settings.

## 🚨 Security Advisory

> A single `authorizationType: NONE` on a forgotten test endpoint can lead to a full account compromise.

Traditional "Outside-In" scanners (DAST) can't find your "shadow" APIs or understand the impact of a vulnerability.

APIWatchDog scans from the "Inside-Out," starting with your AWS configuration to find 100% of your API assets and their specific weaknesses.

## 📋 Table of Contents

  * Overview
  * The Vulnerability
  * Features
  * Installation
  * Quick Start
  * Usage
  * Authentication
  * Verbose Mode & Debugging
  * Output Formats
  * Risk Assessment
  * Examples
  * Requirements
  * Troubleshooting
  * Contributing
  * Disclaimer
  * License

## 🔍 Overview

This tool addresses a critical but often overlooked AWS security vulnerability where Private API Gateways can be accessed from external AWS accounts due to misconfigured resource-based policies.

More broadly, it scans for dozens of common misconfigurations across all API types.

The scanner helps security professionals, DevOps teams, and AWS administrators identify these misconfigurations across their AWS infrastructure.

**What it does:**

  * ✅ **Discovers 100% of API Assets:** Scans all regions for REST, HTTP, and WebSocket APIs, including "shadow" and "zombie" APIs.
  * ✅ **Finds Critical Auth Flaws:** Identifies unauthenticated endpoints (`authorizationType: NONE`), exposed `$default` routes, and weak API key usage.
  * ✅ **Analyzes Private API Security:** Detects misconfigured Private API resource policies and insecure VPC Endpoint policies.
  * ✅ **Scans Backend Integrations:** Finds potential SSRF, MOCK integrations, insecure VPC Links, and hardcoded IAM credentials.
  * ✅ **Audits API Lifecycle:** Checks for unrotated API keys, disabled logging/tracing, weak TLS, and missing WAF/Shield protection.
  * ✅ **Provides Detailed Reporting:** Exports all findings to JSON/CSV with clear risk levels.

## 🎯 The Vulnerability

Private API Gateways are designed to be accessible only from within specific VPCs.

However, when configured with overly permissive resource policies, they become accessible from any AWS account that can create a VPC endpoint in the same region.

This is just one of many vulnerabilities APIWatchDog finds.

**Common Misconfigurations:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*", // ❌ CRITICAL: Allows ANY AWS account
      "Action": "execute-api:Invoke",
      "Resource": "*"
    }
  ]
}
```

**Attack Vector:**

1.  Attacker discovers a misconfigured Private API Gateway
2.  Creates a VPC endpoint in the same AWS region
3.  Launches an EC2 instance in their VPC
4.  Successfully invokes the "private" API from their AWS account

## ✨ Features

APIWatchDog is a comprehensive scanner that checks for a wide range of vulnerabilities:

1.  **API Endpoint Security (CRITICAL)**
      * **Unauthenticated Endpoints:** Finds all REST and HTTP endpoints with `authorizationType: NONE`.
      * \*\*Unauthenticated $default Route:** Finds v2 HTTP APIs with a catch-all `$default\` route that has no authentication.
      * **Weak API Key Auth:** Flags endpoints that use an API Key *instead of* (not in addition to) real authentication.
      * **Insecure CORS:** Detects overly permissive `Access-Control-Allow-Origin: *` policies on `OPTIONS` methods.
2.  **Private API & VPC Security**
      * **Misconfigured Private API Policies (CRITICAL):** Detects private APIs with resource policies allowing `Principal: *` without a VPC condition, making them accessible from *any* AWS account.
      * **Insecure VPC Endpoints:** Scans `execute-api` VPC Endpoints for permissive resource policies (`Principal: *`) that could expose internal APIs.
3.  **Integration & Backend Risk (HIGH)**
      * **SSRF Vulnerabilities:** Detects `HTTP_PROXY` integrations that point to internal/private IP addresses (both IPv4 and IPv6).
      * **MOCK Integrations:** Finds `MOCK` integrations, which should not exist in production environments.
      * **VPC Link Integrations:** Flags `VPC_LINK` integrations for manual review to ensure backend services have proper authentication.
      * **Hardcoded Credentials:** Finds integrations that use a hardcoded IAM role credential instead of resource-based policies.
      * **VTL Mapping:** Flags endpoints that use VTL mapping templates, which require manual review for injection or data leak risks.
4.  **API Lifecycle & Configuration**
      * **Unrotated API Keys:** Scans for API Keys that have not been rotated in over 90 days.
      * **Default Endpoint Enabled:** Flags APIs that allow invocation via the default `execute-api` endpoint, which can bypass WAFs.
      * **"Zombie" API Detection:** Identifies APIs with no resources or no deployments.
5.  **Stage-Level Security**
      * **WAF Integration:** Checks if API stages are protected by a WAFv2 WebACL.
      * **Access Logging:** Checks that Access Logging is enabled.
      * **X-Ray Tracing:** Checks that X-Ray Tracing is enabled for observability.
      * **Cache Encryption:** Checks that cache data encryption is enabled (if caching is used).
6.  **Authorizer & Domain Security**
      * **Weak Authorizer Validation:** Finds `TOKEN` authorizers with no `identityValidationExpression` (regex).
      * **Insecure Lambda Authorizers:**
          * Checks for permissive Lambda resource policies.
          * Flags authorizers with dangerously short timeouts (\< 3s).
      * **Weak TLS Policies:** Scans custom domains and flags those using outdated `TLS_1_0` policies.
      * **Missing mTLS:** Flags regional custom domains that do not enforce mutual TLS.
      * **Shield Advanced:** Checks if AWS Shield Advanced is active on the account.

## 🚀 Installation

### Prerequisites

  * Python 3.7 or higher
  * Valid AWS credentials
  * Internet connectivity

### Install Dependencies

```sh
# Clone the repository
git clone https://github.com/ved-ant-jain/APIWatchDog.git
cd APIWatchDog

# Install required packages
pip install -r requirements.txt

# Optional: Install in virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Verify Installation

```sh
python api_gateway_scanner.py --help
```

## 🏃 Quick Start

```sh
# Basic scan of all regions
python api_gateway_scanner.py --region all

# Scan with verbose output for debugging
python api_gateway_scanner.py --region us-east-1 --verbose

# Export results to JSON with verbose logging
python api_gateway_scanner.py --region all --verbose --export json
```

## 📖 Usage

### Basic Syntax

```sh
python api_gateway_scanner.py [OPTIONS]
```

### Required Arguments

  * `--region, -r`: AWS region(s) to scan

### Optional Arguments

  * `--access-key`: AWS Access Key ID
  * `--secret-key`: AWS Secret Access Key
  * `--session-token`: AWS Session Token (for temporary credentials)
  * `--profile`: AWS profile name
  * `--export`: Export format (json, csv)
  * `--output, -o`: Output filename
  * `--verbose, -v`: Enable verbose logging and debugging

## 🔑 Authentication

The scanner supports all standard AWS authentication methods:

1.  **Environment Variables**
    ```sh
    export AWS_ACCESS_KEY_ID="your-access-key"
    export AWS_SECRET_ACCESS_KEY="your-secret-key"
    export AWS_SESSION_TOKEN="your-session-token"  # Optional
    python api_gateway_scanner.py --region all
    ```
2.  **Command Line Arguments**
    ```sh
    python api_gateway_scanner.py --region all \
      --access-key AKIA... \
      --secret-key wJalrXUt... \
      --session-token IQoJb3Jp...
    ```
3.  **AWS Profiles**
    ```sh
    # Use named profile
    python api_gateway_scanner.py --region all --profile production

    # Use SSO profile
    python api_gateway_scanner.py --region all --profile sso-admin
    ```
4.  **Default Credentials**
    ```sh
    # Uses ~/.aws/credentials or IAM role
    python api_gateway_scanner.py --region all
    ```

## 🔍 Verbose Mode & Debugging

The enhanced verbose mode provides detailed insights into the scanning process and helps troubleshoot issues:

### Enable Verbose Mode

```sh
python api_gateway_scanner.py --region us-east-1 --verbose
```

### Verbose Output Example

```text
INFO:APIWatchDog:Verifying necessary IAM permissions...
INFO:APIWatchDog:IAM permission check passed.
INFO:APIWatchDog:Starting scan of region: us-east-1
INFO:APIWatchDog:[us-east-1] Scanning REST (v1) APIs...
INFO:APIWatchDog:Found WAF acl-name associated with arn:aws:apigateway:us-east-1::/restapis/ab12cdef34/stages/prod
INFO:APIWatchDog:[us-east-1] Could not get authorizers for ab12cdef34: An error occurred (AccessDeniedException)...
INFO:APIWatchDog:[us-east-1] Scanning HTTP/WebSocket (v2) APIs...
INFO:APIWatchDog:[us-east-1] Scanning Custom Domains (v1)...
INFO:APIWatchDog:[us-east-1] Scanning API Keys...
INFO:APIWatchDog:[us-east-1] Scanning VPC Endpoints...
INFO:APIWatchDog:Finished scan of region: us-east-1.
Found 3 potential findings.
```

### Debug Information Includes:

  * **Connection Status**: Confirmation of AWS service connectivity
  * **API Discovery**: Number of APIs found in each region
  * **Policy Retrieval**: Multiple methods attempted for policy access
  * **Error Analysis**: Specific error types and suggested solutions
  * **Risk Assessment**: Real-time analysis results

### Save Debug Output

```sh
# Save all output to file for analysis
python api_gateway_scanner.py --region all --verbose 2>&1 | tee debug_output.log

# Run with maximum verbosity
python api_gateway_scanner.py --region all --verbose --export json --output detailed_scan.json
```

## 📄 Output Formats

### Console Output (Rich)

A color-coded, human-readable table printed directly to your console.

### JSON Export

`--export json`

```json
[
  {
    "region": "us-east-1",
    "api_id": "ab12cdef34",
    "api_name": "public-user-api",
    "api_type": "REST (REGIONAL)",
    "endpoint": "POST /admin/create",
    "risk": "CRITICAL",
    "finding_details": "Endpoint has NO authentication (authorizationType: NONE)."
  },
  {
    "region": "us-east-1",
    "api_id": "pv12cdef35",
    "api_name": "internal-db-api",
    "api_type": "REST (PRIVATE)",
    "endpoint": "N/A (Policy)",
    "risk": "CRITICAL",
    "finding_details": "Private API has a resource policy allowing 'Principal: *' with no VPC/VPCE condition, making it accessible from any AWS account."
  },
  {
    "region": "us-west-2",
    "api_id": "d12cdef36",
    "api_name": "proxy-api",
    "api_type": "REST (REGIONAL)",
    "endpoint": "ANY /proxy",
    "risk": "HIGH",
    "finding_details": "Integration URI points to a private IP (10.0.1.50). This is a potential SSRF risk."
  }
]
```

### CSV Export

`--export csv`

A standard CSV file with one row per finding.

## 🎯 Risk Assessment

Findings are categorized by risk level to help you prioritize remediation.

| Risk Level | Color | Description |
| :--- | :--- | :--- |
| **CRITICAL** | Red | Immediate Exploit - An unauthenticated public endpoint, an exposed `$default` route, or a fully exposed private API. |
| **HIGH** | Orange | Significant Risk - A potential SSRF, a MOCK integration in prod, or a very weak authorizer. |
| **MEDIUM** | Yellow | Security Hygiene - Missing WAF, disabled logging, unrotated keys, or permissive CORS/VPC Endpoint policies. |
| **LOW** | Dim | Informational - Missing tracing, short Lambda timeouts, or use of VTL mapping (requires review). |
| **INFO** | Blue | Context - AWS Shield Advanced is enabled. |

## 💡 Examples

### Comprehensive Security Audit with Debugging

```sh
# Scan all regions with full export and verbose logging
python api_gateway_scanner.py \
  --region all \
  --verbose \
  --export json \
  --output security_audit_$(date +%Y%m%d).json
```

### Troubleshooting Specific Region

```sh
# Debug issues in a specific region
python api_gateway_scanner.py \
  --region us-east-1 \
  --verbose \
  --profile my-profile 2>&1 | tee troubleshoot.log
```

### Multi-Account Scanning with Verbose Output

```sh
# Scan production account with detailed logging
python api_gateway_scanner.py --region all --profile prod-account --verbose

# Scan development account with export
python api_gateway_scanner.py --region all --profile dev-account --verbose --export csv

# Scan staging account with custom output
python api_gateway_scanner.py --region all --profile staging-account --verbose --export json --output staging_scan.json
```

### Continuous Integration with Enhanced Logging

```sh
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

```sh
# Generate daily security report with full debugging
python api_gateway_scanner.py \
  --region all \
  --verbose \
  --export csv \
  --output "daily_scan_$(date +%Y%m%d_%H%M%S).csv" \
  2>&1 | tee "daily_scan_debug_$(date +G%Y%m%d_%H%M%S).log"
```

## 📋 Requirements

### System Requirements

  * **Python**: 3.7 or higher
  * `pip install -r requirements.txt`

### AWS Permissions

The tool needs a read-only IAM policy. This policy provides the *minimum* permissions required for all checks.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "APIWatchDogReadOnly",
      "Effect": "Allow",
      "Action": [
        "apigateway:GET",
        "apigatewayv2:GET",
        "lambda:GetFunctionConfiguration",
        "lambda:GetPolicy",
        "lambda:ListFunctions",
        "ec2:DescribeVpcEndpoints",
        "wafv2:ListWebACLs",
        "wafv2:ListResourcesForWebACL",
        "shield:DescribeSubscription",
        "sts:GetCallerIdentity",
        "ec2:DescribeRegions"
      ],
      "Resource": "*"
    }
  ]
}
```

### Python Dependencies

  * `boto3 >= 1.26.0` - AWS SDK for Python
  * `rich >= 12.0.0` - Rich text formatting (optional but recommended)

## 🔧 Troubleshooting

### Common Issues and Solutions

**Authentication Errors**

  * **Error:** `Unable to locate credentials`
  * **Solution**: Ensure AWS credentials are properly configured
    ```sh
    aws configure list
    # or
    export AWS_ACCESS_KEY_ID="your-key"
    export AWS_SECRET_ACCESS_KEY="your-secret"
    ```

**Permission Denied**

  * **Error:** `User is not authorized to perform: apigateway:GET`
  * **Solution**: Add required IAM permissions to your user/role (see Requirements).

**Connection Timeouts**

  * **Error:** `Connection timeout`
  * Two. **Solution**: Check internet connectivity and AWS service status. The scanner includes retry logic for transient failures.

### Getting Help

```sh
python api_gateway_scanner.py --help
```

## 🤝 Contributing

Contributions are welcome\! Please feel free to open a GitHub Issue for bugs or a Pull Request for new features.

## ⚖️ Disclaimer

This tool is designed for legitimate security assessment purposes only. Users are responsible for:

  * ✅ Obtaining proper authorization before scanning AWS environments
  * ✅ Complying with their organization's security policies
  * ✅ Following AWS Acceptable Use Policy
  * ✅ Respecting rate limits and API quotas
  * ✅ Protecting sensitive information discovered during scans

The authors are not responsible for any misuse of this tool or any damages resulting from its use.

## 📄 License

This project is licensed under the MIT License - see the `LICENSE` file for details.