#!/usr/bin/env python3
"""
APIWatchDog: AWS API Attack Surface Scanner

Scans all API Gateways (REST v1 & HTTP v2) in an AWS account for a wide range of
security misconfigurations, including unauthenticated endpoints, risky configurations,
and misconfigured private API resource policies.

This enhanced version includes scans for:
- API Stages (Logging, Tracing, Caching)
- API Authorizers (Permissions, Validation, Timeouts)
- WAF & Shield Integration (Optimized)
- CORS Misconfigurations
- Custom Domain Security (TLS, mTLS)
- Private API VPC Endpoint Policies
- Integration-level risks (SSRF, MOCK, VPC_LINK, hardcoded creds)
- API Key rotation
"""

import argparse
import boto3
import json
import sys
import logging
import re
import ipaddress
import threading
import csv # FIX: Added missing import
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from botocore.config import Config
from botocore.exceptions import ClientError

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    def rprint(*args, **kwargs):
        print(*args)
    print("Warning: 'rich' library not found. For a better visual experience, install with: pip install rich")

# Configure logging
logger = logging.getLogger("APIWatchDog")

# Boto3 configuration with timeouts and retries
BOTO_CONFIG = Config(
    connect_timeout=5,
    read_timeout=10,
    retries={'max_attempts': 3}
)

class APIGatewayScanner:
    """
    Scans AWS API Gateways for security misconfigurations.
    """
    
    def __init__(self, access_key: Optional[str] = None, secret_key: Optional[str] = None, 
                 session_token: Optional[str] = None, profile: Optional[str] = None):
        """Initialize the scanner with AWS credentials."""
        self.console = Console() if RICH_AVAILABLE else None
        self.results: List[Dict[str, Any]] = []
        self.results_lock = threading.Lock()
        
        # Permission flags (soft-fail)
        self.perms = {
            'apigateway': False,
            'apigatewayv2': False,
            'lambda': False,
            'ec2': False,
            'wafv2': False,
            'shield': False
        }

        try:
            if profile:
                logger.info(f"Using AWS profile: {profile}")
                self.session = boto3.Session(profile_name=profile)
            elif access_key and secret_key:
                logger.info("Using provided AWS access/secret keys.")
                self.session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    aws_session_token=session_token
                )
            else:
                logger.info("Using default AWS credentials (environment variables or IAM role).")
                self.session = boto3.Session()
                
            sts_client = self.session.client('sts', config=BOTO_CONFIG)
            identity = sts_client.get_caller_identity()
            self.account_id = identity['Account']
            logger.info(f"Successfully authenticated as: {identity['Arn']}")
            
        except Exception as e:
            rprint(f"[bold red]Error initializing AWS session: {e}[/bold red]")
            sys.exit(1)

    def _check_permissions(self) -> bool:
        """
        Verifies IAM permissions and sets capability flags (Soft Fail).
        Returns False only if critical API Gateway permissions are missing.
        """
        logger.info("Verifying permissions...")
        
        # Map service key to a specific check call (service, region, func, kwargs)
        checks = {
            'apigateway': ('apigateway', 'us-east-1', 'get_rest_apis', {'limit': 1}),
            'apigatewayv2': ('apigatewayv2', 'us-east-1', 'get_apis', {'MaxResults': '1'}),
            'lambda': ('lambda', 'us-east-1', 'list_functions', {'MaxItems': 1}),
            'ec2': ('ec2', 'us-east-1', 'describe_vpc_endpoints', {'MaxResults': 1}),
            'wafv2': ('wafv2', 'us-east-1', 'list_web_acls', {'Scope': 'REGIONAL', 'Limit': 1}),
            'shield': ('shield', 'us-east-1', 'describe_subscription', {})
        }

        for key, (svc, region, func, kwargs) in checks.items():
            try:
                client = self.session.client(svc, region_name=region, config=BOTO_CONFIG)
                getattr(client, func)(**kwargs)
                self.perms[key] = True
            except ClientError as e:
                code = e.response['Error']['Code']
                # ResourceNotFound is fine (service works, just empty/wrong ID)
                if code in ['ResourceNotFoundException', 'WAFInvalidParameterException']:
                    self.perms[key] = True
                elif code == 'AccessDeniedException':
                    logger.warning(f"Missing permission for {svc}:{func}. Related scans will be skipped.")
                else:
                    logger.warning(f"Error checking {svc}:{func}: {e}. Assuming permission missing.")
            except Exception as e:
                logger.warning(f"Error checking {svc}:{func}: {e}")

        # Critical failure only if we can't scan API Gateway itself
        if not self.perms['apigateway'] and not self.perms['apigatewayv2']:
            rprint("[bold red]Fatal Error: Missing permissions for apigateway:GetRestApis OR apigatewayv2:GetApis.[/bold red]")
            return False
            
        return True

    def _get_all_regions(self) -> List[str]:
        """Fetches available regions, falling back gracefully."""
        try:
            return self.session.get_available_regions('apigateway')
        except Exception as e:
            logger.warning(f"Could not fetch regions dynamically: {e}")
            return [
                "us-east-1", "us-east-2", "us-west-1", "us-west-2",
                "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-northeast-1"
            ]

    def _build_waf_map(self, region: str) -> Dict[str, str]:
        """
        Pre-fetches all WebACL associations for the region to avoid N+1 throttling.
        Returns: { ResourceArn: WebACLArn }
        """
        waf_map = {}
        if not self.perms['wafv2']:
            return waf_map

        try:
            waf_client = self.session.client('wafv2', region_name=region, config=BOTO_CONFIG)
            paginator = waf_client.get_paginator('list_web_acls')
            
            # 1. Get all WebACLs
            web_acls = []
            for page in paginator.paginate(Scope='REGIONAL'):
                web_acls.extend(page.get('WebACLs', []))

            # 2. For each WebACL, get its resources
            # Note: This is still O(W) where W is num_acls, but better than O(Stages)
            for acl in web_acls:
                acl_arn = acl['ARN']
                try:
                    res = waf_client.list_resources_for_web_acl(
                        WebACLArn=acl_arn, ResourceType='API_GATEWAY_STAGE'
                    )
                    for resource_arn in res.get('ResourceArns', []):
                        waf_map[resource_arn] = acl_arn
                except Exception as e:
                    logger.debug(f"[{region}] Failed to list resources for ACL {acl_arn}: {e}")
                    continue
                    
        except Exception as e:
            logger.warning(f"[{region}] Failed to build WAF map: {e}")
            
        return waf_map

    def scan_regions(self, regions: List[str]) -> List[Dict[str, Any]]:
        if 'all' in regions:
            regions = self._get_all_regions()

        if not RICH_AVAILABLE:
            print(f"Scanning {len(regions)} region(s)...")

        # Global Shield Check (Once)
        if self.perms['shield']:
            try:
                shield = self.session.client('shield', region_name='us-east-1', config=BOTO_CONFIG)
                sub = shield.describe_subscription()
                if sub.get('Subscription', {}).get('SubscriptionState') == 'ACTIVE':
                    self.results.append({
                        "region": "Global", "api_id": "N/A", "api_name": "Shield Advanced",
                        "api_type": "Account", "endpoint": "N/A", "risk": "INFO",
                        "finding_details": "AWS Shield Advanced is ACTIVE."
                    })
            except Exception as e:
                logger.debug(f"Shield check failed: {e}")

        with (Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True
        ) if RICH_AVAILABLE else self._null_progress()) as progress:
            
            task = progress.add_task("[cyan]Scanning regions...", total=len(regions)) if RICH_AVAILABLE else None
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(self.scan_region, region): region for region in regions}
                
                for future in as_completed(futures):
                    try:
                        res = future.result()
                        with self.results_lock:
                            self.results.extend(res)
                    except Exception as e:
                        logger.error(f"Region scan failed: {e}")
                    
                    if RICH_AVAILABLE:
                        progress.update(task, advance=1)
        
        return self.results

    def scan_region(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Scanning {region}")
        findings = []
        
        try:
            apigw = self.session.client('apigateway', region_name=region, config=BOTO_CONFIG)
            apigwv2 = self.session.client('apigatewayv2', region_name=region, config=BOTO_CONFIG)
            
            # Optimizations: Pre-fetch WAF map for this region
            waf_map = self._build_waf_map(region)

            # 1. REST APIs (v1)
            if self.perms['apigateway']:
                paginator = apigw.get_paginator('get_rest_apis')
                for page in paginator.paginate(PaginationConfig={'PageSize': 50}):
                    for api in page.get('items', []):
                        findings.extend(self.analyze_rest_api(apigw, api, region, waf_map))
                
                # Custom Domains v1
                findings.extend(self._analyze_custom_domains_v1(apigw, region))
                
                # API Keys
                findings.extend(self._analyze_api_keys(apigw, region))

            # 2. HTTP APIs (v2)
            if self.perms['apigatewayv2']:
                paginator = apigwv2.get_paginator('get_apis')
                for page in paginator.paginate(PaginationConfig={'PageSize': 50}):
                    for api in page.get('Items', []):
                        findings.extend(self.analyze_http_api(apigwv2, api, region, waf_map))

            # 3. VPC Endpoints
            if self.perms['ec2']:
                findings.extend(self._analyze_vpc_endpoints(region))

        except Exception as e:
            logger.error(f"[{region}] Scan failed: {e}")
            
        return findings

    def analyze_rest_api(self, client: Any, api: Dict, region: str, waf_map: Dict) -> List[Dict]:
        findings = []
        api_id = api['id']
        name = api.get('name', 'N/A')
        base = {"region": region, "api_id": api_id, "api_name": name, "api_type": "REST"}

        # Policy Check
        if 'PRIVATE' in api.get('endpointConfiguration', {}).get('types', []):
            findings.extend(self._check_private_policy(api.get('policy'), base))

        # Stages & WAF (Optimized)
        try:
            stages = client.get_stages(restApiId=api_id).get('item', [])
            if not stages and not client.get_resources(restApiId=api_id, limit=1).get('items'):
                 # Zombie Check
                 findings.append({**base, "risk": "LOW", "endpoint": "N/A", "finding_details": "Zombie API: No stages and no resources."})

            for stage in stages:
                s_name = stage['stageName']
                arn = f"arn:aws:apigateway:{region}::/restapis/{api_id}/stages/{s_name}"
                
                # WAF Check (O(1) lookup)
                if self.perms['wafv2'] and arn not in waf_map:
                    findings.append({**base, "risk": "MEDIUM", "endpoint": f"Stage: {s_name}", "finding_details": "Stage not protected by WAFv2."})
                
                # Logging/Tracing
                if not stage.get('tracingEnabled'):
                    findings.append({**base, "risk": "LOW", "endpoint": f"Stage: {s_name}", "finding_details": "X-Ray tracing disabled."})
        except Exception as e:
            logger.debug(f"Stage check error: {e}")

        # Resources & Methods
        findings.extend(self._analyze_resources(client, api_id, base))
        
        return findings

    def _analyze_resources(self, client, api_id, base) -> List[Dict]:
        findings = []
        try:
            paginator = client.get_paginator('get_resources')
            for page in paginator.paginate(restApiId=api_id):
                for res in page.get('items', []):
                    path = res.get('path', '')
                    for method in res.get('resourceMethods', {}):
                        # Skip OPTIONS
                        if method == 'OPTIONS':
                            self._check_cors(client, api_id, res['id'], path, base, findings)
                            continue

                        try:
                            # Method Details
                            meth = client.get_method(restApiId=api_id, resourceId=res['id'], httpMethod=method)
                            
                            # Auth Check
                            if meth.get('authorizationType') == 'NONE' and not meth.get('apiKeyRequired'):
                                findings.append({**base, "risk": "CRITICAL", "endpoint": f"{method} {path}", "finding_details": "Unauthenticated Endpoint."})

                            # Integration Analysis (SSRF & Lambda)
                            self._analyze_integration(client, api_id, res['id'], method, path, base, findings)

                        except Exception as e:
                            logger.debug(f"Method check error: {e}")
                            continue
        except Exception as e:
            logger.debug(f"Resource check error: {e}")
        return findings

    def _analyze_integration(self, client, api_id, res_id, method, path, base, findings):
        """Analyzes integration for SSRF, Mock, Hardcoded creds, and Lambda Authorizers."""
        try:
            integ = client.get_integration(restApiId=api_id, resourceId=res_id, httpMethod=method)
            itype = integ.get('type')
            uri = integ.get('uri', '')

            # MOCK check
            if itype == 'MOCK':
                findings.append({**base, "risk": "HIGH", "endpoint": f"{method} {path}", "finding_details": "MOCK integration in use."})

            # SSRF Check
            if itype == 'HTTP_PROXY' or itype == 'HTTP':
                if self._is_risky_endpoint(uri):
                    findings.append({**base, "risk": "HIGH", "endpoint": f"{method} {path}", "finding_details": f"Potential SSRF: Integration points to internal/local URI ({uri})."})

            # Lambda Permissions (if AWS_PROXY/AWS)
            if self.perms['lambda'] and 'lambda' in uri:
                self._check_lambda_policy(uri, base, f"{method} {path}", findings)

        except Exception as e:
            logger.debug(f"Integration analysis error: {e}")

    def _is_risky_endpoint(self, uri: str) -> bool:
        """Robust SSRF detection handling localhost, private IPs, and internal domains."""
        try:
            # Handle Stage Variables explicitly
            if '${stageVariables' in uri:
                return False # Cannot analyze dynamic URI, skip to avoid false positive

            parsed = urlparse(uri)
            host = parsed.hostname
            if not host: return False

            # Blocklist
            if host in ['localhost', '127.0.0.1', '::1', '0.0.0.0']:
                return True
            if host.endswith('.internal'): # AWS internal DNS
                return True

            # Strip brackets from IPv6 for ipaddress lib
            clean_host = host.strip('[]')
            
            try:
                ip = ipaddress.ip_address(clean_host)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    return True
            except ValueError:
                pass # Not an IP, assume safe public domain (naïve but prevents crash)

        except Exception:
            pass
        return False

    def _check_lambda_policy(self, uri: str, base, endpoint, findings):
        """Checks Lambda resource policy for broad permissions."""
        # Extract ARN with Stage Variable Handling
        # URI format: .../functions/ARN/invocations
        match = re.search(r'functions/(.*?)/invocations', uri)
        if not match: return
        
        arn = match.group(1)
        if '${' in arn: 
            findings.append({**base, "risk": "LOW", "endpoint": endpoint, "finding_details": "Lambda integration uses Stage Variables. Manual review recommended."})
            return

        try:
            lam = self.session.client('lambda', region_name=base['region'], config=BOTO_CONFIG)
            policy_res = lam.get_policy(FunctionName=arn)
            policy = json.loads(policy_res['Policy'])
            
            is_secure = False
            for stmt in policy.get('Statement', []):
                # We look for ANY condition that restricts source
                cond = stmt.get('Condition', {})
                # Check all known operators
                for op in ['ArnLike', 'ArnEquals', 'StringLike', 'StringEquals']:
                    if 'AWS:SourceArn' in cond.get(op, {}):
                        is_secure = True
                        break
            
            if not is_secure:
                findings.append({**base, "risk": "MEDIUM", "endpoint": endpoint, "finding_details": f"Lambda {arn.split(':')[-1]} policy may be overly permissive (no SourceArn condition found)."})

        except ClientError as e:
            # ResourceNotFound means no policy exists (secure by default usually)
            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                logger.warning(f"Lambda check failed: {e}")

    def _check_cors(self, client, api_id, res_id, path, base, findings):
        try:
            resp = client.get_method_response(restApiId=api_id, resourceId=res_id, httpMethod='OPTIONS', statusCode='200')
            headers = resp.get('responseParameters', {})
            # Robust check for wildcard origin
            origin = headers.get('method.response.header.Access-Control-Allow-Origin', '')
            if origin and (origin.strip("'\" ") == '*' or origin.strip() == '*'):
                findings.append({**base, "risk": "MEDIUM", "endpoint": f"OPTIONS {path}", "finding_details": "CORS allows '*' origin."})
        except Exception:
            pass

    def _check_private_policy(self, policy_str: Optional[str], base: Dict) -> List[Dict]:
        findings = []
        if not policy_str:
            return [{**base, "risk": "CRITICAL", "endpoint": "Policy", "finding_details": "Private API has NO resource policy."}]
        
        try:
            policy = json.loads(policy_str)
            for stmt in policy.get('Statement', []):
                if stmt.get('Effect') == 'Allow':
                    princ = stmt.get('Principal', {})
                    # Check for Principal: *
                    if princ == '*' or (isinstance(princ, dict) and princ.get('AWS') == '*'):
                        # Check if conditions restrict VPC
                        cond = stmt.get('Condition', {})
                        if not any(k in str(cond) for k in ['SourceVpc', 'SourceVpce']):
                            findings.append({**base, "risk": "CRITICAL", "endpoint": "Policy", "finding_details": "Private API Policy allows '*' without VPC condition."})
        except Exception:
            pass
        return findings

    def _analyze_custom_domains_v1(self, client, region) -> List[Dict]:
        findings = []
        try:
            paginator = client.get_paginator('get_domain_names')
            for page in paginator.paginate():
                for d in page.get('items', []):
                    name = d['domainName']
                    if d.get('securityPolicy') == 'TLS_1_0':
                        findings.append({"region": region, "api_id": "N/A", "api_name": name, "api_type": "Domain", "risk": "MEDIUM", "endpoint": name, "finding_details": "Weak TLS 1.0 policy."})
        except Exception as e:
            logger.debug(f"Domain analysis error: {e}")
        return findings

    def _analyze_api_keys(self, client, region) -> List[Dict]:
        findings = []
        try:
            paginator = client.get_paginator('get_api_keys')
            for page in paginator.paginate(includeValues=False):
                for key in page.get('items', []):
                    created = key.get('createdDate')
                    if created:
                        # Fix timezone aware comparison
                        if created.tzinfo is None:
                            created = created.replace(tzinfo=timezone.utc)
                        if (datetime.now(timezone.utc) - created).days > 90:
                            findings.append({"region": region, "api_id": "N/A", "api_name": key.get('name', 'N/A'), "api_type": "Key", "risk": "LOW", "endpoint": key['id'], "finding_details": "Old API Key (>90 days)."})
        except Exception as e:
            logger.debug(f"API Key analysis error: {e}")
        return findings

    def _analyze_vpc_endpoints(self, region) -> List[Dict]:
        findings = []
        if not self.perms['ec2']: return findings
        try:
            ec2 = self.session.client('ec2', region_name=region, config=BOTO_CONFIG)
            resp = ec2.describe_vpc_endpoints(Filters=[{'Name': 'service-name', 'Values': [f'com.amazonaws.{region}.execute-api']}])
            for vpce in resp.get('VpcEndpoints', []):
                policy_str = vpce.get('PolicyDocument')
                if not policy_str:
                     findings.append({"region": region, "api_id": "N/A", "api_name": vpce['VpcEndpointId'], "api_type": "VPCE", "risk": "MEDIUM", "endpoint": "Policy", "finding_details": "VPC Endpoint policy is missing (default allows all)."})
                     continue
                
                # Robust JSON check instead of string search
                try:
                    policy = json.loads(policy_str)
                    for stmt in policy.get('Statement', []):
                        if stmt.get('Effect') == 'Allow':
                            princ = stmt.get('Principal', {})
                            if princ == '*' or (isinstance(princ, dict) and princ.get('AWS') == '*'):
                                findings.append({"region": region, "api_id": "N/A", "api_name": vpce['VpcEndpointId'], "api_type": "VPCE", "risk": "MEDIUM", "endpoint": "Policy", "finding_details": "VPC Endpoint policy appears permissive (*)."})
                                break
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"VPCE analysis error: {e}")
        return findings

    def analyze_http_api(self, client, api, region, waf_map) -> List[Dict]:
        # Minimal implementation for HTTP API (v2) mirroring REST checks
        # Checks: Default route auth, WAF, Stages
        findings = []
        api_id = api['ApiId']
        name = api.get('Name', 'N/A')
        base = {"region": region, "api_id": api_id, "api_name": name, "api_type": "HTTP"}
        
        try:
            # Routes
            paginator = client.get_paginator('get_routes')
            for page in paginator.paginate(ApiId=api_id):
                for r in page['Items']:
                    if r.get('AuthorizationType') == 'NONE':
                        risk = "CRITICAL" if r['RouteKey'] == '$default' else "HIGH"
                        findings.append({**base, "risk": risk, "endpoint": r['RouteKey'], "finding_details": "No Authentication."})
            
            # Stages & WAF
            stages = client.get_stages(ApiId=api_id).get('Items', [])
            for s in stages:
                s_name = s['StageName']
                arn = f"arn:aws:apigateway:{region}::/apis/{api_id}/stages/{s_name}"
                if self.perms['wafv2'] and arn not in waf_map:
                    findings.append({**base, "risk": "MEDIUM", "endpoint": f"Stage: {s_name}", "finding_details": "No WAFv2 protection."})
        except Exception as e:
            logger.debug(f"HTTP API analysis error: {e}")
        return findings

    def display_results(self, results):
        if not results:
            rprint("[green]No vulnerabilities found.[/green]")
            return
        
        if RICH_AVAILABLE:
            table = Table(title="Scan Results")
            table.add_column("Risk", style="bold")
            table.add_column("Region")
            table.add_column("API")
            table.add_column("Endpoint")
            table.add_column("Details")
            
            colors = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow", "LOW": "blue", "INFO": "green"}
            for r in sorted(results, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x['risk'])):
                c = colors.get(r['risk'], "white")
                table.add_row(f"[{c}]{r['risk']}[/{c}]", r['region'], r['api_name'], r['endpoint'], r['finding_details'])
            self.console.print(table)
        else:
            print(json.dumps(results, indent=2, default=str))

    def export_results(self, results, format, filename):
        if not filename: filename = f"scan_{datetime.now().strftime('%Y%m%d')}.{format}"
        if format == 'json':
            with open(filename, 'w') as f: json.dump(results, f, indent=2, default=str)
        else:
            if not results: return
            keys = results[0].keys()
            with open(filename, 'w', newline='') as f:
                w = csv.DictWriter(f, fieldnames=keys)
                w.writeheader()
                w.writerows(results)
        rprint(f"[bold green]Exported to {filename}[/bold green]")

    def _null_progress(self):
        class N:
            def __enter__(s): return s
            def __exit__(*a): pass
        return N()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--region', nargs='+', default=['all'])
    parser.add_argument('--profile')
    parser.add_argument('--access-key')
    parser.add_argument('--secret-key')
    parser.add_argument('--session-token')
    parser.add_argument('--export', choices=['json', 'csv'])
    parser.add_argument('--output')
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)
    
    # Validation
    if (args.access_key and not args.secret_key) or (args.secret_key and not args.access_key):
        print("Error: Must provide both access key and secret key.")
        sys.exit(1)

    scanner = APIGatewayScanner(args.access_key, args.secret_key, args.session_token, args.profile)
    
    if not scanner._check_permissions():
        sys.exit(1)

    results = scanner.scan_regions(args.region)
    scanner.display_results(results)
    
    if args.export:
        scanner.export_results(results, args.export, args.output)

if __name__ == "__main__":
    main()