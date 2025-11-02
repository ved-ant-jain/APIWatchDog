#!/usr/bin/env python3
"""
APIWatchDog: AWS API Attack Surface Scanner

Scans all API Gateways (REST v1 & HTTP v2) in an AWS account for a wide range of
security misconfigurations, including unauthenticated endpoints, risky configurations,
and misconfigured private API resource policies.

This enhanced version includes scans for:
- API Stages (Logging, Tracing, Caching)
- API Authorizers (Permissions, Validation, Timeouts)
- WAF & Shield Integration
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
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import threading  # FIX #1: Import threading for lock
from botocore.config import Config
from botocore.exceptions import ClientError
from urllib.parse import urlparse # FIX NEW #3: Import urlparse for robust SSRF check

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    # Define a simple print function if rich is not available
    def rprint(*args, **kwargs):
        print(*args)
    print("Warning: 'rich' library not found. For a better visual experience, install with: pip install rich")


# Configure logging
# Set up a logger. The level will be configured in main() after parsing args.
logger = logging.getLogger(__name__)

# Boto3 configuration with timeouts and retries
# FIX: Add connection timeouts and retry logic
BOTO_CONFIG = Config(
    connect_timeout=5,
    read_timeout=10,
    retries={'max_attempts': 3}
)


class APIGatewayScanner:
    """
    Scans AWS API Gateways for security misconfigurations.
    
    This tool performs an "inside-out" scan using AWS credentials to read
    the configuration of all API Gateways, providing a comprehensive and
    accurate map of the API attack surface.
    """
    
    def __init__(self, access_key: Optional[str] = None, secret_key: Optional[str] = None, 
                 session_token: Optional[str] = None, profile: Optional[str] = None):
        """Initialize the scanner with AWS credentials."""
        self.console = Console() if RICH_AVAILABLE else None
        self.results: List[Dict[str, Any]] = []
        # FIX #1: Initialize a threading.Lock to prevent race conditions on self.results
        self.results_lock = threading.Lock()
        
        try:
            # Setup AWS session
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
                
            # Test credentials
            sts_client = self.session.client('sts', config=BOTO_CONFIG)
            identity = sts_client.get_caller_identity()
            self.account_id = identity['Account']
            logger.info(f"Successfully authenticated as: {identity['Arn']}")
            
        except Exception as e:
            rprint(f"[bold red]Error initializing AWS session: {e}[/bold red]")
            sys.exit(1)

    def _check_permissions(self) -> bool:
        """
        FIX #2: Check for essential IAM permissions before starting the scan.
        """
        logger.info("Verifying necessary IAM permissions...")
        permissions_ok = True
        
        # List of (service, region, function_to_call, kwargs)
        # Using us-east-1 as a standard region for checks
        perm_checks = [
            ('apigateway', 'us-east-1', 'get_rest_apis', {'limit': 1}),
            ('apigatewayv2', 'us-east-1', 'get_apis', {'MaxResults': '1'}),
            ('apigateway', 'us-east-1', 'get_api_keys', {'limit': 1}),
            # FIX NEW #2: Use list_functions, which is a better check
            ('lambda', 'us-east-1', 'list_functions', {'MaxItems': 1}),
            ('ec2', 'us-east-1', 'describe_vpc_endpoints', {'MaxResults': 1}),
            # FIX NEW #4: Use list_web_acls, which is more resilient
            ('wafv2', 'us-east-1', 'list_web_acls', {'Scope': 'REGIONAL', 'Limit': 1}),
            ('shield', 'us-east-1', 'describe_subscription', {}), # Shield is global, check in us-east-1
        ]
        
        for service, region, func, kwargs in perm_checks:
            try:
                client = self.session.client(service, region_name=region, config=BOTO_CONFIG)
                getattr(client, func)(**kwargs)
                
            except ClientError as e:
                if e.response['Error']['Code'] == 'AccessDenied':
                    rprint(f"[bold red]Permission Error:[/bold red] Missing [cyan]{service}:{func}[/cyan]")
                    permissions_ok = False
                elif e.response['Error']['Code'] in ('ResourceNotFoundException'):
                    # This can happen with lambda:get_policy check and is fine
                    pass
                else:
                    # Other error (e.g., service not active in region)
                    logger.warning(f"Permission check for {service}:{func} failed: {e}")
            except Exception as e:
                 logger.warning(f"Permission check for {service}:{func} failed with non-ClientError: {e}")
        
        if not permissions_ok:
            rprint("[bold red]Fatal Error: Missing critical IAM permissions.[/bold red]")
            rprint("Please attach a policy with read-only access for the services listed above.")
            return False
            
        logger.info("IAM permission check passed.")
        return True

    def _get_all_regions(self) -> List[str]:
        """Fetches all available AWS regions for the API Gateway service."""
        try:
            return self.session.get_available_regions('apigateway')
        except Exception as e:
            rprint(f"[bold yellow]Warning:[/bold yellow] Could not dynamically fetch all AWS regions: {e}")
            rprint("[yellow]Falling back to a built-in list of common regions. Some regions may be missed.[/yellow]")
            logger.warning(f"Could not fetch all regions, defaulting to common regions: {e}")
            # Fallback list if discovery fails
            return [
                "us-east-1", "us-east-2", "us-west-1", "us-west-2",
                "af-south-1", "ap-east-1", "ap-south-1", "ap-northeast-1",
                "ap-northeast-2", "ap-northeast-3", "ap-southeast-1",
                "ap-southeast-2", "ap-southeast-3", "ca-central-1",
                "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3",
                "eu-south-1", "eu-north-1", "me-south-1", "sa-east-1"
            ]

    def scan_regions(self, regions: List[str]) -> List[Dict[str, Any]]:
        """
        Scans a list of AWS regions in parallel for API Gateway misconfigurations.
        """
        if 'all' in regions:
            regions = self._get_all_regions()

        if not RICH_AVAILABLE:
            print(f"Scanning {len(regions)} region(s): {', '.join(regions)}")

        # FIX #5: Check Shield subscription once
        try:
            shield_client = self.session.client('shield', region_name='us-east-1', config=BOTO_CONFIG)
            sub = shield_client.describe_subscription()
            if sub.get('Subscription', {}).get('SubscriptionState') == 'ACTIVE':
                with self.results_lock:
                    self.results.append({
                        "region": "Global", "api_id": "N/A", "api_name": "AWS Shield Advanced",
                        "api_type": "Account Security", "endpoint": "N/A", "risk": "INFO",
                        "finding_details": "AWS Shield Advanced subscription is ACTIVE."
                    })
        except Exception as e:
            # Don't show an error if Shield isn't subscribed, as that's the default
            if "ResourceNotFoundException" not in str(e):
                logger.warning(f"Could not check Shield Advanced subscription: {e}")


        with (Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) if RICH_AVAILABLE else self._null_progress()) as progress:
            if RICH_AVAILABLE:
                task = progress.add_task("[cyan]Scanning regions...", total=len(regions))
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(self.scan_region, region): region for region in regions}
                
                for i, future in enumerate(as_completed(futures)):
                    region = futures[future]
                    try:
                        regional_results = future.result()
                        # FIX #1: Use the lock to safely append to the shared results list
                        if regional_results:
                            with self.results_lock:
                                self.results.extend(regional_results)
                    except Exception as e:
                        rprint(f"[bold red]Error scanning region {region}: {e}[/bold red]")
                        logger.error(f"Error scanning region {region}: {e}", exc_info=True)
                    if RICH_AVAILABLE:
                        progress.update(task, advance=1, description=f"[cyan]Scanning regions... (Completed {region})")
        
        return self.results

    def scan_region(self, region: str) -> List[Dict[str, Any]]:
        """
        Scans a single AWS region for all API Gateway (v1 & v2) vulnerabilities.
        """
        logger.info(f"Starting scan of region: {region}")
        regional_findings: List[Dict[str, Any]] = []
        
        try:
            # Create clients
            apigw_client = self.session.client('apigateway', region_name=region, config=BOTO_CONFIG)
            apigwv2_client = self.session.client('apigatewayv2', region_name=region, config=BOTO_CONFIG)
            waf_client = self.session.client('wafv2', region_name=region, config=BOTO_CONFIG)
            ec2_client = self.session.client('ec2', region_name=region, config=BOTO_CONFIG)
            lambda_client = self.session.client('lambda', region_name=region, config=BOTO_CONFIG)
            
            pagination_config = {'PageSize': 50}

            # --- 1. Scan REST APIs (v1) ---
            logger.info(f"[{region}] Scanning REST (v1) APIs...")
            paginator_v1 = apigw_client.get_paginator('get_rest_apis')
            for page in paginator_v1.paginate(PaginationConfig=pagination_config):
                for api in page.get('items', []):
                    regional_findings.extend(
                        self.analyze_rest_api(apigw_client, waf_client, lambda_client, api, region)
                    )

            # --- 2. Scan HTTP/WebSocket APIs (v2) ---
            logger.info(f"[{region}] Scanning HTTP/WebSocket (v2) APIs...")
            paginator_v2 = apigwv2_client.get_paginator('get_apis')
            for page in paginator_v2.paginate(PaginationConfig=pagination_config):
                for api in page.get('Items', []):
                    regional_findings.extend(
                        self.analyze_http_api(apigwv2_client, waf_client, api, region)
                    )
            
            # --- 3. Scan Custom Domains (v1) ---
            logger.info(f"[{region}] Scanning Custom Domains (v1)...")
            regional_findings.extend(
                self._analyze_custom_domains_v1(apigw_client, region)
            )
            
            # --- 4. Scan API Keys ---
            logger.info(f"[{region}] Scanning API Keys...")
            regional_findings.extend(
                self._analyze_api_keys(apigw_client, region)
            )

            # --- 5. Scan VPC Endpoints ---
            logger.info(f"[{region}] Scanning VPC Endpoints...")
            regional_findings.extend(
                self._analyze_vpc_endpoints(ec2_client, region)
            )

        except Exception as e:
            logger.warning(f"Could not scan region {region}. Error: {e}")
        
        logger.info(f"Finished scan of region: {region}. Found {len(regional_findings)} potential findings.")
        return regional_findings

    def analyze_rest_api(self, apigw_client: Any, waf_client: Any, lambda_client: Any, api: Dict[str, Any], region: str) -> List[Dict[str, Any]]:
        """
        Analyzes a single REST (v1) API, breaking checks into sub-functions.
        """
        findings: List[Dict[str, Any]] = []
        api_id = api.get('id', 'N/A')
        api_name = api.get('name', 'N/A')
        api_types = api.get('endpointConfiguration', {}).get('types', ['N/A'])
        api_type_str = ", ".join(api_types)

        base_finding = {
            "region": region, "api_id": api_id, "api_name": api_name,
            "api_type": f"REST ({api_type_str})",
        }

        # Check 1: Original Private API Policy Scan
        if 'PRIVATE' in api_types:
            try:
                policy_data = api.get('policy')
                if policy_data:
                    findings.extend(self._analyze_private_api_policy(policy_data, base_finding))
                else:
                    findings.append({
                        **base_finding, "risk": "MEDIUM", "endpoint": "N/A (Policy)",
                        "finding_details": "Private API has no resource policy. This may be an implicit security risk."
                    })
            except Exception as e:
                logger.warning(f"[{region}] Could not analyze policy for {api_id}: {e}")

        # Check 2: Default Endpoint Enabled
        if not api.get('disableExecuteApiEndpoint', False):
            findings.append({
                **base_finding, "risk": "MEDIUM", "endpoint": "N/A (API-Level)",
                "finding_details": "Default 'execute-api' endpoint is enabled. This can be used to bypass WAFs configured on a custom domain."
            })
            
        # FIX #4, #10: Analyze Stages
        findings.extend(self._analyze_rest_api_stages(apigw_client, waf_client, api_id, region, base_finding))
        
        # FIX #5: Analyze Authorizers
        findings.extend(self._analyze_rest_api_authorizers(apigw_client, lambda_client, api_id, base_finding))
        
        # FIX #6, #12, #13, #14, #16, #18: Analyze Resources/Methods/Integrations
        findings.extend(self._analyze_rest_api_resources(apigw_client, api_id, base_finding))

        return findings

    def _analyze_rest_api_stages(self, apigw_client: Any, waf_client: Any, api_id: str, region: str, base_finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyzes all stages for a REST API for logging, tracing, caching, and WAF.
        (FIX #4, #10, #11)
        """
        findings = []
        try:
            stages = apigw_client.get_stages(restApiId=api_id).get('item', [])
            for stage in stages:
                stage_name = stage.get('stageName')
                stage_arn = f"arn:aws:apigateway:{region}::/restapis/{api_id}/stages/{stage_name}"
                endpoint_desc = f"Stage: {stage_name}"
                
                # Check 4a: Tracing
                if not stage.get('tracingEnabled', False):
                    findings.append({
                        **base_finding, "risk": "LOW", "endpoint": endpoint_desc,
                        "finding_details": "X-Ray Tracing is disabled for this stage, hindering observability."
                    })
                
                # Check 4b: Logging
                log_settings = stage.get('methodSettings', {}).get('*/*')
                if not log_settings or log_settings.get('loggingLevel', 'OFF') == 'OFF':
                     findings.append({
                        **base_finding, "risk": "MEDIUM", "endpoint": endpoint_desc,
                        "finding_details": "Execution logging is disabled for this stage. Security incidents may not be recorded."
                    })
                
                # Check 10: Caching
                if stage.get('cacheClusterEnabled', False):
                    if not stage.get('cacheDataEncrypted', False):
                         findings.append({
                            **base_finding, "risk": "MEDIUM", "endpoint": endpoint_desc,
                            "finding_details": "Caching is enabled for this stage, but cache data encryption is disabled."
                        })
                
                # Check 11: WAF Integration
                if not self._check_waf_association(waf_client, stage_arn, 'REGIONAL'):
                     findings.append({
                        **base_finding, "risk": "MEDIUM", "endpoint": endpoint_desc,
                        "finding_details": "Stage is not protected by a WAFv2 WebACL."
                    })
        except Exception as e:
            logger.warning(f"[{base_finding['region']}] Could not get stages for {api_id}: {e}")
        return findings

    def _analyze_rest_api_authorizers(self, apigw_client: Any, lambda_client: Any, api_id: str, base_finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyzes all authorizers for a REST API for validation, TTL, and permissions.
        (FIX #5, NEW #3, GAP #1)
        """
        findings = []
        try:
            authorizers = apigw_client.get_authorizers(restApiId=api_id).get('items', [])
            for auth in authorizers:
                auth_name = auth.get('name')
                auth_type = auth.get('type', 'TOKEN')
                endpoint_desc = f"Authorizer: {auth_name}"
                
                if auth_type == 'TOKEN' and not auth.get('identityValidationExpression'):
                    findings.append({
                        **base_finding, "risk": "HIGH", "endpoint": endpoint_desc,
                        "finding_details": "TOKEN authorizer has no identity validation expression (regex), making it vulnerable to token-related attacks."
                    })
                
                if auth.get('authorizerResultTtlInSeconds', 0) > 300:
                     findings.append({
                        **base_finding, "risk": "LOW", "endpoint": endpoint_desc,
                        "finding_details": f"Authorizer has a long TTL ({auth.get('authorizerResultTtlInSeconds')}s). Permissions may not be revoked quickly."
                    })

                # NEW #3 & GAP #1: Check Lambda authorizer permissions and timeout
                if auth.get('authorizerUri'):
                    findings.extend(self._check_lambda_authorizer(lambda_client, auth['authorizerUri'], base_finding, endpoint_desc))

        except Exception as e:
            logger.warning(f"[{base_finding['region']}] Could not get authorizers for {api_id}: {e}")
        return findings

    def _extract_lambda_arn_from_uri(self, authorizer_uri: str) -> Optional[str]:
        """Helper to extract a Lambda ARN from an APIGW Authorizer URI."""
        # URI format: arn:aws:apigateway:REGION:lambda:path/2015-03-31/functions/LAMBDA_ARN/invocations
        match = re.search(r'(arn:aws:lambda:.*?:function:.*?)(/invocations|$)', authorizer_uri)
        if not match:
            logger.warning(f"Could not parse Lambda ARN from authorizer URI: {authorizer_uri}")
            return None
        return match.group(1)

    def _check_lambda_authorizer(self, lambda_client: Any, authorizer_uri: str, base_finding: Dict[str, Any], endpoint_desc: str) -> List[Dict[str, Any]]:
        """
        Checks a Lambda authorizer's resource policy and configuration.
        (NEW #3, GAP #1)
        """
        findings = []
        lambda_arn = self._extract_lambda_arn_from_uri(authorizer_uri)
        if not lambda_arn:
            return findings
            
        try:
            # GAP #1: Check Lambda timeout
            config = lambda_client.get_function_configuration(FunctionName=lambda_arn)
            timeout = config.get('Timeout', 3)
            if timeout < 3: # 3s is the default
                findings.append({
                    **base_finding, "risk": "LOW", "endpoint": endpoint_desc,
                    "finding_details": f"Lambda authorizer ({lambda_arn.split(':')[-1]}) has a short timeout ({timeout}s), which could cause auth failures under load."
                })

            # NEW #3: Check Lambda policy
            policy_response = lambda_client.get_policy(FunctionName=lambda_arn)
            policy = json.loads(policy_response.get('Policy', '{}'))
            
            for stmt in policy.get('Statement', []):
                if stmt.get('Effect') == 'Allow' and stmt.get('Principal', {}).get('Service') == 'apigateway.amazonaws.com':
                    condition = stmt.get('Condition', {})
                    source_arn = condition.get('ArnLike', {}).get('AWS:SourceArn')
                    
                    # Check if policy is overly permissive (not tied to a specific API)
                    if not source_arn or '*' in source_arn:
                        findings.append({
                            **base_finding, "risk": "MEDIUM", "endpoint": endpoint_desc,
                            "finding_details": f"Lambda authorizer ({lambda_arn.split(':')[-1]}) has a permissive resource policy (SourceArn: {source_arn})."
                        })
        except ClientError as e:
            # FIX NEW #2: Catch specific errors for invalid/missing lambda
            error_code = e.response['Error']['Code']
            if error_code in ('ResourceNotFoundException', 'InvalidParameterValueException'):
                findings.append({
                    **base_finding, "risk": "MEDIUM", "endpoint": endpoint_desc,
                    "finding_details": f"Lambda authorizer ({lambda_arn.split(':')[-1]}) could not be analyzed. It may be deleted or in another account. Error: {error_code}"
                })
            else:
                logger.warning(f"Could not get policy/config for Lambda authorizer {lambda_arn}: {e}")
        except Exception as e:
            logger.error(f"Error parsing Lambda authorizer {lambda_arn}: {e}")
        return findings

    def _analyze_rest_api_resources(self, apigw_client: Any, api_id: str, base_finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyzes all resources/methods for a REST API.
        (FIX #6, #12, #13, #14, #16, #18, NEW #6, NEW #7)
        """
        findings = []
        has_resources = False
        try:
            paginator = apigw_client.get_paginator('get_resources')
            pagination_config = {'PageSize': 50}
            
            for page in paginator.paginate(restApiId=api_id, PaginationConfig=pagination_config):
                for resource in page.get('items', []):
                    has_resources = True
                    resource_path = resource.get('path', 'N/A')
                    resource_id = resource.get('id', 'N/A')
                    
                    # FIX NEW #8: Change depth limit to 20
                    if resource_path.count('/') > 20: 
                         findings.append({
                            **base_finding, "risk": "LOW", "endpoint": f"Resource: {resource_path}",
                            "finding_details": "Resource path is deeply nested (>20 levels). This is unusual and may be worth a review."
                        })

                    resource_methods = resource.get('resourceMethods')
                    if not resource_methods:
                        continue

                    for method_name in resource_methods.keys():
                        endpoint_desc = f"{method_name} {resource_path}"
                        try:
                            method_details = apigw_client.get_method(
                                restApiId=api_id,
                                resourceId=resource_id,
                                httpMethod=method_name
                            )
                            auth_type = method_details.get('authorizationType', 'NONE')
                            api_key_required = method_details.get('apiKeyRequired', False)
                            
                            # Check 1: Unauthenticated Endpoint
                            if auth_type == 'NONE':
                                if not api_key_required:
                                    # FIX #12: Don't check OPTIONS for auth, check for CORS
                                    if method_name == 'OPTIONS':
                                        findings.extend(self._analyze_rest_api_cors(apigw_client, api_id, resource_id, resource_path, base_finding))
                                    else:
                                        findings.append({
                                            **base_finding, "risk": "CRITICAL", "endpoint": endpoint_desc,
                                            "finding_details": "Endpoint has NO authentication (authorizationType: NONE)."
                                        })
                                else:
                                    findings.append({
                                        **base_finding, "risk": "HIGH", "endpoint": endpoint_desc,
                                        "finding_details": "Endpoint uses API Key for 'authentication' (authorizationType: NONE), not authorization. This is a weak security pattern."
                                    })

                            # Check 2: Missing Request Validator
                            if not method_details.get('requestValidatorId'):
                                findings.append({
                                    **base_finding, "risk": "LOW", "endpoint": endpoint_desc,
                                    "finding_details": "Endpoint has no Request Validator configured. This can allow malformed data to the backend."
                                })
                            
                            # FIX #6: Check for request models
                            if method_name in ['POST', 'PUT', 'PATCH'] and not method_details.get('requestModels'):
                                findings.append({
                                    **base_finding, "risk": "LOW", "endpoint": endpoint_desc,
                                    "finding_details": f"Method {method_name} has no request models defined for its body, increasing risk of injection."
                                })
                            
                            # FIX #6, #18, NEW #6, NEW #7: Check Integrations
                            findings.extend(self._analyze_rest_api_integration(apigw_client, api_id, resource_id, method_name, base_finding, endpoint_desc))

                        except Exception as e:
                            logger.warning(f"[{base_finding['region']}] Could not get method details for {api_id} {endpoint_desc}: {e}")
            
            # FIX #14: Check for zero resources
            if not has_resources:
                 findings.append({
                    **base_finding, "risk": "LOW", "endpoint": "N/A (API-Level)",
                    "finding_details": "API has no resources defined. This might be an incomplete or 'zombie' API."
                })

            # FIX #16: Check for old deployments
            deployments = apigw_client.get_deployments(restApiId=api_id).get('items', [])
            if not deployments:
                 findings.append({
                    **base_finding, "risk": "LOW", "endpoint": "N/A (API-Level)",
                    "finding_details": "API has no deployments. This is likely an unused 'zombie' API."
                })
            
        except Exception as e:
            logger.warning(f"[{base_finding['region']}] Could not get resources for {api_id}: {e}")
        return findings
    
    def _analyze_rest_api_integration(self, apigw_client: Any, api_id: str, resource_id: str, method: str, base_finding: Dict[str, Any], endpoint_desc: str) -> List[Dict[str, Any]]:
        """
        Analyzes the integration for a specific method.
        (FIX #6, #18, NEW #3, NEW #6, NEW #7)
        """
        findings = []
        try:
            integration = apigw_client.get_integration(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=method
            )
            int_type = integration.get('type')

            # FIX NEW #6: Check for MOCK integrations
            if int_type == 'MOCK':
                 findings.append({
                    **base_finding, "risk": "HIGH", "endpoint": endpoint_desc,
                    "finding_details": "MOCK integration found. This should not be in a production environment."
                })

            # FIX NEW #7: Check for VPC_LINK integrations
            if integration.get('connectionType') == 'VPC_LINK':
                 findings.append({
                    **base_finding, "risk": "MEDIUM", "endpoint": endpoint_desc,
                    "finding_details": "Integration uses a VPC Link. Manual review required to ensure backend service has proper auth."
                })
            
            # FIX #18: Check for request/response transformations
            if integration.get('requestTemplates') or integration.get('responseTemplates'):
                 findings.append({
                    **base_finding, "risk": "LOW", "endpoint": endpoint_desc,
                    "finding_details": "Integration uses VTL mapping templates. Manual review required for potential injection or data leaks."
                })

            # FIX #6: Check for hardcoded credentials
            if integration.get('credentials'):
                 findings.append({
                    **base_finding, "risk": "MEDIUM", "endpoint": endpoint_desc,
                    "finding_details": "Integration uses a hardcoded IAM role credential. This is a potential security risk; prefer resource-based policies."
                })

            # FIX #6 & NEW #3: Check for SSRF risk in HTTP_PROXY
            if int_type == 'HTTP_PROXY' and integration.get('uri'):
                uri = integration.get('uri')
                # FIX NEW #3: Use urlparse for robust hostname extraction
                try:
                    parsed_uri = urlparse(uri)
                    hostname = parsed_uri.hostname
                    
                    if hostname:
                        # FIX NEW #4: Strip brackets from IPv6 addresses
                        if hostname.startswith('[') and hostname.endswith(']'):
                            hostname = hostname[1:-1]
                            
                        # Check if hostname is an IP address
                        ip = ipaddress.ip_address(hostname)
                        if ip.is_private or ip.is_loopback or ip.is_link_local:
                             findings.append({
                                **base_finding, "risk": "HIGH", "endpoint": endpoint_desc,
                                "finding_details": f"Integration URI points to a private IP ({hostname}). This is a potential SSRF risk."
                            })
                except ValueError:
                    # It's a domain name, not an IP. This is fine.
                    pass
                except Exception as e:
                    logger.info(f"Could not parse IP from integration URI {uri}: {e}")

        except Exception as e:
            logger.warning(f"[{base_finding['region']}] Could not get integration for {endpoint_desc}: {e}")
        return findings

    def _analyze_rest_api_cors(self, apigw_client: Any, api_id: str, resource_id: str, resource_path: str, base_finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """FIX #12: Analyzes CORS headers on an OPTIONS method"""
        findings = []
        endpoint_desc = f"OPTIONS {resource_path}"
        try:
            # Check the 200 response for the OPTIONS method
            response = apigw_client.get_method_response(restApiId=api_id, resourceId=resource_id, httpMethod='OPTIONS', statusCode='200')
            headers = response.get('responseParameters', {})
            
            origin_header = headers.get('method.response.header.Access-Control-Allow-Origin')
            # FIX NEW #1: Make check more robust
            if origin_header and (origin_header.strip().lower() == "'*'" or origin_header.strip().lower() == "*"):
                findings.append({
                    **base_finding, "risk": "MEDIUM", "endpoint": endpoint_desc,
                    "finding_details": "CORS policy allows 'Access-Control-Allow-Origin: *', which is overly permissive."
                })
        except Exception as e:
             # This will fail often if no 200/OPTIONS is set, which is fine.
            logger.info(f"Could not get CORS response for {api_id} {resource_path}: {e}")
        return findings

    def _analyze_private_api_policy(self, policy_data: Any, base_finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyzes a REST API's resource policy (str or dict) for common misconfigurations."""
        findings = []
        policy_doc = {}
        
        if isinstance(policy_data, str):
            try:
                policy_doc = json.loads(policy_data)
            except json.JSONDecodeError:
                logger.warning(f"[{base_finding['region']}] Could not parse policy JSON for {base_finding['api_id']}, it may be malformed.")
                return findings
        elif isinstance(policy_data, dict):
            policy_doc = policy_data
        else:
            logger.warning(f"[{base_finding['region']}] Policy for {base_finding['api_id']} is of unexpected type: {type(policy_data)}")
            return findings

        try:
            statements = policy_doc.get('Statement', [])
            for stmt in statements:
                effect = stmt.get('Effect', 'Deny')
                if effect != 'Allow':
                    continue

                principal = stmt.get('Principal', {})
                is_principal_star = False
                if principal == '*':
                    is_principal_star = True
                elif isinstance(principal, dict) and principal.get('AWS') == '*':
                    is_principal_star = True
                elif 'arn:aws:iam::*:root' in str(principal): # Fallback check
                     is_principal_star = True

                if is_principal_star:
                    condition = str(stmt.get('Condition', {}))
                    if 'aws:SourceVpc' not in condition and 'aws:SourceVpce' not in condition:
                        findings.append({
                            **base_finding, "risk": "CRITICAL", "endpoint": "N/A (Policy)",
                            "finding_details": "Private API has a resource policy allowing 'Principal: *' with no VPC/VPCE condition, making it accessible from any AWS account."
                        })
        except Exception as e:
            logger.error(f"[{base_finding['region']}] Error analyzing policy logic for {base_finding['api_id']}: {e}")
        return findings

    def analyze_http_api(self, apigwv2_client: Any, waf_client: Any, api: Dict[str, Any], region: str) -> List[Dict[str, Any]]:
        """Analyzes a single HTTP/WebSocket (v2) API for all route-level vulnerabilities."""
        findings: List[Dict[str, Any]] = []
        api_id = api.get('ApiId', 'N/A')
        api_name = api.get('Name', 'N/A')
        api_type = f"{api.get('ProtocolType', 'N/A')} (v2)"

        base_finding = {
            "region": region, "api_id": api_id, "api_name": api_name, "api_type": api_type,
        }

        # Check 1: Route-Level Authentication
        try:
            paginator = apigwv2_client.get_paginator('get_routes')
            pagination_config = {'PageSize': 50}
            for page in paginator.paginate(ApiId=api_id, PaginationConfig=pagination_config):
                for route in page.get('Items', []):
                    route_key = route.get('RouteKey', 'N/A')
                    auth_type = route.get('AuthorizationType', 'NONE')
                    
                    if auth_type == 'NONE':
                        # FIX NEW #5: $default route with no auth is CRITICAL
                        if route_key == '$default':
                            findings.append({
                                **base_finding, "risk": "CRITICAL", "endpoint": f"{route_key} (Route)",
                                "finding_details": "Default catch-all route '$default' has NO authentication."
                            })
                        else:
                            findings.append({
                                **base_finding, "risk": "CRITICAL", "endpoint": f"{route_key} (Route)",
                                "finding_details": "Endpoint has NO authentication (AuthorizationType: NONE)."
                            })
        except Exception as e:
            logger.warning(f"[{region}] Could not get routes for v2 API {api_id}: {e}")
            
        # FIX #15: Analyze HTTP/WSS API Stages
        try:
            stages = apigwv2_client.get_stages(ApiId=api_id).get('Items', [])
            for stage in stages:
                stage_name = stage.get('StageName')
                stage_arn = f"arn:aws:apigateway:{region}::/apis/{api_id}/stages/{stage_name}"
                endpoint_desc = f"Stage: {stage_name}"

                if not stage.get('AccessLogSettings'):
                     findings.append({
                        **base_finding, "risk": "MEDIUM", "endpoint": endpoint_desc,
                        "finding_details": "Access logging is disabled for this stage. Security incidents may not be recorded."
                    })

                # Check 11: WAF Integration
                if not self._check_waf_association(waf_client, stage_arn, 'REGIONAL'):
                     findings.append({
                        **base_finding, "risk": "MEDIUM", "endpoint": endpoint_desc,
                        "finding_details": "Stage is not protected by a WAFv2 WebACL."
                    })
        except Exception as e:
            logger.warning(f"[{region}] Could not get stages for v2 API {api_id}: {e}")
            
        return findings

    def _check_waf_association(self, waf_client: Any, api_stage_arn: str, scope: str) -> bool:
        """
        Checks if an API Gateway stage ARN is associated with a WAF.
        (FIX #11)
        """
        try:
            # We must get all WebACLs and check their associations
            paginator = waf_client.get_paginator('list_web_acls')
            for page in paginator.paginate(Scope=scope):
                for acl in page.get('WebACLs', []):
                    acl_arn = acl.get('ARN')
                    if not acl_arn:
                        continue
                    
                    resources = waf_client.list_resources_for_web_acl(WebACLArn=acl_arn, ResourceType='API_GATEWAY_STAGE').get('ResourceArns', [])
                    if api_stage_arn in resources:
                        logger.info(f"Found WAF {acl_arn} associated with {api_stage_arn}")
                        return True
        except Exception as e:
            # Often fails due to permissions, which is fine, we just can't check.
            logger.info(f"Could not check WAF association for {api_stage_arn}: {e}")
        return False

    def _analyze_custom_domains_v1(self, apigw_client: Any, region: str) -> List[Dict[str, Any]]:
        """
        Analyzes custom domains for TLS and mTLS settings.
        (FIX #17 & #8)
        """
        findings = []
        try:
            paginator = apigw_client.get_paginator('get_domain_names')
            for page in paginator.paginate(PaginationConfig={'PageSize': 25}):
                for domain in page.get('items', []):
                    domain_name = domain.get('domainName')
                    base_finding = {
                        "region": region, "api_id": "N/A", "api_name": f"Domain: {domain_name}",
                        "api_type": "Custom Domain", "endpoint": domain_name
                    }
                    
                    # Check 17: TLS Version
                    sec_policy = domain.get('securityPolicy', 'TLS_1_0')
                    if sec_policy == 'TLS_1_0':
                        findings.append({
                            **base_finding, "risk": "MEDIUM",
                            "finding_details": f"Custom domain is using an outdated '{sec_policy}' security policy. Recommend TLS_1_2."
                        })
                    
                    # Check 8: mTLS
                    if domain.get('endpointConfiguration', {}).get('types', ['EDGE'])[0] == 'REGIONAL':
                        mtls_auth = domain.get('mutualTlsAuthentication')
                        if not mtls_auth or not mtls_auth.get('truststoreUri'):
                             findings.append({
                                **base_finding, "risk": "LOW",
                                "finding_details": "Regional custom domain does not have mTLS (mutual TLS) configured."
                            })
        except Exception as e:
            logger.warning(f"[{region}] Could not analyze custom domains: {e}")
        return findings

    def _analyze_api_keys(self, apigw_client: Any, region: str) -> List[Dict[str, Any]]:
        """
        Analyzes API Keys for rotation.
        (NEW #4, FIX NEW #1)
        """
        findings = []
        try:
            paginator = apigw_client.get_paginator('get_api_keys')
            for page in paginator.paginate(includeValues=False, PaginationConfig={'PageSize': 25}):
                for key in page.get('items', []):
                    key_name = key.get('name', 'N/A')
                    key_id = key.get('id', 'N/A')
                    created_date = key.get('createdDate')
                    
                    # FIX NEW #1: Handle naive datetime objects
                    if created_date:
                        if created_date.tzinfo is None:
                            created_date = created_date.replace(tzinfo=timezone.utc)
                        
                        if (datetime.now(timezone.utc) - created_date).days > 90:
                            findings.append({
                                "region": region, "api_id": "N/A", "api_name": f"API Key: {key_name}",
                                "api_type": "API Key", "endpoint": key_id, "risk": "MEDIUM",
                                "finding_details": f"API Key was created on {created_date.date()} and has not been rotated in over 90 days."
                            })
        except Exception as e:
            logger.warning(f"[{region}] Could not analyze API Keys: {e}")
        return findings
        
    def _analyze_vpc_endpoints(self, ec2_client: Any, region: str) -> List[Dict[str, Any]]:
        """
        Analyzes VPC Endpoints for execute-api for insecure policies.
        (UNRESOLVED #7)
        """
        findings = []
        try:
            paginator = ec2_client.get_paginator('describe_vpc_endpoints')
            service_name = f"com.amazonaws.{region}.execute-api"
            
            for page in paginator.paginate(Filters=[{'Name': 'service-name', 'Values': [service_name]}]):
                for vpce in page.get('VpcEndpoints', []):
                    vpce_id = vpce.get('VpcEndpointId')
                    policy_str = vpce.get('PolicyDocument')
                    if not policy_str:
                         findings.append({
                            "region": region, "api_id": vpce_id, "api_name": f"VPC Endpoint: {vpce_id}",
                            "api_type": "VPC Endpoint", "endpoint": vpce_id, "risk": "MEDIUM",
                            "finding_details": "VPC Endpoint for execute-api has no resource policy. Default is full access within the VPC."
                        })
                         continue
                    
                    try:
                        policy_doc = json.loads(policy_str)
                        for stmt in policy_doc.get('Statement', []):
                            if stmt.get('Effect') == 'Allow':
                                principal = stmt.get('Principal', {})
                                is_principal_star = False
                                if principal == '*': is_principal_star = True
                                elif isinstance(principal, dict) and principal.get('AWS') == '*': is_principal_star = True
                                
                                if is_principal_star:
                                    findings.append({
                                        "region": region, "api_id": vpce_id, "api_name": f"VPC Endpoint: {vpce_id}",
                                        "api_type": "VPC Endpoint", "endpoint": vpce_id, "risk": "HIGH",
                                        "finding_details": "VPC Endpoint policy allows 'Principal: *', potentially exposing private APIs to any user/role within the VPC."
                                    })
                    except Exception as e:
                        logger.warning(f"Could not parse VPC Endpoint policy for {vpce_id}: {e}")

        except Exception as e:
            logger.warning(f"[{region}] Could not analyze VPC Endpoints: {e}")
        return findings

    def display_results(self, results: List[Dict[str, Any]]):
        """Displays the scan results in a rich-formatted table."""
        if not results:
            rprint("\n[bold green]✅ No security misconfigurations found.[/bold green]")
            return
            
        if not RICH_AVAILABLE:
            print("\nScan Results:\n")
            print("---")
            for finding in results:
                print(f" Risk: {finding.get('risk', 'N/A')}")
                print(f" Region: {finding.get('region', 'N/A')}")
                print(f" API Name: {finding.get('api_name', 'N/A')} ({finding.get('api_id', 'N/A')})")
                print(f" API Type: {finding.get('api_type', 'N/A')}")
                print(f" Endpoint: {finding.get('endpoint', 'N/A')}")
                print(f" Finding: {finding.get('finding_details', 'N/A')}")
                print("---")
        else:
            table = Table(title="AWS API Attack Surface Scan Results", show_lines=True)
            table.add_column("Risk", style="bold", min_width=10)
            table.add_column("Region", style="cyan", min_width=10)
            table.add_column("API Name", style="magenta", min_width=20)
            table.add_column("API Type", style="green", min_width=15)
            table.add_column("Endpoint", style="yellow", min_width=20)
            table.add_column("Finding Details", style="default", min_width=40)
            
            risk_styles = {
                "CRITICAL": "[bold red]", "HIGH": "[bold yellow]", "MEDIUM": "[yellow]", "LOW": "[dim]", "INFO": "[blue]"
            }
            
            risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            sorted_results = sorted(results, key=lambda x: risk_order.get(x.get('risk'), 99))
            
            for finding in sorted_results:
                risk = finding.get('risk', 'N/A')
                style = risk_styles.get(risk, "[white]")
                
                table.add_row(
                    f"{style}{risk}",
                    finding.get('region', 'N/A'),
                    f"{finding.get('api_name', 'N/A')}\n[dim]{finding.get('api_id', 'N/A')}",
                    finding.get('api_type', 'N/A'),
                    finding.get('endpoint', 'N/A'),
                    finding.get('finding_details', 'N/A')
                )
                
            self.console.print("\n")
            self.console.print(table)

    def export_results(self, results: List[Dict[str, Any]], export_format: str, filename: Optional[str] = None):
        """Exports the scan results to JSON or CSV."""
        if not results:
            rprint("[yellow]No results to export.[/yellow]")
            return

        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"apiwatchdog_scan_{timestamp}.{export_format}"
            
        try:
            if export_format == 'json':
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=4, default=str) # Add default=str for datetime
            
            elif export_format == 'csv':
                all_keys: Set[str] = set().union(*(d.keys() for d in results))
                fieldnames = sorted(list(all_keys))
                
                with open(filename, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    for item in results:
                        writer.writerow(item)
            
            rprint(f"\n[bold green]Successfully exported {len(results)} findings to {filename}[/bold green]")
            
        except Exception as e:
            rprint(f"\n[bold red]Error exporting results to {filename}: {e}[/bold red]")
            
    def _null_progress(self):
        """A null context manager for when 'rich' is not available."""
        class NullProgress:
            def __enter__(self): return self
            def __exit__(self, exc_type, exc_val, exc_tb): pass
            def add_task(self, *args, **kwargs): return None
            def update(self, *args, **kwargs): pass
        return NullProgress()

def main():
    parser = argparse.ArgumentParser(
        description="APIWatchDog: AWS API Attack Surface Scanner",
        epilog="Finds unauthenticated endpoints, misconfigured private APIs, and other security flaws."
    )
    
    cred_group = parser.add_argument_group('AWS Credentials')
    cred_group.add_argument('--access-key', help='AWS Access Key ID')
    cred_group.add_argument('--secret-key', help='AWS Secret Access Key')
    # FIX #1 (New): Corrected typo from ..add_argument to .add_argument
    cred_group.add_argument('--session-token', help='AWS Session Token (for temporary credentials)')
    cred_group.add_argument('--profile', help='AWS profile name (from ~/.aws/credentials)')
    
    scan_group = parser.add_argument_group('Scan Configuration')
    scan_group.add_argument('--region', '-r', dest='regions', nargs='+', default=['all'],
                            help='AWS region(s) to scan. Default: "all". Example: us-east-1 us-west-2')
    
    output_group = parser.add_argument_group('Output')
    output_group.add_argument('--export', choices=['json', 'csv'], help='Export results to a file (json or csv)')
    output_group.add_argument('--output', '-o', help='Output filename. If not specified, a default is generated.')
    output_group.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging for debugging')
    
    args = parser.parse_args()
    
    # FIX #9: Configure logging once, and only if handlers aren't already set
    if not logging.getLogger().hasHandlers():
        log_level = logging.INFO if args.verbose else logging.WARNING
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(level=log_level, format=log_format)
    
    # Silence boto3's noisy logging unless we are in verbose mode
    if not args.verbose:
        logging.getLogger('boto3').setLevel(logging.CRITICAL)
        logging.getLogger('botocore').setLevel(logging.CRITICAL)
        logging.getLogger('urllib3').setLevel(logging.CRITICAL)

    global logger
    logger = logging.getLogger("APIWatchDog") # Re-get logger after config
    
    if not RICH_AVAILABLE:
        print("--- APIWatchDog: AWS API Attack Surface Scanner ---")

    # FIX #3: Validate that if one key is provided, the other is too.
    if (args.access_key and not args.secret_key) or (not args.access_key and args.secret_key):
        rprint("[bold red]Fatal Error: Credential Mismatch[/bold red]")
        rprint("You must provide --access-key and --secret-key together.")
        sys.exit(1)

    try:
        scanner = APIGatewayScanner(
            access_key=args.access_key,
            secret_key=args.secret_key,
            session_token=args.session_token,
            profile=args.profile
        )
        
        # FIX #2: Perform pre-scan permission check
        if not scanner._check_permissions():
            sys.exit(1) # Exit if permissions are missing
        
        results = scanner.scan_regions(args.regions)
        scanner.display_results(results)
        
        # Show summary
        total_findings = len(results)
        critical_count = len([r for r in results if r.get('risk') == 'CRITICAL'])
        high_count = len([r for r in results if r.get('risk') == 'HIGH'])
        medium_count = len([r for r in results if r.get('risk') == 'MEDIUM'])
        low_count = len([r for r in results if r.get('risk') == 'LOW'])
        info_count = len([r for r in results if r.get('risk') == 'INFO'])
        
        rprint("\n[bold]Scan Summary:[/bold]")
        rprint(f"Total Findings: {total_findings}")
        rprint(f"[bold red]Critical: {critical_count} [bold yellow]High: {high_count} [yellow]Medium: {medium_count} [dim]Low: {low_count} [blue]Info: {info_count}")
        
        if args.export:
            scanner.export_results(results, args.export, args.output)
        
        if critical_count > 0:
            sys.exit(2)
        elif high_count > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        rprint("\n[bold yellow]Scan interrupted by user.[/bold yellow]")
        sys.exit(130)
    except Exception as e:
        rprint(f"[bold red]Fatal error: {str(e)}[/bold red]")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()

