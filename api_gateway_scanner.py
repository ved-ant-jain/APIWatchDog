#!/usr/bin/env python3
"""
AWS Private API Gateway Misconfiguration Scanner
Scans for private API Gateways that may be publicly accessible due to misconfigured resource policies.
"""

import argparse
import boto3
import json
import sys
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Warning: 'rich' library not found. Install with: pip install rich")

class APIGatewayScanner:
    def __init__(self, access_key: Optional[str] = None, secret_key: Optional[str] = None, 
                 session_token: Optional[str] = None, profile: Optional[str] = None, verbose: bool = False):
        """Initialize the scanner with AWS credentials."""
        self.console = Console() if RICH_AVAILABLE else None
        self.results = []
        self.verbose = verbose
        
        # Setup AWS session
        if profile:
            self.session = boto3.Session(profile_name=profile)
        elif access_key and secret_key:
            self.session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token
            )
        else:
            # Use default credentials
            self.session = boto3.Session()
    
    def get_all_regions(self) -> List[str]:
        """Get all available AWS regions."""
        try:
            ec2 = self.session.client('ec2', region_name='us-east-1')
            regions = ec2.describe_regions()['Regions']
            return [region['RegionName'] for region in regions]
        except Exception as e:
            self._log_error(f"Failed to get regions: {str(e)}")
            return ['us-east-1', 'us-west-1', 'us-west-2', 'eu-west-1', 'eu-central-1']
    
    def parse_regions(self, region_input: str) -> List[str]:
        """Parse region input and return list of regions to scan."""
        if region_input.lower() == 'all':
            return self.get_all_regions()
        else:
            return [r.strip() for r in region_input.split(',')]
    
    def check_api_gateway_policy(self, policy_document: str) -> Dict[str, Any]:
        """Analyze API Gateway resource policy for misconfigurations."""
        try:
            policy = json.loads(policy_document)
            issues = []
            risk_level = "SECURE"
            
            for statement in policy.get('Statement', []):
                effect = statement.get('Effect', '')
                principal = statement.get('Principal', {})
                action = statement.get('Action', [])
                condition = statement.get('Condition', {})
                
                # Check for overly permissive principal
                if isinstance(principal, str) and principal == "*":
                    issues.append("Principal set to '*' (allows any AWS account)")
                    risk_level = "CRITICAL"
                elif isinstance(principal, dict):
                    aws_principals = principal.get('AWS', [])
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    
                    for aws_principal in aws_principals:
                        if aws_principal == "*":
                            issues.append("AWS Principal set to '*' (allows any AWS account)")
                            risk_level = "CRITICAL"
                        elif aws_principal == "arn:aws:iam::*:root":
                            issues.append("Principal allows any AWS account root")
                            risk_level = "HIGH"
                
                # Check for missing conditions on permissive policies
                if effect == "Allow" and not condition and risk_level in ["CRITICAL", "HIGH"]:
                    issues.append("No conditions specified for permissive policy")
                
                # Check for execute-api:Invoke action
                if isinstance(action, list):
                    if "execute-api:Invoke" in action or "*" in action:
                        if not condition:
                            issues.append("execute-api:Invoke allowed without conditions")
                            if risk_level == "SECURE":
                                risk_level = "MEDIUM"
                
            return {
                'risk_level': risk_level,
                'issues': issues,
                'policy': policy
            }
            
        except json.JSONDecodeError:
            return {
                'risk_level': 'ERROR',
                'issues': ['Invalid JSON in policy document'],
                'policy': None
            }
        except Exception as e:
            return {
                'risk_level': 'ERROR',
                'issues': [f'Error analyzing policy: {str(e)}'],
                'policy': None
            }
    
    def scan_region(self, region: str) -> List[Dict[str, Any]]:
        """Scan a specific region for API Gateway misconfigurations."""
        region_results = []
        
        if self.verbose:
            self._log_info(f"Starting scan of region: {region}")
        
        try:
            # Scan API Gateway v1 (REST APIs)
            apigw_client = self.session.client('apigateway', region_name=region)
            
            if self.verbose:
                self._log_info(f"Connected to API Gateway service in {region}")
            
            # Get all REST APIs
            rest_apis = apigw_client.get_rest_apis()
            api_count = len(rest_apis.get('items', []))
            
            if self.verbose:
                self._log_info(f"Found {api_count} REST APIs in {region}")
            
            for i, api in enumerate(rest_apis.get('items', []), 1):
                api_id = api['id']
                api_name = api.get('name', 'Unknown')
                endpoint_config = api.get('endpointConfiguration', {})
                endpoint_types = endpoint_config.get('types', [])
                
                if self.verbose:
                    self._log_info(f"Analyzing API {i}/{api_count}: {api_name} ({api_id}) - Types: {endpoint_types}")
                
                result = {
                    'region': region,
                    'api_id': api_id,
                    'api_name': api_name,
                    'api_type': 'REST API',
                    'endpoint_types': endpoint_types,
                    'status': 'SECURE',
                    'issues': [],
                    'policy_document': None
                }
                
                # Check if it's a private API
                if 'PRIVATE' in endpoint_types:
                    try:
                        # First try to get the resource policy directly
                        try:
                            policy_response = apigw_client.get_rest_api(restApiId=api_id)
                            policy_document = policy_response.get('policy')
                        except Exception as policy_error:
                            if self.verbose:
                                self._log_info(f"Direct policy retrieval failed for {api_id}, trying alternative method: {str(policy_error)}")
                            
                            # Alternative method - some APIs store policy differently
                            try:
                                # Try getting the API details without embed
                                api_details = apigw_client.get_rest_api(restApiId=api_id)
                                policy_document = api_details.get('policy')
                                
                                if not policy_document:
                                    # Check if there's a separate resource policy endpoint
                                    try:
                                        # This might not exist for all APIs, but worth trying
                                        policy_response = apigw_client.get_resource_policy(restApiId=api_id)
                                        policy_document = policy_response.get('policy')
                                    except apigw_client.exceptions.NotFoundException:
                                        if self.verbose:
                                            self._log_info(f"No resource policy found for private API {api_id}")
                                        policy_document = None
                                    except Exception as inner_error:
                                        if self.verbose:
                                            self._log_info(f"Resource policy endpoint not available for {api_id}: {str(inner_error)}")
                                        policy_document = None
                                        
                            except Exception as alt_error:
                                if self.verbose:
                                    self._log_error(f"Alternative policy retrieval failed for {api_id}: {str(alt_error)}")
                                policy_document = None
                        
                        if policy_document:
                            result['policy_document'] = policy_document
                            policy_analysis = self.check_api_gateway_policy(policy_document)
                            result['status'] = policy_analysis['risk_level']
                            result['issues'] = policy_analysis['issues']
                            
                            if self.verbose:
                                self._log_info(f"Policy analysis for {api_id}: {policy_analysis['risk_level']} - {len(policy_analysis['issues'])} issues found")
                        else:
                            result['status'] = 'NO_POLICY'
                            result['issues'] = ['No resource policy found for private API - this may be a security risk']
                            
                            if self.verbose:
                                self._log_warning(f"Private API {api_id} ({api_name}) has no resource policy")
                                
                    except Exception as e:
                        error_msg = str(e)
                        result['status'] = 'ERROR'
                        result['issues'] = [f'Error checking policy: {error_msg}']
                        
                        if self.verbose:
                            self._log_error(f"Failed to analyze private API {api_id} ({api_name}): {error_msg}")
                            # Add more specific error information
                            if "Parameter validation failed" in error_msg:
                                self._log_error(f"This might be due to API Gateway version compatibility or insufficient permissions")
                            elif "AccessDenied" in error_msg:
                                self._log_error(f"Insufficient permissions to read API Gateway policy for {api_id}")
                            elif "NotFound" in error_msg:
                                self._log_error(f"API Gateway {api_id} not found or no longer exists")
                
                region_results.append(result)
            
            # Scan API Gateway v2 (HTTP APIs)
            try:
                apigwv2_client = self.session.client('apigatewayv2', region_name=region)
                http_apis = apigwv2_client.get_apis()
                
                for api in http_apis.get('Items', []):
                    api_id = api['ApiId']
                    api_name = api.get('Name', 'Unknown')
                    protocol_type = api.get('ProtocolType', 'HTTP')
                    
                    result = {
                        'region': region,
                        'api_id': api_id,
                        'api_name': api_name,
                        'api_type': f'{protocol_type} API v2',
                        'endpoint_types': ['REGIONAL'],  # HTTP APIs are regional by default
                        'status': 'SECURE',
                        'issues': [],
                        'policy_document': None
                    }
                    
                    # Note: HTTP APIs don't have the same private/public distinction as REST APIs
                    # They use different authorization mechanisms
                    region_results.append(result)
                    
            except Exception as e:
                self._log_error(f"Error scanning HTTP APIs in {region}: {str(e)}")
                
        except Exception as e:
            self._log_error(f"Error scanning region {region}: {str(e)}")
            region_results.append({
                'region': region,
                'api_id': 'ERROR',
                'api_name': 'ERROR',
                'api_type': 'ERROR',
                'endpoint_types': [],
                'status': 'ERROR',
                'issues': [f'Failed to scan region: {str(e)}'],
                'policy_document': None
            })
        
        return region_results
    
    def scan_regions(self, regions: List[str]) -> List[Dict[str, Any]]:
        """Scan multiple regions concurrently."""
        all_results = []
        
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                task = progress.add_task("Scanning regions...", total=len(regions))
                
                with ThreadPoolExecutor(max_workers=5) as executor:
                    future_to_region = {
                        executor.submit(self.scan_region, region): region 
                        for region in regions
                    }
                    
                    for future in as_completed(future_to_region):
                        region = future_to_region[future]
                        try:
                            results = future.result()
                            all_results.extend(results)
                            progress.update(task, advance=1, description=f"Completed {region}")
                        except Exception as e:
                            self._log_error(f"Error scanning {region}: {str(e)}")
                            progress.update(task, advance=1)
        else:
            for i, region in enumerate(regions):
                print(f"Scanning region {i+1}/{len(regions)}: {region}")
                results = self.scan_region(region)
                all_results.extend(results)
        
        return all_results
    
    def display_results(self, results: List[Dict[str, Any]]):
        """Display scan results in a formatted table."""
        if not results:
            print("No API Gateways found.")
            return
        
        if RICH_AVAILABLE:
            table = Table(title="AWS API Gateway Security Scan Results")
            table.add_column("Region", style="cyan")
            table.add_column("API ID", style="blue")
            table.add_column("Name", style="white")
            table.add_column("Type", style="magenta")
            table.add_column("Endpoint", style="yellow")
            table.add_column("Status", style="bold")
            table.add_column("Issues", style="red")
            
            for result in results:
                status_color = self._get_status_color(result['status'])
                endpoint_types = ', '.join(result['endpoint_types']) if result['endpoint_types'] else 'N/A'
                issues = '; '.join(result['issues'][:2]) if result['issues'] else 'None'
                if len(result['issues']) > 2:
                    issues += f" (+{len(result['issues'])-2} more)"
                
                table.add_row(
                    result['region'],
                    result['api_id'],
                    result['api_name'][:30] + '...' if len(result['api_name']) > 30 else result['api_name'],
                    result['api_type'],
                    endpoint_types,
                    f"[{status_color}]{result['status']}[/{status_color}]",
                    issues[:50] + '...' if len(issues) > 50 else issues
                )
            
            self.console.print(table)
        else:
            # Fallback to simple table
            print("\n" + "="*120)
            print(f"{'Region':<15} {'API ID':<20} {'Name':<25} {'Type':<15} {'Status':<12} {'Issues'}")
            print("="*120)
            
            for result in results:
                endpoint_types = ', '.join(result['endpoint_types']) if result['endpoint_types'] else 'N/A'
                issues = '; '.join(result['issues'][:1]) if result['issues'] else 'None'
                
                print(f"{result['region']:<15} {result['api_id']:<20} {result['api_name'][:24]:<25} "
                      f"{result['api_type']:<15} {result['status']:<12} {issues[:40]}")
    
    def _get_status_color(self, status: str) -> str:
        """Get color for status display."""
        color_map = {
            'SECURE': 'green',
            'MEDIUM': 'yellow',
            'HIGH': 'orange3',
            'CRITICAL': 'red',
            'ERROR': 'red',
            'NO_POLICY': 'yellow'
        }
        return color_map.get(status, 'white')
    
    def export_results(self, results: List[Dict[str, Any]], format_type: str, filename: str):
        """Export results to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format_type.lower() == 'json':
            filename = filename or f"api_gateway_scan_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"Results exported to {filename}")
            
        elif format_type.lower() == 'csv':
            filename = filename or f"api_gateway_scan_{timestamp}.csv"
            with open(filename, 'w', newline='') as f:
                if results:
                    writer = csv.DictWriter(f, fieldnames=results[0].keys())
                    writer.writeheader()
                    for result in results:
                        # Convert lists to strings for CSV
                        csv_result = result.copy()
                        csv_result['endpoint_types'] = ', '.join(result['endpoint_types'])
                        csv_result['issues'] = '; '.join(result['issues'])
                        writer.writerow(csv_result)
            print(f"Results exported to {filename}")
    
    def _log_error(self, message: str):
        """Log error message."""
        if RICH_AVAILABLE:
            self.console.print(f"[red]ERROR: {message}[/red]")
        else:
            print(f"ERROR: {message}")

    def _log_info(self, message: str):
        """Log info message."""
        if self.verbose:
            if RICH_AVAILABLE:
                self.console.print(f"[blue]INFO: {message}[/blue]")
            else:
                print(f"INFO: {message}")

    def _log_warning(self, message: str):
        """Log warning message."""
        if self.verbose:
            if RICH_AVAILABLE:
                self.console.print(f"[yellow]WARNING: {message}[/yellow]")
            else:
                print(f"WARNING: {message}")

    def _log_debug(self, message: str):
        """Log debug message."""
        if self.verbose:
            if RICH_AVAILABLE:
                self.console.print(f"[dim]DEBUG: {message}[/dim]")
            else:
                print(f"DEBUG: {message}")

def main():
    parser = argparse.ArgumentParser(
        description="AWS Private API Gateway Misconfiguration Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python api_gateway_scanner.py --region all
  python api_gateway_scanner.py --region us-east-1
  python api_gateway_scanner.py --region us-east-1,us-west-1
  python api_gateway_scanner.py --region all --access-key ABC --secret-key XYZ
  python api_gateway_scanner.py --region all --profile my-profile
  python api_gateway_scanner.py --region all --export json --output results.json
        """
    )
    
    parser.add_argument('--region', '-r', required=True,
                       help='AWS region(s) to scan. Use "all" for all regions, or comma-separated list')
    parser.add_argument('--access-key', help='AWS Access Key ID')
    parser.add_argument('--secret-key', help='AWS Secret Access Key')
    parser.add_argument('--session-token', help='AWS Session Token (for temporary credentials)')
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--export', choices=['json', 'csv'], help='Export format')
    parser.add_argument('--output', '-o', help='Output filename')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    
    # Validate authentication arguments
    if args.access_key and not args.secret_key:
        print("Error: --secret-key is required when --access-key is provided")
        sys.exit(1)
    
    if args.secret_key and not args.access_key:
        print("Error: --access-key is required when --secret-key is provided")
        sys.exit(1)
    
    try:
        # Initialize scanner
        scanner = APIGatewayScanner(
            access_key=args.access_key,
            secret_key=args.secret_key,
            session_token=args.session_token,
            profile=args.profile,
            verbose=args.verbose
        )
        
        # Parse regions
        regions = scanner.parse_regions(args.region)
        print(f"Scanning {len(regions)} region(s): {', '.join(regions)}")
        
        # Perform scan
        results = scanner.scan_regions(regions)
        
        # Display results
        scanner.display_results(results)
        
        # Show summary
        total_apis = len(results)
        critical_count = len([r for r in results if r['status'] == 'CRITICAL'])
        high_count = len([r for r in results if r['status'] == 'HIGH'])
        medium_count = len([r for r in results if r['status'] == 'MEDIUM'])
        
        print(f"\nScan Summary:")
        print(f"Total APIs found: {total_apis}")
        print(f"Critical issues: {critical_count}")
        print(f"High risk issues: {high_count}")
        print(f"Medium risk issues: {medium_count}")
        
        # Export if requested
        if args.export:
            scanner.export_results(results, args.export, args.output)
        
        # Exit with appropriate code
        if critical_count > 0:
            sys.exit(2)  # Critical issues found
        elif high_count > 0:
            sys.exit(1)  # High risk issues found
        else:
            sys.exit(0)  # No critical issues
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
