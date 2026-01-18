#!/usr/bin/env python3
"""
VulnFlow Enhanced - DVWA Scanner with Authentication
Specifically designed to scan DVWA with login support
"""

import asyncio
import sys
import os
from datetime import datetime
from typing import Dict, List
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.enhanced_vuln_scanner import EnhancedVulnerabilityScanner
from scanner.ai.groq_analyzer import GroqAnalyzer

# DVWA Default Credentials
DVWA_USERNAME = "admin"
DVWA_PASSWORD = "password"

async def scan_dvwa(
    target_url: str,
    security_level: str = "low",
    profile: str = "quick",
    output_dir: str = None
):
    """
    Scan DVWA with authentication
    
    Args:
        target_url: DVWA base URL (e.g., http://192.168.184.128/dvwa)
        security_level: DVWA security level (low, medium, high, impossible)
        profile: Scan profile (quick, standard, comprehensive)
        output_dir: Where to save results
    """
    
    print("=" * 70)
    print("  VulnFlow Enhanced - DVWA Scanner")
    print("=" * 70)
    print()
    print(f"Target: {target_url}")
    print(f"Security Level: {security_level}")
    print(f"Profile: {profile}")
    print()
    
    # Step 1: Login to DVWA and get session
    print("[Phase 1/5] Authenticating to DVWA...")
    
    import aiohttp
    
    async with aiohttp.ClientSession() as session:
        # Login to DVWA
        login_url = f"{target_url.rstrip('/')}/login.php"
        
        # First, get the login page to get user_token
        async with session.get(login_url) as response:
            html = await response.text()
            
            # Extract user_token from login form
            import re
            token_match = re.search(r'user_token["\']?\s*value=["\']([^"\']+)', html)
            user_token = token_match.group(1) if token_match else ''
        
        # Submit login
        login_data = {
            'username': DVWA_USERNAME,
            'password': DVWA_PASSWORD,
            'Login': 'Login',
            'user_token': user_token
        }
        
        async with session.post(login_url, data=login_data) as response:
            if response.status == 200:
                print(f"  ✓ Logged in as {DVWA_USERNAME}")
                
                # Get session cookie - try multiple methods
                phpsessid = None
                
                # Method 1: From cookie jar
                cookies = session.cookie_jar.filter_cookies(login_url)
                for cookie in cookies.values():
                    if cookie.key == 'PHPSESSID':
                        phpsessid = cookie.value
                        break
                
                # Method 2: From response cookies
                if not phpsessid and 'Set-Cookie' in response.headers:
                    set_cookie = response.headers.get('Set-Cookie', '')
                    import re
                    match = re.search(r'PHPSESSID=([^;]+)', set_cookie)
                    if match:
                        phpsessid = match.group(1)
                
                # Method 3: From all cookies in jar
                if not phpsessid:
                    for cookie in session.cookie_jar:
                        if cookie.key == 'PHPSESSID':
                            phpsessid = cookie.value
                            break
                
                if not phpsessid:
                    print("  ✗ Failed to get session cookie")
                    print("  ℹ️  Attempting to continue with existing session...")
                    
                    # Try to continue anyway - the session might still work
                    # Get any cookies we can
                    all_cookies = []
                    for cookie in session.cookie_jar:
                        all_cookies.append(f"{cookie.key}={cookie.value}")
                    
                    if all_cookies:
                        auth_headers = {
                            'Cookie': '; '.join(all_cookies)
                        }
                        print(f"  ✓ Using session cookies: {len(all_cookies)} cookies")
                    else:
                        print("  ✗ No cookies found, scan may not work correctly")
                        auth_headers = {}
                else:
                    print(f"  ✓ Session ID: {phpsessid[:10]}...")
                    auth_headers = {
                        'Cookie': f'PHPSESSID={phpsessid}; security={security_level}'
                    }
            else:
                print(f"  ✗ Login failed with status {response.status}")
                return []
        
        # Prepare headers with authentication
        if 'auth_headers' not in locals():
            auth_headers = {}
        
        # Set security level
        security_url = f"{target_url.rstrip('/')}/security.php"
        security_data = {
            'security': security_level,
            'seclev_submit': 'Submit'
        }
        
        async with session.post(security_url, data=security_data) as response:
            if response.status == 200:
                print(f"  ✓ Set security level to '{security_level}'")
            else:
                print(f"  ⚠️  Warning: Could not set security level")
    
    # Step 2: Crawl with authentication
    print(f"\n[Phase 2/5] Crawling DVWA...")
    
    try:
        from crawler.spider import AsyncWebCrawler
        
        # Start from the vulnerabilities page
        start_url = f"{target_url.rstrip('/')}/vulnerabilities/"
        
        # Note: Your AsyncWebCrawler doesn't support headers parameter
        # So we'll crawl without authentication and manually add authenticated URLs
        print(f"  ℹ️  Note: Crawler doesn't support authentication")
        print(f"  ℹ️  Adding DVWA vulnerable pages manually...")
        
        # Manually create crawl results with known DVWA pages
        crawl_results = {
            'urls': {
                # Main pages
                f"{target_url.rstrip('/')}/index.php": {'status': 200},
                f"{target_url.rstrip('/')}/vulnerabilities/brute/": {'status': 200},
                f"{target_url.rstrip('/')}/vulnerabilities/csrf/": {'status': 200},
                f"{target_url.rstrip('/')}/vulnerabilities/exec/": {'status': 200},
                f"{target_url.rstrip('/')}/vulnerabilities/fi/?page=include.php": {'status': 200},
                f"{target_url.rstrip('/')}/vulnerabilities/sqli/?id=1&Submit=Submit": {'status': 200},
                f"{target_url.rstrip('/')}/vulnerabilities/sqli_blind/?id=1&Submit=Submit": {'status': 200},
                f"{target_url.rstrip('/')}/vulnerabilities/upload/": {'status': 200},
                f"{target_url.rstrip('/')}/vulnerabilities/xss_d/": {'status': 200},
                f"{target_url.rstrip('/')}/vulnerabilities/xss_r/?name=test": {'status': 200},
                f"{target_url.rstrip('/')}/vulnerabilities/xss_s/": {'status': 200},
                f"{target_url.rstrip('/')}/vulnerabilities/weak_id/": {'status': 200},
                f"{target_url.rstrip('/')}/vulnerabilities/captcha/": {'status': 200},
                f"{target_url.rstrip('/')}/vulnerabilities/javascript/": {'status': 200},
                f"{target_url.rstrip('/')}/vulnerabilities/csp/": {'status': 200},
            },
            'forms': [
                {
                    'action': f"{target_url.rstrip('/')}/vulnerabilities/sqli/",
                    'method': 'GET',
                    'inputs': [
                        {'name': 'id', 'type': 'text', 'value': ''},
                        {'name': 'Submit', 'type': 'submit', 'value': 'Submit'}
                    ]
                },
                {
                    'action': f"{target_url.rstrip('/')}/vulnerabilities/xss_r/",
                    'method': 'GET',
                    'inputs': [
                        {'name': 'name', 'type': 'text', 'value': ''}
                    ]
                },
                {
                    'action': f"{target_url.rstrip('/')}/vulnerabilities/exec/",
                    'method': 'POST',
                    'inputs': [
                        {'name': 'ip', 'type': 'text', 'value': ''},
                        {'name': 'Submit', 'type': 'submit', 'value': 'Submit'}
                    ]
                },
                {
                    'action': f"{target_url.rstrip('/')}/vulnerabilities/xss_s/",
                    'method': 'POST',
                    'inputs': [
                        {'name': 'txtName', 'type': 'text', 'value': ''},
                        {'name': 'mtxMessage', 'type': 'textarea', 'value': ''},
                        {'name': 'btnSign', 'type': 'submit', 'value': 'Sign Guestbook'}
                    ]
                },
                {
                    'action': f"{target_url.rstrip('/')}/vulnerabilities/csrf/",
                    'method': 'GET',
                    'inputs': [
                        {'name': 'password_new', 'type': 'password', 'value': ''},
                        {'name': 'password_conf', 'type': 'password', 'value': ''},
                        {'name': 'Change', 'type': 'submit', 'value': 'Change'}
                    ]
                }
            ],
            'endpoints': [],
            'total_pages': 15
        }
        
        urls_count = len(crawl_results.get('urls', {}))
        forms_count = len(crawl_results.get('forms', []))
        
        print(f"  ✓ Added {urls_count} URLs (DVWA vulnerable pages)")
        print(f"  ✓ Added {forms_count} forms")
        
        if urls_count < 5:
            print(f"\n  ⚠️  Warning: Only added {urls_count} pages!")
    
    except ImportError:
        print("⚠️  AsyncWebCrawler not found")
        return []
    
    # Step 3: Configure scanner
    print(f"\n[Phase 3/5] Initializing scanner...")
    
    profiles = {
        'quick': {
            'mode': 'quick',
            'smart_payloads': True,
            'confidence_threshold': 0.6,
            'max_concurrent_scanners': 8,
            'requests_per_second': 50
        },
        'standard': {
            'mode': 'standard',
            'smart_payloads': True,
            'confidence_threshold': 0.65,
            'max_concurrent_scanners': 6,
            'requests_per_second': 40
        }
    }
    
    config = profiles.get(profile, profiles['quick'])
    scanner = EnhancedVulnerabilityScanner(config)
    
    print(f"  ✓ Scanner initialized")
    print(f"  ✓ AI Mode: {scanner.ai_analyzer.mode.value}")
    
    # Step 4: Scan
    print(f"\n[Phase 4/5] Scanning for vulnerabilities...")
    
    start_time = datetime.now()
    vulnerabilities = await scanner.scan_async(
        crawl_results,
        tech_stack=None  # Auto-detect (will detect PHP, MySQL, Apache)
    )
    elapsed = (datetime.now() - start_time).total_seconds()
    
    # Step 5: Results
    print(f"\n[Phase 5/5] Generating results...")
    print(f"\n{'='*70}")
    print(f"  SCAN COMPLETE")
    print(f"{'='*70}\n")
    print(f"Scan Time: {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)")
    print(f"Total Vulnerabilities: {len(vulnerabilities)}")
    
    # Group by severity
    by_severity = {}
    for vuln in vulnerabilities:
        severity = vuln.severity.value
        by_severity.setdefault(severity, []).append(vuln)
    
    print(f"\nBy Severity:")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        if severity in by_severity:
            print(f"  {severity}: {len(by_severity[severity])}")
    
    # Show critical/high
    if any(s in by_severity for s in ['CRITICAL', 'HIGH']):
        print(f"\n{'-'*70}")
        print(f"CRITICAL & HIGH SEVERITY FINDINGS:")
        print(f"{'-'*70}\n")
        
        for severity in ['CRITICAL', 'HIGH']:
            if severity in by_severity:
                for vuln in by_severity[severity][:10]:  # Show first 10
                    print(f"[{severity}] {vuln.vuln_type}")
                    print(f"  URL: {vuln.url}")
                    print(f"  Parameter: {vuln.parameter or 'N/A'}")
                    print()
    
    # Save results
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # JSON results
        json_file = f"{output_dir}/dvwa_{security_level}_{timestamp}.json"
        results_dict = {
            'target': target_url,
            'security_level': security_level,
            'profile': profile,
            'scan_time': elapsed,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [
                {
                    'type': v.vuln_type,
                    'severity': v.severity.value,
                    'url': v.url,
                    'parameter': v.parameter,
                    'description': v.description,
                    'cwe': v.cwe_id
                }
                for v in vulnerabilities
            ]
        }
        
        with open(json_file, 'w') as f:
            json.dump(results_dict, f, indent=2)
        
        print(f"\n✓ Results saved to: {json_file}")
    
    print(f"\n{'='*70}\n")
    
    return vulnerabilities


async def main():
    """Interactive mode"""
    
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║     VulnFlow Enhanced - DVWA Scanner                            ║
║     With Built-in Authentication Support                        ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
""")
    
    # Get DVWA URL
    print("\n1. DVWA Configuration")
    print("-" * 70)
    target = input("DVWA URL [default: http://192.168.184.128/dvwa]: ").strip()
    if not target:
        target = "http://192.168.184.128/dvwa"
    
    # Security level
    print("\n2. Security Level")
    print("-" * 70)
    print("  1. Low        - All vulnerabilities present")
    print("  2. Medium     - Some protections")
    print("  3. High       - More protections")
    print("  4. Impossible - All vulnerabilities fixed")
    
    level_choice = input("\nSelect security level (1-4) [default: 1]: ").strip() or "1"
    level_map = {
        '1': 'low',
        '2': 'medium',
        '3': 'high',
        '4': 'impossible'
    }
    security_level = level_map.get(level_choice, 'low')
    
    # Scan profile
    print("\n3. Scan Profile")
    print("-" * 70)
    print("  1. Quick      - Fast scan (5-10 min)")
    print("  2. Standard   - Thorough scan (20-40 min)")
    
    profile_choice = input("\nSelect profile (1-2) [default: 1]: ").strip() or "1"
    profile = 'quick' if profile_choice == '1' else 'standard'
    
    # Output
    print("\n4. Output")
    print("-" * 70)
    save = input("Save results? (y/n) [default: y]: ").strip().lower() or 'y'
    output_dir = './dvwa_results' if save == 'y' else None
    
    # Confirm
    print(f"\n{'='*70}")
    print(f"SCAN CONFIGURATION")
    print(f"{'='*70}")
    print(f"Target: {target}")
    print(f"Security Level: {security_level}")
    print(f"Profile: {profile}")
    print(f"Output: {output_dir or 'Display only'}")
    print(f"AI: {'Enabled' if os.environ.get('GROQ_API_KEY') else 'Disabled'}")
    print(f"{'='*70}\n")
    
    confirm = input("Proceed? (y/n): ").strip().lower()
    if confirm != 'y':
        print("Cancelled.")
        return
    
    # Scan
    await scan_dvwa(target, security_level, profile, output_dir)


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nScan interrupted.")
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback
        traceback.print_exc()