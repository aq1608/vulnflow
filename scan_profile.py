#!/usr/bin/env python3
"""
VulnFlow Enhanced - Security Scanner (No Authorization Checks)
⚠️  WARNING: Use responsibly! Only scan systems you own or have permission to test.
"""

import asyncio
import sys
import os
from datetime import datetime
from typing import Dict, List
import json
from urllib.parse import urlparse

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.enhanced_vuln_scanner import EnhancedVulnerabilityScanner
from scanner.ai.groq_analyzer import GroqAnalyzer


# ==============================================================================
# SCANNING CONFIGURATIONS
# ==============================================================================

SCAN_PROFILES = {
    'quick': {
        'description': 'Quick assessment (5-10 minutes)',
        'config': {
            'mode': 'quick',
            'smart_payloads': True,
            'confidence_threshold': 0.6,
            'max_concurrent_scanners': 8,
            'max_concurrent_targets': 15,
            'requests_per_second': 75,
            'timeout': 20
        }
    },
    
    'standard': {
        'description': 'Standard OWASP scan (20-40 minutes)',
        'config': {
            'mode': 'standard',
            'smart_payloads': True,
            'confidence_threshold': 0.65,
            'max_concurrent_scanners': 6,
            'max_concurrent_targets': 12,
            'requests_per_second': 60,
            'timeout': 25
        }
    },
    
    'comprehensive': {
        'description': 'Full OWASP Top 10 (40-90 minutes)',
        'config': {
            'mode': 'owasp',
            'smart_payloads': True,
            'confidence_threshold': 0.7,
            'max_concurrent_scanners': 5,
            'max_concurrent_targets': 10,
            'requests_per_second': 50,
            'timeout': 30
        }
    },
    
    'production': {
        'description': 'Conservative scan for live sites (60+ minutes)',
        'config': {
            'mode': 'owasp',
            'smart_payloads': True,
            'confidence_threshold': 0.75,
            'max_concurrent_scanners': 3,
            'max_concurrent_targets': 6,
            'requests_per_second': 25,
            'timeout': 35
        }
    }
}


# ==============================================================================
# MAIN SCANNING FUNCTION
# ==============================================================================

async def scan_web_application(
    target_url: str,
    profile: str = 'standard',
    tech_stack: List[str] = None,
    output_dir: str = None
):
    """
    Scan a web application for security vulnerabilities.
    
    Args:
        target_url: The target web application URL
        profile: Scan profile ('quick', 'standard', 'comprehensive', 'production')
        tech_stack: Detected technology stack (e.g., ['PHP', 'MySQL', 'Apache'])
        output_dir: Directory to save results (optional)
    
    Returns:
        List of vulnerabilities found
    """
    
    print(f"\n{'='*70}")
    print(f"  VulnFlow Enhanced - Security Scanner")
    print(f"{'='*70}\n")
    
    # Show warning
    print("⚠️  WARNING: Ensure you have permission to scan this target!")
    print(f"    Target: {target_url}\n")
    
    # Get scan configuration
    if profile not in SCAN_PROFILES:
        print(f"⚠️  Unknown profile '{profile}', using 'standard'")
        profile = 'standard'
    
    scan_info = SCAN_PROFILES[profile]
    config = scan_info['config']
    
    print(f"Scan Profile: {profile}")
    print(f"Description: {scan_info['description']}")
    print(f"Target: {target_url}")
    print(f"AI Mode: {'Enabled' if os.environ.get('GROQ_API_KEY') else 'Disabled (set GROQ_API_KEY to enable)'}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\n{'-'*70}\n")
    
    # Import crawler (from your existing VulnFlow)
    try:
        from crawler.spider import AsyncWebCrawler
    except ImportError:
        print("⚠️  AsyncWebCrawler not found. Using simulated crawler for demo.")
        # For demonstration - in production this would be real crawler
        crawl_results = {
            'urls': [target_url],
            'forms': []
        }
    else:
        # Crawl the target
        print("[Phase 1/4] Crawling target website...")
        crawler = AsyncWebCrawler(
            target_url,
            max_depth=3,
            max_pages=100  # Adjust based on site size
        )
        crawl_results = await crawler.crawl()
        print(f"  ✓ Found {len(crawl_results.get('urls', []))} URLs")
        print(f"  ✓ Found {len(crawl_results.get('forms', []))} forms")
    
    # Initialize scanner
    print(f"\n[Phase 2/4] Initializing vulnerability scanner...")
    scanner = EnhancedVulnerabilityScanner(config)
    print(f"  ✓ Active scanners: {len(scanner.active_scanners)}")
    print(f"  ✓ Parallel workers: {config['max_concurrent_scanners']}")
    
    # Run scan
    print(f"\n[Phase 3/4] Scanning for vulnerabilities...")
    print(f"  (This may take {scan_info['description'].split('(')[1]}")
    
    start_time = datetime.now()
    vulnerabilities = await scanner.scan_async(crawl_results, tech_stack or [])
    elapsed = (datetime.now() - start_time).total_seconds()
    
    # Get metrics
    metrics = scanner.get_metrics()
    
    # Display results
    print(f"\n[Phase 4/4] Generating results...")
    print(f"\n{'='*70}")
    print(f"  SCAN COMPLETE")
    print(f"{'='*70}\n")
    print(f"Scan Time: {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)")
    print(f"Vulnerabilities Found: {len(vulnerabilities)}")
    
    if metrics['ai_enhanced_findings'] > 0:
        print(f"\nAI Enhancements:")
        print(f"  • AI-validated findings: {metrics['ai_enhanced_findings']}")
        print(f"  • False positives filtered: {metrics['false_positives_filtered']}")
        print(f"  • Smart payloads used: {metrics['smart_payloads_used']}")
    
    # Group by severity
    by_severity = {}
    for vuln in vulnerabilities:
        severity = vuln.severity.value
        by_severity.setdefault(severity, []).append(vuln)
    
    print(f"\nFindings by Severity:")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        if severity in by_severity:
            count = len(by_severity[severity])
            print(f"  {severity}: {count}")
    
    # Show critical and high findings
    if any(s in by_severity for s in ['CRITICAL', 'HIGH']):
        print(f"\n{'-'*70}")
        print(f"CRITICAL & HIGH SEVERITY FINDINGS")
        print(f"{'-'*70}\n")
        
        for severity in ['CRITICAL', 'HIGH']:
            if severity in by_severity:
                for i, vuln in enumerate(by_severity[severity], 1):
                    print(f"\n[{severity}] {vuln.vuln_type}")
                    print(f"  URL: {vuln.url}")
                    print(f"  Parameter: {vuln.parameter or 'N/A'}")
                    print(f"  CWE: {vuln.cwe_id}")
                    
                    # Show AI confidence if available
                    if 'Confidence:' in vuln.description:
                        for line in vuln.description.split('\n'):
                            if 'Confidence:' in line:
                                print(f"  {line.strip()}")
                                break
    
    # Save results if output directory specified
    if output_dir:
        await save_results(
            target_url,
            profile,
            vulnerabilities,
            metrics,
            elapsed,
            output_dir,
            tech_stack
        )
    
    return vulnerabilities


async def save_results(
    target_url: str,
    profile: str,
    vulnerabilities: List,
    metrics: Dict,
    elapsed: float,
    output_dir: str,
    tech_stack: List[str]
):
    """Save scan results to files"""
    
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Save JSON results
    json_file = f"{output_dir}/scan_{timestamp}.json"
    results_dict = {
        'target': target_url,
        'profile': profile,
        'scan_time': elapsed,
        'timestamp': datetime.now().isoformat(),
        'metrics': metrics,
        'vulnerabilities': [
            {
                'type': v.vuln_type,
                'severity': v.severity.value,
                'url': v.url,
                'parameter': v.parameter,
                'description': v.description,
                'cwe': v.cwe_id,
                'payload': v.payload,
                'evidence': v.evidence
            }
            for v in vulnerabilities
        ]
    }
    
    with open(json_file, 'w') as f:
        json.dump(results_dict, f, indent=2)
    
    print(f"\n✓ Results saved to: {json_file}")
    
    # Generate AI summary if available
    if os.environ.get('GROQ_API_KEY'):
        print(f"\n[*] Generating AI-powered executive summary...")
        
        analyzer = GroqAnalyzer()
        summary = await analyzer.summarize_scan_results(
            [v.__dict__ for v in vulnerabilities[:20]],  # Limit for API
            tech_stack or [],
            len(vulnerabilities)
        )
        
        summary_file = f"{output_dir}/executive_summary_{timestamp}.md"
        
        # Build full report
        full_report = f"""# Security Assessment Report

**Target:** {target_url}  
**Scan Profile:** {profile}  
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Scan Duration:** {elapsed/60:.1f} minutes  
**Total Findings:** {len(vulnerabilities)}

---

{summary}

---

## Scan Details

- **Technology Stack:** {', '.join(tech_stack) if tech_stack else 'Not detected'}
- **AI Enhanced Findings:** {metrics.get('ai_enhanced_findings', 0)}
- **False Positives Filtered:** {metrics.get('false_positives_filtered', 0)}
- **Confidence Threshold:** {SCAN_PROFILES[profile]['config']['confidence_threshold']}

---

*Generated by VulnFlow Enhanced*
"""
        
        with open(summary_file, 'w') as f:
            f.write(full_report)
        
        print(f"✓ Executive summary saved to: {summary_file}")


# ==============================================================================
# INTERACTIVE MODE
# ==============================================================================

async def interactive_scan():
    """Interactive mode for scanning"""
    
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║     VulnFlow Enhanced - Security Scanner                        ║
║     Professional OWASP Top 10 Vulnerability Assessment           ║
║                                                                  ║
║     ⚠️  Use Responsibly - Only Scan Authorized Targets!         ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
""")
    
    # Get target URL
    print("\n1. Target URL Configuration")
    print("-" * 70)
    target = input("Enter target URL (e.g., http://192.168.1.100/dvwa): ").strip()
    
    if not target:
        print("⚠️  No target provided. Exiting.")
        return
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    # Select scan profile
    print("\n2. Scan Profile Selection")
    print("-" * 70)
    for i, (profile, info) in enumerate(SCAN_PROFILES.items(), 1):
        print(f"  {i}. {profile.upper()}")
        print(f"     {info['description']}")
        print()
    
    profile_choice = input("Select profile (1-4) [default: 2]: ").strip() or "2"
    profile_map = {
        '1': 'quick',
        '2': 'standard',
        '3': 'comprehensive',
        '4': 'production'
    }
    profile = profile_map.get(profile_choice, 'standard')
    
    # Output directory (renumbered from 4 to 3)
    print("\n3. Output Configuration")
    print("-" * 70)
    save_results_choice = input("Save results to file? (y/n) [default: y]: ").strip().lower() or 'y'
    output_dir = None
    if save_results_choice == 'y':
        output_dir = input("Output directory [default: ./scan_results]: ").strip() or './scan_results'
    
    # Confirm and run
    print("\n" + "=" * 70)
    print("SCAN CONFIGURATION SUMMARY")
    print("=" * 70)
    print(f"Target: {target}")
    print(f"Profile: {profile}")
    print(f"Tech Stack: Auto-detect")
    print(f"Output: {output_dir if output_dir else 'Display only'}")
    print(f"AI: {'Enabled' if os.environ.get('GROQ_API_KEY') else 'Disabled'}")
    print("=" * 70)
    
    confirm = input("\nProceed with scan? (y/n): ").strip().lower()
    if confirm != 'y':
        print("Scan cancelled.")
        return
    
    # Run scan with None for tech_stack (will auto-detect)
    await scan_web_application(target, profile, None, output_dir)
    
    print("\n" + "=" * 70)
    print("Scan complete!")
    print("=" * 70)


# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================

async def main():
    """Main entry point"""
    
    # Check if running interactively or with arguments
    if len(sys.argv) > 1:
        # Command-line mode
        import argparse
        
        parser = argparse.ArgumentParser(
            description='VulnFlow Enhanced - Security Scanner'
        )
        parser.add_argument('target', help='Target URL to scan')
        parser.add_argument(
            '--profile', '-p',
            choices=['quick', 'standard', 'comprehensive', 'production'],
            default='standard',
            help='Scan profile'
        )
        parser.add_argument(
            '--output', '-o',
            help='Output directory for results'
        )
        
        args = parser.parse_args()
        
        # Always use None for tech_stack (will auto-detect)
        await scan_web_application(
            args.target,
            args.profile,
            None,  # Auto-detect tech stack
            args.output
        )
    else:
        # Interactive mode
        await interactive_scan()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user.")
    except Exception as e:
        print(f"\n\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()