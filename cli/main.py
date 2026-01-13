# websec/cli/main.py
import click
import asyncio
import sys
import json
from datetime import datetime
import time
from typing import Callable

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.panel import Panel
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Import from project modules
from crawler.spider import AsyncWebCrawler
from scanner.vuln_scanner import VulnerabilityScanner
from detector.tech_fingerprint import TechnologyDetector
from remediation.engine import RemediationEngine
from reports.generator import ReportGenerator

if RICH_AVAILABLE:
    console = Console()


def print_banner():
    """Print VulnFlow banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗██╗      ██████╗ ██╗    ██╗  ║
║  ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██║     ██╔═══██╗██║    ██║  ║
║  ██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██║     ██║   ██║██║ █╗ ██║  ║
║  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██║     ██║   ██║██║███╗██║  ║
║   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║     ███████╗╚██████╔╝╚███╔███╔╝  ║
║    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝   ║
║                                                                           ║
║                   Web Vulnerability Scanner v1.0.3                        ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
    """
    if RICH_AVAILABLE:
        console.print(banner, style="bold blue")
    else:
        print(banner)


async def run_full_scan(target_url: str, depth: int, max_pages: int, 
                        verbose: bool = False) -> dict:
    """Run a complete scan against the target"""
    results = {
        "target": target_url,
        "scan_time": datetime.now().isoformat(),
        "vulnerabilities": [],
        "tech_stack": {},
        "remediations": {},
        "pages_scanned": 0,
        "forms_tested": 0
    }
    
    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Scanning...", total=100)
            
            # Phase 1: Crawl
            progress.update(task, completed=10, description="[cyan]Crawling website...")
            crawler = AsyncWebCrawler(target_url, depth, max_pages)
            crawl_results = await crawler.crawl()
            results["pages_scanned"] = len(crawl_results.get("urls", {}))
            results["forms_tested"] = len(crawl_results.get("forms", []))
            
            if verbose:
                console.print(f"  [green]✓[/green] Found {results['pages_scanned']} URLs")
                console.print(f"  [green]✓[/green] Found {results['forms_tested']} forms")
            
            # Phase 2: Detect technology
            progress.update(task, completed=30, description="[cyan]Detecting technologies...")
            detector = TechnologyDetector()
            results["tech_stack"] = detector.detect_from_crawl_results(crawl_results)
            
            if verbose and results["tech_stack"]:
                console.print(f"  [green]✓[/green] Detected: {', '.join(results['tech_stack'].keys())}")
            
            # Phase 3: Scan for vulnerabilities
            progress.update(task, completed=50, description="[cyan]Scanning for vulnerabilities...")
            scanner = VulnerabilityScanner()
            results["vulnerabilities"] = await scanner.scan_target(crawl_results)
            
            if verbose:
                console.print(f"  [green]✓[/green] Found {len(results['vulnerabilities'])} vulnerabilities")
            
            # Phase 4: Generate remediations
            progress.update(task, completed=80, description="[cyan]Generating remediation advice...")
            remediation_engine = RemediationEngine()
            for vuln in results["vulnerabilities"]:
                advice = remediation_engine.get_remediation(vuln.vuln_type, results["tech_stack"])
                if advice:
                    results["remediations"][vuln.vuln_type] = advice
            
            progress.update(task, completed=100, description="[green]Scan complete!")
    else:
        # Fallback without rich
        print("[*] Phase 1: Crawling website...")
        crawler = AsyncWebCrawler(target_url, depth, max_pages)
        crawl_results = await crawler.crawl()
        results["pages_scanned"] = len(crawl_results.get("urls", {}))
        results["forms_tested"] = len(crawl_results.get("forms", []))
        print(f"    Found {results['pages_scanned']} URLs, {results['forms_tested']} forms")
        
        print("[*] Phase 2: Detecting technologies...")
        detector = TechnologyDetector()
        results["tech_stack"] = detector.detect_from_crawl_results(crawl_results)
        
        print("[*] Phase 3: Scanning for vulnerabilities...")
        scanner = VulnerabilityScanner()
        results["vulnerabilities"] = await scanner.scan_target(crawl_results)
        print(f"    Found {len(results['vulnerabilities'])} vulnerabilities")
        
        print("[*] Phase 4: Generating remediation advice...")
        remediation_engine = RemediationEngine()
        for vuln in results["vulnerabilities"]:
            advice = remediation_engine.get_remediation(vuln.vuln_type, results["tech_stack"])
            if advice:
                results["remediations"][vuln.vuln_type] = advice
        
        print("[+] Scan complete!")
    
    return results


def display_results(results: dict, show_remediation: bool = False):
    """Display scan results"""
    vulns = results.get("vulnerabilities", [])
    
    if RICH_AVAILABLE:
        # Summary panel
        summary_text = f"""
[bold]Target:[/bold] {results['target']}
[bold]Scan Time:[/bold] {results['scan_time']}
[bold]Pages Scanned:[/bold] {results['pages_scanned']}
[bold]Forms Tested:[/bold] {results['forms_tested']}
[bold]Total Vulnerabilities:[/bold] {len(vulns)}
        """
        console.print(Panel(summary_text, title="📊 Scan Summary", border_style="blue"))
        
        # Severity breakdown
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in vulns:
            sev = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        severity_table = Table(title="Severity Breakdown")
        severity_table.add_column("Severity", style="bold")
        severity_table.add_column("Count", justify="center")
        
        severity_colors = {
            "critical": "red",
            "high": "orange1",
            "medium": "yellow",
            "low": "blue",
            "info": "dim"
        }
        
        for sev, count in severity_counts.items():
            if count > 0:
                color = severity_colors.get(sev, "white")
                severity_table.add_row(f"[{color}]{sev.upper()}[/{color}]", str(count))
        
        console.print(severity_table)
        console.print()
        
        # Tech stack
        if results.get("tech_stack"):
            tech_table = Table(title="🔧 Detected Technologies")
            tech_table.add_column("Technology")
            tech_table.add_column("Category")
            tech_table.add_column("Confidence")
            
            for tech, info in results["tech_stack"].items():
                confidence = f"{info['confidence']*100:.0f}%"
                tech_table.add_row(tech, info['category'], confidence)
            
            console.print(tech_table)
            console.print()
        
        # Vulnerabilities table
        if vulns:
            vuln_table = Table(title="🔴 Vulnerabilities Found")
            vuln_table.add_column("#", style="dim", width=4)
            vuln_table.add_column("Type", style="cyan")
            vuln_table.add_column("Severity")
            vuln_table.add_column("URL", max_width=40)
            vuln_table.add_column("Parameter")
            
            for i, vuln in enumerate(vulns, 1):
                sev = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
                color = severity_colors.get(sev, "white")
                
                url_display = vuln.url[:40] + "..." if len(vuln.url) > 40 else vuln.url
                
                vuln_table.add_row(
                    str(i),
                    vuln.vuln_type,
                    f"[{color}]{sev.upper()}[/{color}]",
                    url_display,
                    vuln.parameter or "N/A"
                )
            
            console.print(vuln_table)
            
            # Detailed findings
            console.print("\n[bold]📋 Detailed Findings:[/bold]\n")
            
            for i, vuln in enumerate(vulns, 1):
                sev = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
                color = severity_colors.get(sev, "white")
                
                console.print(f"[bold]#{i} {vuln.vuln_type}[/bold]")
                console.print(f"   Severity: [{color}]{sev.upper()}[/{color}]")
                console.print(f"   URL: {vuln.url}")
                if vuln.parameter:
                    console.print(f"   Parameter: {vuln.parameter}")
                if vuln.payload:
                    console.print(f"   Payload: {vuln.payload[:60]}...")
                console.print(f"   Evidence: {vuln.evidence[:80]}...")
                if vuln.cwe_id:
                    console.print(f"   CWE: {vuln.cwe_id}")
                console.print(f"   Description: {vuln.description}")
                
                # Show remediation if requested
                if show_remediation and vuln.vuln_type in results.get("remediations", {}):
                    console.print(f"\n   [green]💡 Remediation:[/green]")
                    for advice in results["remediations"][vuln.vuln_type]:
                        console.print(f"      Framework: {advice.framework}")
                        console.print(f"      {advice.description}")
                
                console.print()
        else:
            console.print(Panel(
                "[green]✅ No vulnerabilities found![/green]\n\nGreat job! The scan did not detect any security issues.",
                title="Results",
                border_style="green"
            ))
    else:
        # Fallback without rich
        print("\n" + "="*60)
        print("SCAN RESULTS")
        print("="*60)
        print(f"Target: {results['target']}")
        print(f"Scan Time: {results['scan_time']}")
        print(f"Pages Scanned: {results['pages_scanned']}")
        print(f"Forms Tested: {results['forms_tested']}")
        print(f"Vulnerabilities: {len(vulns)}")
        print("-"*60)
        
        if vulns:
            for i, vuln in enumerate(vulns, 1):
                sev = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
                print(f"\n[{i}] {vuln.vuln_type}")
                print(f"    Severity: {sev.upper()}")
                print(f"    URL: {vuln.url}")
                if vuln.parameter:
                    print(f"    Parameter: {vuln.parameter}")
                print(f"    Description: {vuln.description}")
        else:
            print("\n[+] No vulnerabilities found!")
        
        print("="*60)


def determine_exit_code(results: dict, fail_on: str) -> int:
    """Determine CLI exit code based on findings and threshold"""
    vulns = results.get("vulnerabilities", [])
    
    if not vulns:
        return 0
    
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for vuln in vulns:
        sev = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    if fail_on == "critical" and severity_counts["critical"] > 0:
        return 2
    elif fail_on == "high" and (severity_counts["critical"] > 0 or severity_counts["high"] > 0):
        return 1
    elif fail_on == "medium" and (severity_counts["critical"] > 0 or 
                                   severity_counts["high"] > 0 or 
                                   severity_counts["medium"] > 0):
        return 1
    elif fail_on == "any" and len(vulns) > 0:
        return 1
    
    return 0


@click.group()
@click.version_option(version="1.0.3")
def cli():
    """VulnFlow - Web Vulnerability Scanner with Contextual Remediation"""
    pass

@cli.command()
@click.argument('target_url')
@click.option('--depth', '-d', default=2, help='Maximum crawl depth (default: 2)')
@click.option('--max-pages', '-m', default=50, help='Maximum pages to crawl (default: 50)')
@click.option('--output', '-o', default=None, help='Output file path')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['json', 'html', 'sarif']),
              default='json', help='Report format')
@click.option('--fail-on',
              type=click.Choice(['critical', 'high', 'medium', 'any', 'none']),
              default='none', help='Exit with error if severity found')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--remediation', '-r', is_flag=True, help='Show remediation advice')
@click.option('--quick', '-q', is_flag=True, help='Quick scan (fewer payloads, faster)')
@click.option('--thorough', '-t', is_flag=True, help='Thorough scan (more payloads, slower)')
@click.option('--concurrency', '-c', default=20, help='Max concurrent requests (default: 20)')
@click.option('--timeout', default=10, help='Request timeout in seconds (default: 10)')
def scan(target_url, depth, max_pages, output, output_format, fail_on, 
         verbose, remediation, quick, thorough, concurrency, timeout):
    """Scan a target URL for vulnerabilities
    
    Examples:
    
        vulnflow scan http://example.com
        
        vulnflow scan http://example.com --quick  # Fast scan
        
        vulnflow scan http://example.com --thorough  # Deep scan
        
        vulnflow scan http://example.com -c 50  # High concurrency
    """
    print_banner()
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    # Configure scan
    from scanner.fast_scanner import ScanConfig
    
    config = ScanConfig(
        max_concurrent_requests=concurrency,
        request_timeout=timeout,
        quick_mode=quick,
        smart_scan=not thorough,
        max_payloads_per_param=5 if quick else (50 if thorough else 15),
    )
    
    if RICH_AVAILABLE:
        console.print(f"\n[bold]Target:[/bold] {target_url}")
        console.print(f"[bold]Mode:[/bold] {'Quick' if quick else 'Thorough' if thorough else 'Normal'}")
        console.print(f"[bold]Concurrency:[/bold] {concurrency} | [bold]Timeout:[/bold] {timeout}s\n")
    else:
        print(f"\nTarget: {target_url}")
        print(f"Mode: {'Quick' if quick else 'Thorough' if thorough else 'Normal'}")
        print(f"Concurrency: {concurrency} | Timeout: {timeout}s\n")
    
    # Run scan with progress
    try:
        start_time = time.time()
        results = asyncio.run(run_fast_scan(
            target_url, depth, max_pages, config, verbose
        ))
        elapsed = time.time() - start_time
        
        if RICH_AVAILABLE:
            console.print(f"\n[green]Scan completed in {elapsed:.1f} seconds[/green]")
        else:
            print(f"\nScan completed in {elapsed:.1f} seconds")
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Error during scan: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    
    # Display and save results
    display_results(results, show_remediation=remediation)
    
    if output:
        generator = ReportGenerator()
        
        if output_format == 'html':
            report_content = generator.generate_html_report(results)
        elif output_format == 'sarif':
            report_content = generator.generate_sarif_report(results)
        else:
            report_content = generator.generate_json_report(results)
        
        with open(output, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        if RICH_AVAILABLE:
            console.print(f"\n[green]📄 Report saved to:[/green] {output}")
        else:
            print(f"\nReport saved to: {output}")
    
    # Exit code
    if fail_on != 'none':
        exit_code = determine_exit_code(results, fail_on)
        sys.exit(exit_code)


async def run_fast_scan(target_url: str, depth: int, max_pages: int,
                        config, verbose: bool = False) -> dict:
    """Run optimized fast scan"""
    from crawler.spider import AsyncWebCrawler
    from scanner.fast_scanner import FastVulnerabilityScanner
    from detector.tech_fingerprint import TechnologyDetector
    from remediation.engine import RemediationEngine
    
    results = {
        "target": target_url,
        "scan_time": datetime.now().isoformat(),
        "vulnerabilities": [],
        "tech_stack": {},
        "remediations": {},
        "pages_scanned": 0,
        "forms_tested": 0,
        "stats": {}
    }
    
    # Progress callback
    def progress_callback(current, total, message):
        if RICH_AVAILABLE and verbose:
            console.print(f"  [dim]{message}[/dim]")
        elif verbose:
            print(f"  {message}")
    
    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            # Phase 1: Crawl
            task = progress.add_task("[cyan]Crawling...", total=100)
            progress.update(task, completed=10)
            
            crawler = AsyncWebCrawler(target_url, depth, max_pages)
            crawl_results = await crawler.crawl()
            results["pages_scanned"] = len(crawl_results.get("urls", {}))
            results["forms_tested"] = len(crawl_results.get("forms", []))
            
            progress.update(task, completed=20, description=f"[cyan]Found {results['pages_scanned']} URLs, {results['forms_tested']} forms")
            
            # Phase 2: Detect tech
            progress.update(task, completed=25, description="[cyan]Detecting technologies...")
            detector = TechnologyDetector()
            results["tech_stack"] = detector.detect_from_crawl_results(crawl_results)
            
            # Phase 3: Fast vulnerability scan
            progress.update(task, completed=30, description="[cyan]Scanning for vulnerabilities...")
            
            scanner = FastVulnerabilityScanner(config)
            
            def scan_progress(current, total, msg):
                pct = 30 + int((current / max(total, 1)) * 60)
                progress.update(task, completed=pct, description=f"[cyan]{msg}")
            
            results["vulnerabilities"] = await scanner.scan_target(crawl_results, scan_progress)
            results["stats"] = scanner.get_stats()
            
            # Phase 4: Remediation
            progress.update(task, completed=95, description="[cyan]Generating remediation...")
            remediation_engine = RemediationEngine()
            for vuln in results["vulnerabilities"]:
                advice = remediation_engine.get_remediation(vuln.vuln_type, results["tech_stack"])
                if advice:
                    results["remediations"][vuln.vuln_type] = advice
            
            progress.update(task, completed=100, description="[green]Complete!")
    else:
        # Fallback without rich
        print("[*] Phase 1: Crawling...")
        crawler = AsyncWebCrawler(target_url, depth, max_pages)
        crawl_results = await crawler.crawl()
        results["pages_scanned"] = len(crawl_results.get("urls", {}))
        results["forms_tested"] = len(crawl_results.get("forms", []))
        print(f"    Found {results['pages_scanned']} URLs, {results['forms_tested']} forms")
        
        print("[*] Phase 2: Detecting technologies...")
        detector = TechnologyDetector()
        results["tech_stack"] = detector.detect_from_crawl_results(crawl_results)
        
        print("[*] Phase 3: Scanning (this may take a while)...")
        scanner = FastVulnerabilityScanner(config)
        results["vulnerabilities"] = await scanner.scan_target(crawl_results, progress_callback)
        results["stats"] = scanner.get_stats()
        
        print("[*] Phase 4: Generating remediation...")
        remediation_engine = RemediationEngine()
        for vuln in results["vulnerabilities"]:
            advice = remediation_engine.get_remediation(vuln.vuln_type, results["tech_stack"])
            if advice:
                results["remediations"][vuln.vuln_type] = advice
        
        print("[+] Complete!")
    
    return results

@cli.command()
@click.option('--host', '-h', default='0.0.0.0', help='Host to bind (default: 0.0.0.0)')
@click.option('--port', '-p', default=8000, help='Port to bind (default: 8000)')
def server(host, port):
    """Start the VulnFlow API server
    
    Example:
    
        vulnflow server --port 8080
    """
    print_banner()
    
    try:
        import uvicorn
        if RICH_AVAILABLE:
            console.print(f"\n[green]Starting VulnFlow API server on {host}:{port}[/green]")
            console.print(f"[dim]API docs available at: http://{host}:{port}/docs[/dim]\n")
        else:
            print(f"\nStarting VulnFlow API server on {host}:{port}")
            print(f"API docs available at: http://{host}:{port}/docs\n")
        
        uvicorn.run("websec.api.main:app", host=host, port=port, reload=True)
    except ImportError:
        print("Error: uvicorn is required to run the API server")
        print("Install with: pip install uvicorn")
        sys.exit(1)


@cli.command()
def version():
    """Show version information"""
    print_banner()
    if RICH_AVAILABLE:
        console.print("\n[bold]VulnFlow[/bold] version 1.0.3")
        console.print("[dim]Web Vulnerability Scanner with Contextual Remediation[/dim]")
    else:
        print("\nVulnFlow version 1.0.3")
        print("Web Vulnerability Scanner with Contextual Remediation")


def main():
    """Main entry point"""
    cli()


if __name__ == "__main__":
    main()