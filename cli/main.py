# cli/main.py - AI-INTEGRATED with RICH PROGRESS
"""
VulnFlow CLI with Full AI Integration + Rich Terminal Output
"""

import click
import asyncio
import sys
import json
import os
from datetime import datetime
from typing import Optional
import time

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
    from rich.panel import Panel
    from rich.live import Live
    from rich.layout import Layout
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Import from project modules
from crawler.spider import AsyncWebCrawler
from scanner.enhanced_vuln_scanner import EnhancedVulnerabilityScanner
from detector.tech_fingerprint import TechnologyDetector
from remediation.engine import RemediationEngine
from reports.generator import ReportGenerator

if RICH_AVAILABLE:
    console = Console()


class ScanTimer:
    """Timer class to track scan duration and phase timings"""
    
    def __init__(self):
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.phase_times: dict = {}
        self._current_phase: Optional[str] = None
        self._phase_start: Optional[float] = None
    
    def start(self):
        self.start_time = time.perf_counter()
        self.phase_times = {}
        return self
    
    def stop(self):
        self.end_time = time.perf_counter()
        if self._current_phase:
            self.end_phase()
        return self
    
    def start_phase(self, phase_name: str):
        if self._current_phase:
            self.end_phase()
        self._current_phase = phase_name
        self._phase_start = time.perf_counter()
        return self
    
    def end_phase(self):
        if self._current_phase and self._phase_start:
            elapsed = time.perf_counter() - self._phase_start
            self.phase_times[self._current_phase] = elapsed
            self._current_phase = None
            self._phase_start = None
        return self
    
    @property
    def total_duration(self) -> float:
        if self.start_time is None:
            return 0.0
        end = self.end_time or time.perf_counter()
        return end - self.start_time
    
    @property
    def total_duration_formatted(self) -> str:
        return self.format_duration(self.total_duration)
    
    @staticmethod
    def format_duration(seconds: float) -> str:
        if seconds < 1:
            return f"{seconds * 1000:.0f}ms"
        elif seconds < 60:
            return f"{seconds:.2f}s"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            secs = seconds % 60
            return f"{minutes}m {secs:.1f}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            secs = seconds % 60
            return f"{hours}h {minutes}m {secs:.0f}s"
    
    def get_phase_duration(self, phase_name: str) -> float:
        return self.phase_times.get(phase_name, 0.0)
    
    def get_summary(self) -> dict:
        return {
            "total_duration": self.total_duration,
            "total_duration_formatted": self.total_duration_formatted,
            "phases": {
                name: {
                    "duration": duration,
                    "duration_formatted": self.format_duration(duration)
                }
                for name, duration in self.phase_times.items()
            }
        }


def display_results(results: dict, show_remediation: bool = False, show_stats: bool = False):
    """Display scan results"""
    vulns = results.get("vulnerabilities", [])
    
    if RICH_AVAILABLE:
        if not vulns:
            console.print("\n[green]✓ No vulnerabilities found![/green]")
            return
        
        console.print(f"\n[red]⚠️  Found {len(vulns)} vulnerabilities[/red]\n")
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in vulns:
            sev = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        summary_table = Table(title="Vulnerability Summary")
        summary_table.add_column("Severity", style="bold")
        summary_table.add_column("Count", justify="right")
        
        if severity_counts["critical"] > 0:
            summary_table.add_row("Critical", str(severity_counts["critical"]), style="bold red")
        if severity_counts["high"] > 0:
            summary_table.add_row("High", str(severity_counts["high"]), style="red")
        if severity_counts["medium"] > 0:
            summary_table.add_row("Medium", str(severity_counts["medium"]), style="yellow")
        if severity_counts["low"] > 0:
            summary_table.add_row("Low", str(severity_counts["low"]), style="cyan")
        if severity_counts["info"] > 0:
            summary_table.add_row("Info", str(severity_counts["info"]), style="dim")
        
        console.print(summary_table)
        console.print("\n[bold]Detailed Findings:[/bold]\n")
        
        for i, vuln in enumerate(vulns, 1):
            severity_style = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "cyan",
                "info": "dim"
            }
            sev = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
            style = severity_style.get(sev, "white")
            
            console.print(f"[{style}]{i}. [{sev.upper()}] {vuln.vuln_type}[/{style}]")
            console.print(f"   URL: {vuln.url}")
            if vuln.parameter:
                console.print(f"   Parameter: {vuln.parameter}")
            if show_remediation and hasattr(vuln, 'remediation') and vuln.remediation:
                console.print(f"   [dim]Remediation: {vuln.remediation}[/dim]")
            console.print()
        
        if show_stats and "scan_stats" in results:
            stats = results["scan_stats"]
            console.print("\n[bold cyan]Execution Statistics:[/bold cyan]")
            console.print(f"  • AI Enhanced: {stats.get('ai_enhanced_findings', 0)}")
            console.print(f"  • False Positives Filtered: {stats.get('false_positives_filtered', 0)}")
    
    else:
        if not vulns:
            print("\n✓ No vulnerabilities found!")
            return
        
        print(f"\n⚠️  Found {len(vulns)} vulnerabilities\n")
        print("="*60)
        
        for i, vuln in enumerate(vulns, 1):
            sev = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
            print(f"{i}. [{sev.upper()}] {vuln.vuln_type}")
            print(f"   URL: {vuln.url}")
            if vuln.parameter:
                print(f"   Parameter: {vuln.parameter}")
            if show_remediation and hasattr(vuln, 'remediation') and vuln.remediation:
                print(f"   Remediation: {vuln.remediation}")
            print()
        
        print("="*60)


def determine_exit_code(results: dict, fail_on: str) -> int:
    """Determine CLI exit code based on findings"""
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
@click.version_option(version="2.0.0")
def cli():
    """VulnFlow - AI-Enhanced Web Vulnerability Scanner
    
    Features:
    - AI-powered vulnerability analysis with Groq LLM
    - Smart payload generation based on tech stack
    - False positive reduction with confidence scoring
    - Context-aware remediation advice
    - Parallel scanning for faster results
    
    Set GROQ_API_KEY environment variable to enable AI features.
    """
    pass


@cli.command()
@click.argument('target_url')
@click.option('--depth', '-d', default=2, help='Maximum crawl depth (default: 2)')
@click.option('--max-pages', '-m', default=50, help='Maximum pages to crawl (default: 50)')
@click.option('--output', '-o', default=None, help='Output file path')
@click.option('--format', '-f', 'output_format', 
              type=click.Choice(['json', 'html', 'sarif']), 
              default='json', help='Report format (default: json)')
@click.option('--fail-on', 
              type=click.Choice(['critical', 'high', 'medium', 'any', 'none']),
              default='critical', help='Severity threshold for non-zero exit (default: critical)')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--remediation', '-r', is_flag=True, help='Show remediation advice')
# AI-specific options
@click.option('--ai-enabled/--no-ai', default=True, help='Enable/disable AI analysis (default: auto-detect)')
@click.option('--api-key', default=None, help='Groq API key (overrides GROQ_API_KEY env var)')
@click.option('--smart-payloads/--no-smart-payloads', default=True, help='Use AI-generated payloads (default: enabled)')
@click.option('--confidence-threshold', default=0.6, type=float, help='Minimum confidence score (0.0-1.0, default: 0.6)')
# Scan mode options
@click.option('--mode', type=click.Choice(['quick', 'standard', 'owasp', 'full']), 
              default='standard', help='Scan mode (default: standard)')
# Performance options
@click.option('--workers', '-w', default=8, help='Number of concurrent workers (default: 8)')
@click.option('--concurrent-targets', '-c', default=15, help='Concurrent targets (default: 15)')
@click.option('--rate-limit', default=75.0, help='Max requests per second (default: 75)')
@click.option('--timeout', '-t', default=20.0, help='Timeout per scan in seconds (default: 20)')
# Display options
@click.option('--stats', is_flag=True, help='Show execution statistics')
@click.option('--timing', is_flag=True, help='Show detailed timing breakdown')
@click.option('--no-timing', is_flag=True, help='Hide timing information')
def scan(target_url, depth, max_pages, output, output_format, fail_on, verbose, 
         remediation, ai_enabled, api_key, smart_payloads, confidence_threshold,
         mode, workers, concurrent_targets, rate_limit, timeout, 
         stats, timing, no_timing):
    """Scan a target URL for vulnerabilities with AI-powered analysis"""
    
    # Display banner
    if RICH_AVAILABLE:
        banner = """
[bold cyan]
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗██╗      ██████╗ ██╗    ║
║  ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██║     ██╔═══██╗██║    ║
║  ██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██║     ██║   ██║██║    ║
║  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██║     ██║   ██║██║    ║
║   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║     ███████╗╚██████╔╝██║    ║
║    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝    ║
║                                                                      ║
║            AI-Enhanced Web Vulnerability Scanner v2.0              ║
║                  Powered by Groq LLM (Llama 3.3 70B)                ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
[/bold cyan]"""
        console.print(banner)
    else:
        print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗██╗      ██████╗ ██╗    ║
║  ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██║     ██╔═══██╗██║    ║
║  ██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██║     ██║   ██║██║    ║
║  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██║     ██║   ██║██║    ║
║   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║     ███████╗╚██████╔╝██║    ║
║    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝    ║
║                                                                      ║
║            AI-Enhanced Web Vulnerability Scanner v2.0              ║
║                  Powered by Groq LLM (Llama 3.3 70B)                ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
""")
    
    # Start timer
    scan_timer = ScanTimer().start()
    
    # Check AI availability
    has_api_key = api_key or os.environ.get("GROQ_API_KEY")
    ai_mode = ai_enabled and has_api_key
    
    # Display scan configuration
    if RICH_AVAILABLE:
        config_table = Table(show_header=False, box=None, padding=(0, 1))
        config_table.add_column("Setting", style="cyan")
        config_table.add_column("Value", style="white")
        
        config_table.add_row("Target URL", target_url)
        config_table.add_row("Scan Mode", mode.upper())
        config_table.add_row("AI Mode", "✓ ENABLED" if ai_mode else "✗ DISABLED")
        if ai_mode:
            config_table.add_row("Confidence Threshold", f"{confidence_threshold:.1%}")
        config_table.add_row("Max Depth", str(depth))
        config_table.add_row("Max Pages", str(max_pages))
        config_table.add_row("Workers", str(workers))
        
        console.print(config_table)
        console.print()
    else:
        print(f"Target URL: {target_url}")
        print(f"Scan Mode: {mode.upper()}")
        print(f"AI Mode: {'ENABLED' if ai_mode else 'DISABLED'}")
        if ai_mode:
            print(f"Confidence Threshold: {confidence_threshold:.1%}")
        print(f"Max Depth: {depth}")
        print(f"Max Pages: {max_pages}")
        print(f"Workers: {workers}")
        print()
    
    if verbose:
        if RICH_AVAILABLE:
            if ai_mode:
                console.print("[green]✓ AI-powered analysis enabled[/green] - Using Groq LLM (Llama 3.3 70B)")
            else:
                console.print("[yellow]⚠ AI-powered analysis disabled[/yellow] - Set GROQ_API_KEY to enable")
            console.print()
        else:
            if ai_mode:
                print("✓ AI-powered analysis enabled - Using Groq LLM (Llama 3.3 70B)")
            else:
                print("⚠ AI-powered analysis disabled - Set GROQ_API_KEY to enable")
            print()
    
    # Build scan configuration
    scan_config = {
        'api_key': api_key,
        'smart_payloads': smart_payloads,
        'confidence_threshold': confidence_threshold,
        'mode': mode,
        'scan_depth': 'normal',
        'parallel': True,
        'max_concurrent_scanners': workers,
        'max_concurrent_targets': concurrent_targets,
        'requests_per_second': rate_limit,
        'timeout': timeout,
    }
    
    # Initialize results
    results = {
        "target_url": target_url,
        "scan_date": datetime.now().isoformat(),
        "ai_enabled": ai_mode,
        "scan_mode": mode,
        "confidence_threshold": confidence_threshold,
        "pages_scanned": 0,
        "forms_tested": 0,
        "tech_stack": [],
        "vulnerabilities": [],
        "remediations": {},
        "scan_stats": {}
    }
    
    # Create async wrapper with Rich progress
    async def run_scan_with_progress(progress, task):
        """Async wrapper with Rich progress updates"""
        # Phase 1: Crawling
        scan_timer.start_phase("Crawling")
        progress.update(task, description="[cyan]Phase 1: Crawling website...")
        
        crawler = AsyncWebCrawler(target_url, depth, max_pages)
        crawl_results = await crawler.crawl()
        results["pages_scanned"] = len(crawl_results.get("urls", {}))
        results["forms_tested"] = len(crawl_results.get("forms", []))
        scan_timer.end_phase()
        
        progress.update(task, description=f"[green]✓ Crawled {results['pages_scanned']} pages, {results['forms_tested']} forms")
        
        # Phase 2: Technology Detection
        scan_timer.start_phase("Technology Detection")
        progress.update(task, description="[cyan]Phase 2: Detecting technologies...")
        
        detector = TechnologyDetector()
        tech_dict = detector.detect_from_crawl_results(crawl_results)
        results["tech_stack"] = tech_dict
        scan_timer.end_phase()
        
        tech_names = list(tech_dict.keys())
        tech_str = ", ".join(tech_names[:3]) if tech_names else "Unknown"
        progress.update(task, description=f"[green]✓ Detected: {tech_str}")
        
        # Phase 3: AI-Enhanced Scanning
        scan_timer.start_phase("AI-Enhanced Scanning")
        ai_label = "AI-Enhanced" if ai_mode else "Standard"
        progress.update(task, description=f"[cyan]Phase 3: {ai_label} vulnerability scanning...")
        
        scanner = EnhancedVulnerabilityScanner(scan_config)
        
        # Convert tech_dict to list of names for scanner
        tech_list = list(results["tech_stack"].keys()) if results["tech_stack"] else []
        
        # Run scan
        results["vulnerabilities"] = await scanner.scan_async(crawl_results, tech_list)
        results["scan_stats"] = scanner.get_metrics()
        scan_timer.end_phase()
        
        vuln_count = len(results["vulnerabilities"])
        progress.update(task, description=f"[green]✓ Found {vuln_count} vulnerabilities")
        
        # Phase 4: Remediation
        if remediation:
            scan_timer.start_phase("Remediation Generation")
            progress.update(task, description="[cyan]Phase 4: Generating remediation advice...")
            
            remediation_engine = RemediationEngine()
            tech_list = list(results["tech_stack"].keys()) if results["tech_stack"] else []
            
            for vuln in results["vulnerabilities"]:
                advice = remediation_engine.get_remediation(vuln.vuln_type, tech_list)
                if advice:
                    results["remediations"][vuln.vuln_type] = advice
            scan_timer.end_phase()
            
            progress.update(task, description="[green]✓ Remediation advice generated")
        
        progress.update(task, description="[green]✓ Scan complete!")
    
    # Create simple async wrapper for non-Rich mode
    async def run_scan_simple():
        """Simple async wrapper without Rich progress"""
        # Phase 1: Crawling
        scan_timer.start_phase("Crawling")
        print("[*] Phase 1: Crawling website...")
        
        crawler = AsyncWebCrawler(target_url, depth, max_pages)
        crawl_results = await crawler.crawl()
        results["pages_scanned"] = len(crawl_results.get("urls", {}))
        results["forms_tested"] = len(crawl_results.get("forms", []))
        scan_timer.end_phase()
        
        print(f"    Found {results['pages_scanned']} URLs, {results['forms_tested']} forms")
        
        # Phase 2: Technology Detection
        scan_timer.start_phase("Technology Detection")
        print("[*] Phase 2: Detecting technologies...")
        
        detector = TechnologyDetector()
        tech_dict = detector.detect_from_crawl_results(crawl_results)
        results["tech_stack"] = tech_dict
        scan_timer.end_phase()
        
        tech_names = list(tech_dict.keys())
        tech_str = ", ".join(tech_names[:3]) if tech_names else "Unknown"
        print(f"    Detected: {tech_str}")
        
        # Phase 3: AI-Enhanced Scanning
        scan_timer.start_phase("AI-Enhanced Scanning")
        ai_label = "AI-Enhanced" if ai_mode else "Standard"
        print(f"[*] Phase 3: {ai_label} vulnerability scanning...")
        
        scanner = EnhancedVulnerabilityScanner(scan_config)
        
        tech_list = list(results["tech_stack"].keys()) if results["tech_stack"] else []
        
        results["vulnerabilities"] = await scanner.scan_async(crawl_results, tech_list)
        results["scan_stats"] = scanner.get_metrics()
        scan_timer.end_phase()
        
        print(f"    Found {len(results['vulnerabilities'])} vulnerabilities")
        
        # Phase 4: Remediation
        if remediation:
            scan_timer.start_phase("Remediation Generation")
            print("[*] Phase 4: Generating remediation advice...")
            
            remediation_engine = RemediationEngine()
            tech_list = list(results["tech_stack"].keys()) if results["tech_stack"] else []
            
            for vuln in results["vulnerabilities"]:
                advice = remediation_engine.get_remediation(vuln.vuln_type, tech_list)
                if advice:
                    results["remediations"][vuln.vuln_type] = advice
            scan_timer.end_phase()
            
            print("    Completed")
        
        print("[+] Scan complete!")
    
    # Run scan with or without Rich
    try:
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Initializing scan...", total=None)
                asyncio.run(run_scan_with_progress(progress, task))
        else:
            asyncio.run(run_scan_simple())
    
    except KeyboardInterrupt:
        scan_timer.stop()
        if RICH_AVAILABLE:
            console.print("\n[yellow]⚠️  Scan interrupted by user[/yellow]")
        else:
            print("\n⚠️  Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        scan_timer.stop()
        if RICH_AVAILABLE:
            console.print(f"\n[red]Error during scan: {e}[/red]")
            console.print(f"[dim]Elapsed time: {scan_timer.total_duration_formatted}[/dim]")
        else:
            print(f"\nError during scan: {e}")
            print(f"Elapsed time: {scan_timer.total_duration_formatted}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    
    # Stop timer
    scan_timer.stop()
    
    # Display results
    display_results(results, show_remediation=remediation, show_stats=stats)
    
    # Display timing
    if not no_timing:
        if RICH_AVAILABLE:
            console.print(f"\n[bold cyan]⏱️  Total scan time:[/bold cyan] [bold white]{scan_timer.total_duration_formatted}[/bold white]")
        else:
            print(f"\nTotal scan time: {scan_timer.total_duration_formatted}")
    
    # Generate report
    if output:
        generator = ReportGenerator()
        
        results["timing"] = scan_timer.get_summary()
        results["ai_metadata"] = {
            "enabled": ai_mode,
            "smart_payloads": smart_payloads,
            "confidence_threshold": confidence_threshold,
            "model": "llama-3.3-70b-versatile" if ai_mode else None
        }
        
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
    if fail_on == 'none':
        sys.exit(0)
    
    exit_code = determine_exit_code(results, fail_on)
    sys.exit(exit_code)


@cli.command()
@click.option('--host', '-h', default='0.0.0.0', help='Host to bind (default: 0.0.0.0)')
@click.option('--port', '-p', default=8000, help='Port to bind (default: 8000)')
def server(host, port):
    """Start the VulnFlow API server"""
    try:
        import uvicorn
        from api.main import app
        
        if RICH_AVAILABLE:
            console.print(f"[green]Starting VulnFlow API server on {host}:{port}[/green]")
        else:
            print(f"Starting VulnFlow API server on {host}:{port}")
        
        uvicorn.run(app, host=host, port=port)
    except ImportError:
        if RICH_AVAILABLE:
            console.print("[red]Error: uvicorn not installed. Run: pip install uvicorn[/red]")
        else:
            print("Error: uvicorn not installed. Run: pip install uvicorn")
        sys.exit(1)


@cli.command()
def version():
    """Show version information"""
    version_info = """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗██╗      ██████╗ ██╗    ║
║  ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██║     ██╔═══██╗██║    ║
║  ██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██║     ██║   ██║██║    ║
║  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██║     ██║   ██║██║    ║
║   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║     ███████╗╚██████╔╝██║    ║
║    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝    ║
║                                                                      ║
║            AI-Enhanced Web Vulnerability Scanner v2.0              ║
║                  Powered by Groq LLM (Llama 3.3 70B)                ║
║                                                                      ║
║  Features:                                                           ║
║    • AI-powered vulnerability analysis                              ║
║    • Smart payload generation based on tech stack                   ║
║    • False positive reduction with confidence scoring               ║
║    • Context-aware remediation advice                               ║
║    • Parallel scanning for faster results                           ║
║    • OWASP Top 10 2021 coverage                                     ║
║                                                                      ║
║  Set GROQ_API_KEY environment variable to enable AI features        ║
║  Get your free API key at: https://console.groq.com                 ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """
    
    if RICH_AVAILABLE:
        console.print(version_info, style="cyan")
    else:
        print(version_info)


def main():
    """Main entry point for CLI"""
    cli()


if __name__ == '__main__':
    main()