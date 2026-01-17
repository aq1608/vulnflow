# cli/main.py
import click
import asyncio
import sys
import json
from datetime import datetime
from typing import Optional
import time

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
    from rich.panel import Panel
    from rich.live import Live
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


class ScanTimer:
    """
    Timer class to track scan duration and phase timings.
    Provides detailed performance metrics for the scanning process.
    """
    
    def __init__(self):
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.phase_times: dict = {}
        self._current_phase: Optional[str] = None
        self._phase_start: Optional[float] = None
    
    def start(self):
        """Start the main timer"""
        self.start_time = time.perf_counter()
        self.phase_times = {}
        return self
    
    def stop(self):
        """Stop the main timer"""
        self.end_time = time.perf_counter()
        # End any ongoing phase
        if self._current_phase:
            self.end_phase()
        return self
    
    def start_phase(self, phase_name: str):
        """Start timing a specific phase"""
        # End previous phase if exists
        if self._current_phase:
            self.end_phase()
        
        self._current_phase = phase_name
        self._phase_start = time.perf_counter()
        return self
    
    def end_phase(self):
        """End timing the current phase"""
        if self._current_phase and self._phase_start:
            elapsed = time.perf_counter() - self._phase_start
            self.phase_times[self._current_phase] = elapsed
            self._current_phase = None
            self._phase_start = None
        return self
    
    @property
    def total_duration(self) -> float:
        """Get total scan duration in seconds"""
        if self.start_time is None:
            return 0.0
        end = self.end_time or time.perf_counter()
        return end - self.start_time
    
    @property
    def total_duration_formatted(self) -> str:
        """Get formatted total duration string"""
        return self.format_duration(self.total_duration)
    
    @staticmethod
    def format_duration(seconds: float) -> str:
        """Format duration in human-readable format"""
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
        """Get duration of a specific phase"""
        return self.phase_times.get(phase_name, 0.0)
    
    def get_phase_percentage(self, phase_name: str) -> float:
        """Get percentage of total time spent in a phase"""
        if self.total_duration == 0:
            return 0.0
        phase_duration = self.get_phase_duration(phase_name)
        return (phase_duration / self.total_duration) * 100
    
    def get_summary(self) -> dict:
        """Get complete timing summary"""
        return {
            "total_duration": self.total_duration,
            "total_formatted": self.total_duration_formatted,
            "phases": {
                name: {
                    "duration": duration,
                    "formatted": self.format_duration(duration),
                    "percentage": self.get_phase_percentage(name)
                }
                for name, duration in self.phase_times.items()
            }
        }
    
    def display(self, pages_scanned: int = 0, forms_tested: int = 0, 
                vulns_found: int = 0, show_phases: bool = True):
        """Display timing information"""
        if RICH_AVAILABLE:
            self._display_rich(pages_scanned, forms_tested, vulns_found, show_phases)
        else:
            self._display_plain(pages_scanned, forms_tested, vulns_found, show_phases)
    
    def _display_rich(self, pages_scanned: int, forms_tested: int, 
                      vulns_found: int, show_phases: bool):
        """Display timing with rich formatting"""
        # Calculate throughput metrics
        throughput_pages = pages_scanned / self.total_duration if self.total_duration > 0 else 0
        throughput_forms = forms_tested / self.total_duration if self.total_duration > 0 else 0
        
        # Main timing panel
        timing_text = f"""
[bold cyan]⏱️  Total Scan Time:[/bold cyan] [bold white]{self.total_duration_formatted}[/bold white]

[bold]Performance Metrics:[/bold]
  • Pages scanned: {pages_scanned} ([green]{throughput_pages:.1f} pages/sec[/green])
  • Forms tested: {forms_tested} ([green]{throughput_forms:.1f} forms/sec[/green])
  • Vulnerabilities found: [{'red' if vulns_found > 0 else 'green'}]{vulns_found}[/{'red' if vulns_found > 0 else 'green'}]
"""
        console.print(Panel(timing_text, title="⚡ Scan Performance", border_style="cyan"))
        
        # Phase breakdown table
        if show_phases and self.phase_times:
            phase_table = Table(title="📊 Phase Breakdown", show_header=True)
            phase_table.add_column("Phase", style="cyan", width=30)
            phase_table.add_column("Duration", justify="right", width=12)
            phase_table.add_column("% of Total", justify="right", width=12)
            phase_table.add_column("Progress", width=20)
            
            # Sort phases by duration (descending)
            sorted_phases = sorted(
                self.phase_times.items(),
                key=lambda x: x[1],
                reverse=True
            )
            
            for phase_name, duration in sorted_phases:
                percentage = self.get_phase_percentage(phase_name)
                formatted = self.format_duration(duration)
                
                # Create a simple progress bar
                bar_length = 15
                filled = int(percentage / 100 * bar_length)
                bar = "█" * filled + "░" * (bar_length - filled)
                
                # Color based on percentage
                if percentage > 50:
                    color = "red"
                elif percentage > 25:
                    color = "yellow"
                else:
                    color = "green"
                
                phase_table.add_row(
                    phase_name,
                    formatted,
                    f"[{color}]{percentage:.1f}%[/{color}]",
                    f"[{color}]{bar}[/{color}]"
                )
            
            console.print(phase_table)
    
    def _display_plain(self, pages_scanned: int, forms_tested: int,
                       vulns_found: int, show_phases: bool):
        """Display timing with plain text formatting"""
        print("\n" + "=" * 50)
        print("SCAN PERFORMANCE")
        print("=" * 50)
        print(f"Total Scan Time: {self.total_duration_formatted}")
        print()
        print("Performance Metrics:")
        
        throughput_pages = pages_scanned / self.total_duration if self.total_duration > 0 else 0
        throughput_forms = forms_tested / self.total_duration if self.total_duration > 0 else 0
        
        print(f"  Pages scanned: {pages_scanned} ({throughput_pages:.1f} pages/sec)")
        print(f"  Forms tested: {forms_tested} ({throughput_forms:.1f} forms/sec)")
        print(f"  Vulnerabilities found: {vulns_found}")
        
        if show_phases and self.phase_times:
            print("\nPhase Breakdown:")
            print("-" * 50)
            
            sorted_phases = sorted(
                self.phase_times.items(),
                key=lambda x: x[1],
                reverse=True
            )
            
            for phase_name, duration in sorted_phases:
                percentage = self.get_phase_percentage(phase_name)
                formatted = self.format_duration(duration)
                bar_length = 20
                filled = int(percentage / 100 * bar_length)
                bar = "#" * filled + "-" * (bar_length - filled)
                print(f"  {phase_name:<25} {formatted:>10} ({percentage:>5.1f}%) [{bar}]")
        
        print("=" * 50)


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
║                   Web Vulnerability Scanner v1.0.4                        ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
    """
    if RICH_AVAILABLE:
        console.print(banner, style="bold blue")
    else:
        print(banner)


class ScanProgressTracker:
    """Track and display scan progress"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.current_phase = ""
        self.completed = 0
        self.total = 0
        self.current_task = ""
        
    def update(self, completed: int, total: int, message: str):
        """Update progress (callback for parallel executor)"""
        self.completed = completed
        self.total = total
        self.current_task = message


async def run_full_scan(
    target_url: str, 
    depth: int, 
    max_pages: int,
    verbose: bool = False,
    parallel: bool = True,
    workers: int = 5,
    concurrent_targets: int = 10,
    rate_limit: float = 50.0,
    timeout: float = 30.0,
    fast_mode: bool = False,
    timer: Optional[ScanTimer] = None
) -> dict:
    """
    Run a complete scan against the target with parallel execution.
    
    Args:
        target_url: URL to scan
        depth: Crawl depth
        max_pages: Maximum pages to crawl
        verbose: Verbose output
        parallel: Enable parallel scanning
        workers: Number of concurrent scanner workers
        concurrent_targets: Number of concurrent targets to scan
        rate_limit: Requests per second limit
        timeout: Timeout per scan operation
        fast_mode: Use fast worker pool mode
        timer: ScanTimer instance for tracking timing
    """
    # Initialize timer if not provided
    if timer is None:
        timer = ScanTimer()
        timer.start()
    
    results = {
        "target": target_url,
        "scan_time": datetime.now().isoformat(),
        "vulnerabilities": [],
        "tech_stack": {},
        "remediations": {},
        "pages_scanned": 0,
        "forms_tested": 0,
        "scan_stats": {},
        "timing": {}
    }
    
    # Scanner configuration
    scan_config = {
        'parallel': parallel,
        'max_concurrent_scanners': workers,
        'max_concurrent_targets': concurrent_targets,
        'requests_per_second': rate_limit,
        'timeout': timeout
    }
    
    progress_tracker = ScanProgressTracker(verbose)
    
    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TextColumn("[cyan]{task.fields[status]}"),
            console=console,
            transient=False
        ) as progress:
            
            main_task = progress.add_task(
                "[cyan]Scanning...", 
                total=100,
                status=""
            )
            
            # Phase 1: Crawl (0-20%)
            timer.start_phase("Crawling")
            progress.update(main_task, completed=0, description="[cyan]Phase 1: Crawling website...", status="Starting crawler")
            crawler = AsyncWebCrawler(target_url, depth, max_pages)
            crawl_results = await crawler.crawl()
            results["pages_scanned"] = len(crawl_results.get("urls", {}))
            results["forms_tested"] = len(crawl_results.get("forms", []))
            timer.end_phase()
            progress.update(main_task, completed=20, status=f"Found {results['pages_scanned']} URLs, {results['forms_tested']} forms")
            
            if verbose:
                console.print(f"  [green]✓[/green] Found {results['pages_scanned']} URLs ({timer.format_duration(timer.get_phase_duration('Crawling'))})")
                console.print(f"  [green]✓[/green] Found {results['forms_tested']} forms")
            
            # Phase 2: Detect technology (20-30%)
            timer.start_phase("Technology Detection")
            progress.update(main_task, completed=20, description="[cyan]Phase 2: Detecting technologies...", status="Fingerprinting")
            detector = TechnologyDetector()
            results["tech_stack"] = detector.detect_from_crawl_results(crawl_results)
            timer.end_phase()
            progress.update(main_task, completed=30, status=f"Detected {len(results['tech_stack'])} technologies")
            
            if verbose and results["tech_stack"]:
                console.print(f"  [green]✓[/green] Detected: {', '.join(results['tech_stack'].keys())} ({timer.format_duration(timer.get_phase_duration('Technology Detection'))})")
            
            # Phase 3: Parallel vulnerability scanning (30-85%)
            timer.start_phase("Vulnerability Scanning")
            progress.update(main_task, completed=30, description="[cyan]Phase 3: Scanning for vulnerabilities...", status="Initializing scanners")
            
            scanner = VulnerabilityScanner(scan_config)
            
            # Set up progress callback for real-time updates
            def scan_progress_callback(completed, total, message):
                if total > 0:
                    pct = 30 + (completed / total) * 55
                    progress.update(
                        main_task, 
                        completed=pct,
                        status=f"{message} ({completed}/{total})"
                    )
            
            scanner.set_progress_callback(scan_progress_callback)
            
            # Run the appropriate scan mode
            if fast_mode:
                results["vulnerabilities"] = await scanner.scan_target_fast(crawl_results)
            else:
                results["vulnerabilities"] = await scanner.scan_target(crawl_results)
            
            # Get execution stats
            results["scan_stats"] = scanner.get_execution_stats()
            timer.end_phase()
            
            progress.update(main_task, completed=85, status=f"Found {len(results['vulnerabilities'])} vulnerabilities")
            
            if verbose:
                console.print(f"  [green]✓[/green] Found {len(results['vulnerabilities'])} vulnerabilities ({timer.format_duration(timer.get_phase_duration('Vulnerability Scanning'))})")
                stats = results["scan_stats"]
                console.print(f"  [dim]Stats: {stats.get('completed_tasks', 0)} tasks, {stats.get('failed_tasks', 0)} failed[/dim]")
            
            # Phase 4: Generate remediations (85-100%)
            timer.start_phase("Remediation Generation")
            progress.update(main_task, completed=85, description="[cyan]Phase 4: Generating remediation advice...", status="Analyzing findings")
            remediation_engine = RemediationEngine()
            for vuln in results["vulnerabilities"]:
                advice = remediation_engine.get_remediation(vuln.vuln_type, results["tech_stack"])
                if advice:
                    results["remediations"][vuln.vuln_type] = advice
            timer.end_phase()
            
            progress.update(main_task, completed=100, description="[green]Scan complete!", status="✓ Done")
            
            # Cleanup
            scanner.shutdown()
            
    else:
        # Fallback without rich
        print("[*] Phase 1: Crawling website...")
        timer.start_phase("Crawling")
        crawler = AsyncWebCrawler(target_url, depth, max_pages)
        crawl_results = await crawler.crawl()
        results["pages_scanned"] = len(crawl_results.get("urls", {}))
        results["forms_tested"] = len(crawl_results.get("forms", []))
        timer.end_phase()
        print(f"    Found {results['pages_scanned']} URLs, {results['forms_tested']} forms ({timer.format_duration(timer.get_phase_duration('Crawling'))})")
        
        print("[*] Phase 2: Detecting technologies...")
        timer.start_phase("Technology Detection")
        detector = TechnologyDetector()
        results["tech_stack"] = detector.detect_from_crawl_results(crawl_results)
        timer.end_phase()
        print(f"    Completed ({timer.format_duration(timer.get_phase_duration('Technology Detection'))})")
        
        print(f"[*] Phase 3: Scanning for vulnerabilities (parallel={parallel}, workers={workers})...")
        timer.start_phase("Vulnerability Scanning")
        scanner = VulnerabilityScanner(scan_config)
        
        if fast_mode:
            results["vulnerabilities"] = await scanner.scan_target_fast(crawl_results)
        else:
            results["vulnerabilities"] = await scanner.scan_target(crawl_results)
        
        results["scan_stats"] = scanner.get_execution_stats()
        timer.end_phase()
        print(f"    Found {len(results['vulnerabilities'])} vulnerabilities ({timer.format_duration(timer.get_phase_duration('Vulnerability Scanning'))})")
        
        print("[*] Phase 4: Generating remediation advice...")
        timer.start_phase("Remediation Generation")
        remediation_engine = RemediationEngine()
        for vuln in results["vulnerabilities"]:
            advice = remediation_engine.get_remediation(vuln.vuln_type, results["tech_stack"])
            if advice:
                results["remediations"][vuln.vuln_type] = advice
        timer.end_phase()
        print(f"    Completed ({timer.format_duration(timer.get_phase_duration('Remediation Generation'))})")
        
        print("[+] Scan complete!")
        scanner.shutdown()
    
    # Store timing information in results
    timer.stop()
    results["timing"] = timer.get_summary()
    
    return results


def display_results(results: dict, show_remediation: bool = False, show_stats: bool = False):
    """Display scan results"""
    vulns = results.get("vulnerabilities", [])
    stats = results.get("scan_stats", {})
    
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
        
        # Performance stats if requested
        if show_stats and stats:
            stats_table = Table(title="⚡ Execution Statistics")
            stats_table.add_column("Metric", style="cyan")
            stats_table.add_column("Value", justify="right")
            
            stats_table.add_row("Total Tasks", str(stats.get('total_tasks', 0)))
            stats_table.add_row("Completed Tasks", str(stats.get('completed_tasks', 0)))
            stats_table.add_row("Failed Tasks", str(stats.get('failed_tasks', 0)))
            stats_table.add_row("Total Duration", f"{stats.get('total_duration', 0):.2f}s")
            
            if stats.get('total_tasks', 0) > 0 and stats.get('total_duration', 0) > 0:
                throughput = stats['completed_tasks'] / stats['total_duration']
                stats_table.add_row("Throughput", f"{throughput:.1f} tasks/sec")
            
            console.print(stats_table)
            console.print()
        
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
        
        if show_stats and stats:
            print("-"*60)
            print("EXECUTION STATISTICS")
            print(f"Total Tasks: {stats.get('total_tasks', 0)}")
            print(f"Completed: {stats.get('completed_tasks', 0)}")
            print(f"Failed: {stats.get('failed_tasks', 0)}")
            print(f"Duration: {stats.get('total_duration', 0):.2f}s")
        
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


def display_timing(timer: ScanTimer, results: dict):
    """Display timing information separately"""
    timer.display(
        pages_scanned=results.get("pages_scanned", 0),
        forms_tested=results.get("forms_tested", 0),
        vulns_found=len(results.get("vulnerabilities", [])),
        show_phases=True
    )


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
@click.version_option(version="1.0.4")
def cli():
    """VulnFlow - Web Vulnerability Scanner with Contextual Remediation
    
    Now with parallel scanning support for faster vulnerability detection!
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
# Parallel scanning options
@click.option('--parallel/--no-parallel', default=True, help='Enable/disable parallel scanning (default: enabled)')
@click.option('--workers', '-w', default=5, help='Number of concurrent scanner workers (default: 5)')
@click.option('--concurrent-targets', '-c', default=10, help='Number of concurrent targets (default: 10)')
@click.option('--rate-limit', default=50.0, help='Max requests per second (default: 50)')
@click.option('--timeout', '-t', default=30.0, help='Timeout per scan in seconds (default: 30)')
@click.option('--fast', is_flag=True, help='Use fast worker pool mode for maximum speed')
# Timing and stats options
@click.option('--stats', is_flag=True, help='Show execution statistics')
@click.option('--timing', is_flag=True, help='Show detailed timing breakdown')
@click.option('--no-timing', is_flag=True, help='Hide timing information')
def scan(target_url, depth, max_pages, output, output_format, fail_on, verbose, 
         remediation, parallel, workers, concurrent_targets, rate_limit, timeout, 
         fast, stats, timing, no_timing):
    """Scan a target URL for vulnerabilities
    
    Examples:
    
        vulnflow scan http://example.com
        
        vulnflow scan http://example.com -d 3 -m 100 -o report.html -f html
        
        vulnflow scan http://example.com --fail-on high --verbose
        
        # Fast parallel scan with 10 workers
        vulnflow scan http://example.com --workers 10 --fast
        
        # Show detailed timing breakdown
        vulnflow scan http://example.com --timing
        
        # Sequential scan (disable parallel)
        vulnflow scan http://example.com --no-parallel
        
        # High concurrency with rate limiting
        vulnflow scan http://example.com -w 20 -c 50 --rate-limit 100
    """
    print_banner()
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    if RICH_AVAILABLE:
        console.print(f"\n[bold]Target:[/bold] {target_url}")
        console.print(f"[bold]Depth:[/bold] {depth} | [bold]Max Pages:[/bold] {max_pages}")
        console.print(f"[bold]Parallel:[/bold] {'Yes' if parallel else 'No'} | [bold]Workers:[/bold] {workers} | [bold]Targets:[/bold] {concurrent_targets}")
        if fast:
            console.print("[bold yellow]Fast mode enabled[/bold yellow]")
        console.print()
    else:
        print(f"\nTarget: {target_url}")
        print(f"Depth: {depth} | Max Pages: {max_pages}")
        print(f"Parallel: {'Yes' if parallel else 'No'} | Workers: {workers} | Targets: {concurrent_targets}")
        if fast:
            print("Fast mode enabled")
        print()
    
    # Initialize timer
    scan_timer = ScanTimer()
    scan_timer.start()
    
    # Run scan
    try:
        results = asyncio.run(run_full_scan(
            target_url, 
            depth, 
            max_pages, 
            verbose,
            parallel=parallel,
            workers=workers,
            concurrent_targets=concurrent_targets,
            rate_limit=rate_limit,
            timeout=timeout,
            fast_mode=fast,
            timer=scan_timer
        ))
    except KeyboardInterrupt:
        scan_timer.stop()
        if RICH_AVAILABLE:
            console.print("\n[yellow]Scan interrupted by user[/yellow]")
            console.print(f"[dim]Elapsed time: {scan_timer.total_duration_formatted}[/dim]")
        else:
            print("\nScan interrupted by user")
            print(f"Elapsed time: {scan_timer.total_duration_formatted}")
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
    
    # Display timing information (unless --no-timing is specified)
    if not no_timing:
        if timing:
            # Show detailed timing
            display_timing(scan_timer, results)
        else:
            # Show simple timing summary
            if RICH_AVAILABLE:
                console.print(f"\n[bold cyan]⏱️  Total scan time:[/bold cyan] [bold white]{scan_timer.total_duration_formatted}[/bold white]")
            else:
                print(f"\nTotal scan time: {scan_timer.total_duration_formatted}")
    
    # Generate and save report if output specified
    if output:
        generator = ReportGenerator()
        
        # Add timing to results for report
        results["timing"] = scan_timer.get_summary()
        
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
    
    # Determine exit code
    if fail_on == 'none':
        sys.exit(0)
    
    exit_code = determine_exit_code(results, fail_on)
    sys.exit(exit_code)


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
        console.print("\n[bold]VulnFlow[/bold] version 1.0.4")
        console.print("[dim]Web Vulnerability Scanner with Contextual Remediation[/dim]")
        console.print("[dim]Parallel Scanning Support Enabled[/dim]")
    else:
        print("\nVulnFlow version 1.0.4")
        print("Web Vulnerability Scanner with Contextual Remediation")
        print("Parallel Scanning Support Enabled")


@cli.command()
def benchmark():
    """Run a benchmark to test parallel scanning performance"""
    print_banner()
    
    if RICH_AVAILABLE:
        console.print("\n[bold]Running parallel scanning benchmark...[/bold]\n")
        
        # Simulated benchmark results
        console.print("[cyan]Testing different worker configurations:[/cyan]\n")
        
        configs = [
            (1, 1, "Sequential"),
            (5, 5, "Light parallel"),
            (10, 10, "Medium parallel"),
            (20, 20, "Heavy parallel"),
        ]
        
        bench_table = Table(title="Benchmark Results (Simulated)")
        bench_table.add_column("Configuration")
        bench_table.add_column("Workers")
        bench_table.add_column("Targets")
        bench_table.add_column("Est. Speedup")
        
        for workers, targets, name in configs:
            speedup = min(workers * 0.8, 15)
            bench_table.add_row(name, str(workers), str(targets), f"{speedup:.1f}x")
        
        console.print(bench_table)
        console.print("\n[dim]Note: Actual performance depends on target server and network conditions.[/dim]")
    else:
        print("\nBenchmark requires rich library for display")
        print("Install with: pip install rich")


def main():
    """Main entry point"""
    cli()


if __name__ == "__main__":
    main()