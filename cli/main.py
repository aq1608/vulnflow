# cli/main.py - MERGED: AI-INTEGRATED + FULL FEATURES
"""
VulnFlow CLI with Full AI Integration + Rich Terminal Output + Complete Feature Set
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
from detector.tech_fingerprint import TechnologyDetector
from remediation.engine import RemediationEngine
from reports.generator import ReportGenerator

# Try to import Enhanced scanner (AI), fall back to standard
try:
    from scanner.enhanced_vuln_scanner import EnhancedVulnerabilityScanner
    ENHANCED_SCANNER_AVAILABLE = True
except ImportError:
    ENHANCED_SCANNER_AVAILABLE = False

from scanner.vuln_scanner import VulnerabilityScanner

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
        if self._current_phase:
            self.end_phase()
        return self
    
    def start_phase(self, phase_name: str):
        """Start timing a specific phase"""
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
        throughput_pages = pages_scanned / self.total_duration if self.total_duration > 0 else 0
        throughput_forms = forms_tested / self.total_duration if self.total_duration > 0 else 0
        
        timing_text = f"""
[bold cyan]⏱️  Total Scan Time:[/bold cyan] [bold white]{self.total_duration_formatted}[/bold white]

[bold]Performance Metrics:[/bold]
  • Pages scanned: {pages_scanned} ([green]{throughput_pages:.1f} pages/sec[/green])
  • Forms tested: {forms_tested} ([green]{throughput_forms:.1f} forms/sec[/green])
  • Vulnerabilities found: [{'red' if vulns_found > 0 else 'green'}]{vulns_found}[/{'red' if vulns_found > 0 else 'green'}]
"""
        console.print(Panel(timing_text, title="⚡ Scan Performance", border_style="cyan"))
        
        if show_phases and self.phase_times:
            phase_table = Table(title="📊 Phase Breakdown", show_header=True)
            phase_table.add_column("Phase", style="cyan", width=30)
            phase_table.add_column("Duration", justify="right", width=12)
            phase_table.add_column("% of Total", justify="right", width=12)
            phase_table.add_column("Progress", width=20)
            
            sorted_phases = sorted(
                self.phase_times.items(),
                key=lambda x: x[1],
                reverse=True
            )
            
            for phase_name, duration in sorted_phases:
                percentage = self.get_phase_percentage(phase_name)
                formatted = self.format_duration(duration)
                
                bar_length = 15
                filled = int(percentage / 100 * bar_length)
                bar = "█" * filled + "░" * (bar_length - filled)
                
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
║            AI-Enhanced Web Vulnerability Scanner v2.0.1                   ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
    """
    if RICH_AVAILABLE:
        console.print(banner, style="bold blue")
    else:
        print(banner)


async def run_full_scan(
    target_url: str, 
    depth: int, 
    max_pages: int,
    verbose: bool = False,
    workers: int = 8,
    concurrent_targets: int = 15,
    rate_limit: float = 75.0,
    timeout: float = 30.0,
    timer: Optional[ScanTimer] = None,
    # AI-specific options
    ai_enabled: bool = True,
    api_key: Optional[str] = None,
    smart_payloads: bool = True,
    confidence_threshold: float = 0.6,
    mode: str = 'full',
    show_remediation: bool = False
) -> dict:
    """
    Run a complete scan against the target with parallel execution and optional AI enhancement.
    
    Args:
        target_url: URL to scan
        depth: Crawl depth
        max_pages: Maximum pages to crawl
        verbose: Verbose output
        workers: Number of concurrent scanner workers
        concurrent_targets: Number of concurrent targets to scan
        rate_limit: Requests per second limit
        timeout: Timeout per scan operation
        timer: ScanTimer instance for tracking timing
        ai_enabled: Enable AI-powered analysis
        api_key: Groq API key (overrides env var)
        smart_payloads: Use AI-generated payloads
        confidence_threshold: Minimum confidence score for findings
        mode: Scan mode (quick/standard/owasp/full)
        show_remediation: Generate remediation advice
    """
    # Initialize timer if not provided
    if timer is None:
        timer = ScanTimer()
        timer.start()
    
    # Check AI availability
    has_api_key = api_key or os.environ.get("GROQ_API_KEY")
    ai_mode = ai_enabled and has_api_key and ENHANCED_SCANNER_AVAILABLE
    
    results = {
        "target": target_url,
        "target_url": target_url,
        "scan_time": datetime.now().isoformat(),
        "scan_date": datetime.now().isoformat(),
        "ai_enabled": ai_mode,
        "scan_mode": mode,
        "confidence_threshold": confidence_threshold if ai_mode else None,
        "vulnerabilities": [],
        "tech_stack": {},
        "remediations": {},
        "pages_scanned": 0,
        "forms_tested": 0,
        "scan_stats": {},
        "timing": {}
    }
    
    # Scanner configuration (always parallel)
    scan_config = {
        'parallel': True,
        'max_concurrent_scanners': workers,
        'max_concurrent_targets': concurrent_targets,
        'requests_per_second': rate_limit,
        'timeout': timeout,
        'api_key': api_key,
        'smart_payloads': smart_payloads,
        'confidence_threshold': confidence_threshold,
        'mode': mode,
        'scan_depth': 'deep',
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
            # transient=False
        ) as progress:
            
            main_task = progress.add_task(
                "[cyan]Scanning...", 
                total=None,
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
            
            # Phase 3: Vulnerability scanning (30-85%)
            scan_phase_name = "AI-Enhanced Scanning" if ai_mode else "Vulnerability Scanning"
            timer.start_phase(scan_phase_name)
            progress.update(main_task, completed=30, description=f"[cyan]Phase 3: {scan_phase_name}...", status="Initializing scanners")
            
            def scan_progress_callback(completed, total, message):
                if total > 0:
                    pct = 30 + (completed / total) * 55
                    progress.update(
                        main_task, 
                        completed=pct,
                        status=f"{message} ({completed}/{total})"
                    )
            if ai_mode:
                scanner = EnhancedVulnerabilityScanner(scan_config)
                tech_list = list(results["tech_stack"].keys()) if results["tech_stack"] else []
                
                if hasattr(scanner, 'set_progress_callback'):
                    scanner.set_progress_callback(scan_progress_callback)
                
                results["vulnerabilities"] = await scanner.scan_async(crawl_results, tech_list)
                results["scan_stats"] = scanner.get_metrics() if hasattr(scanner, 'get_metrics') else {}
            else:
                scanner = VulnerabilityScanner(scan_config)
                
                scanner.set_progress_callback(scan_progress_callback)
                results["vulnerabilities"] = await scanner.scan_target(crawl_results)
                results["scan_stats"] = scanner.get_execution_stats()
            
            timer.end_phase()
            
            progress.update(main_task, completed=85, status=f"Found {len(results['vulnerabilities'])} vulnerabilities")
            
            if verbose:
                console.print(f"  [green]✓[/green] Found {len(results['vulnerabilities'])} vulnerabilities ({timer.format_duration(timer.get_phase_duration(scan_phase_name))})")
                stats = results["scan_stats"]
                if ai_mode:
                    console.print(f"  [dim]AI Stats: {stats.get('ai_enhanced_findings', 0)} AI-enhanced, {stats.get('false_positives_filtered', 0)} filtered[/dim]")
                else:
                    console.print(f"  [dim]Stats: {stats.get('completed_tasks', 0)} tasks, {stats.get('failed_tasks', 0)} failed[/dim]")
            
            # Phase 4: Generate remediations (85-100%)
            timer.start_phase("Remediation Generation")
            progress.update(main_task, completed=85, description="[cyan]Phase 4: Generating remediation advice...", status="Analyzing findings")
            remediation_engine = RemediationEngine()
            tech_list = list(results["tech_stack"].keys()) if results["tech_stack"] else []
            for vuln in results["vulnerabilities"]:
                advice = remediation_engine.get_remediation(vuln.vuln_type, tech_list if ai_mode else results["tech_stack"])
                if advice:
                    results["remediations"][vuln.vuln_type] = advice
            timer.end_phase()
            
            progress.update(main_task, completed=100, description="[green]Scan complete!", status="✓ Done")
            
            if hasattr(scanner, 'shutdown'):
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
        
        scan_phase_name = "AI-Enhanced Scanning" if ai_mode else "Vulnerability Scanning"
        print(f"[*] Phase 3: {scan_phase_name} (workers={workers})...")
        timer.start_phase(scan_phase_name)
        
        if ai_mode:
            scanner = EnhancedVulnerabilityScanner(scan_config)
            tech_list = list(results["tech_stack"].keys()) if results["tech_stack"] else []
            results["vulnerabilities"] = await scanner.scan_async(crawl_results, tech_list)
            results["scan_stats"] = scanner.get_metrics() if hasattr(scanner, 'get_metrics') else {}
        else:
            scanner = VulnerabilityScanner(scan_config)
            results["vulnerabilities"] = await scanner.scan_target(crawl_results)
            results["scan_stats"] = scanner.get_execution_stats()
        
        timer.end_phase()
        print(f"    Found {len(results['vulnerabilities'])} vulnerabilities ({timer.format_duration(timer.get_phase_duration(scan_phase_name))})")
        
        print("[*] Phase 4: Generating remediation advice...")
        timer.start_phase("Remediation Generation")
        remediation_engine = RemediationEngine()
        tech_list = list(results["tech_stack"].keys()) if results["tech_stack"] else []
        for vuln in results["vulnerabilities"]:
            advice = remediation_engine.get_remediation(vuln.vuln_type, tech_list if ai_mode else results["tech_stack"])
            if advice:
                results["remediations"][vuln.vuln_type] = advice
        timer.end_phase()
        print(f"    Completed ({timer.format_duration(timer.get_phase_duration('Remediation Generation'))})")
        
        print("[+] Scan complete!")
        if hasattr(scanner, 'shutdown'):
            scanner.shutdown()
    
    # Store timing information in results
    timer.stop()
    results["timing"] = timer.get_summary()
    
    # Add AI metadata if applicable
    if ai_mode:
        results["ai_metadata"] = {
            "enabled": True,
            "smart_payloads": smart_payloads,
            "confidence_threshold": confidence_threshold,
            "model": "llama-3.3-70b-versatile"
        }
    
    return results


def display_results(results: dict, show_remediation: bool = False, show_stats: bool = False):
    """Display scan results"""
    vulns = results.get("vulnerabilities", [])
    stats = results.get("scan_stats", {})
    ai_mode = results.get("ai_enabled", False)
    
    if RICH_AVAILABLE:
        # Summary panel
        summary_text = f"""
[bold]Target:[/bold] {results.get('target', results.get('target_url', 'N/A'))}
[bold]Scan Time:[/bold] {results.get('scan_time', results.get('scan_date', 'N/A'))}
[bold]Pages Scanned:[/bold] {results.get('pages_scanned', 0)}
[bold]Forms Tested:[/bold] {results.get('forms_tested', 0)}
[bold]AI Enhanced:[/bold] {'Yes' if ai_mode else 'No'}
[bold]Total Vulnerabilities:[/bold] {len(vulns)}
        """
        console.print(Panel(summary_text, title="📊 Scan Summary", border_style="blue"))
        
        # Performance stats if requested
        if show_stats and stats:
            stats_table = Table(title="⚡ Execution Statistics")
            stats_table.add_column("Metric", style="cyan")
            stats_table.add_column("Value", justify="right")
            
            if ai_mode:
                stats_table.add_row("AI Enhanced Findings", str(stats.get('ai_enhanced_findings', 0)))
                stats_table.add_row("False Positives Filtered", str(stats.get('false_positives_filtered', 0)))
            else:
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
                if isinstance(info, dict):
                    confidence = f"{info.get('confidence', 0)*100:.0f}%"
                    category = info.get('category', 'Unknown')
                else:
                    confidence = "N/A"
                    category = str(info)
                tech_table.add_row(tech, category, confidence)
            
            console.print(tech_table)
            console.print()
        
        # # Vulnerabilities table
        # if vulns:
        #     vuln_table = Table(title="🔴 Vulnerabilities Found")
        #     vuln_table.add_column("#", style="dim", width=4)
        #     vuln_table.add_column("Type", style="cyan")
        #     vuln_table.add_column("Severity")
        #     vuln_table.add_column("URL", max_width=40)
        #     vuln_table.add_column("Parameter")
        #     if ai_mode:
        #         vuln_table.add_column("Confidence")
            
        #     for i, vuln in enumerate(vulns, 1):
        #         sev = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
        #         color = severity_colors.get(sev, "white")
                
        #         url_display = vuln.url[:40] + "..." if len(vuln.url) > 40 else vuln.url
                
        #         row = [
        #             str(i),
        #             vuln.vuln_type,
        #             f"[{color}]{sev.upper()}[/{color}]",
        #             url_display,
        #             vuln.parameter or "N/A"
        #         ]
                
        #         if ai_mode and hasattr(vuln, 'confidence'):
        #             row.append(f"{vuln.confidence:.0%}" if vuln.confidence else "N/A")
                
        #         vuln_table.add_row(*row)
            
        #     console.print(vuln_table)
            
        #     # Detailed findings
        #     console.print("\n[bold]📋 Detailed Findings:[/bold]\n")
            
        #     for i, vuln in enumerate(vulns, 1):
        #         sev = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
        #         color = severity_colors.get(sev, "white")
                
        #         console.print(f"[bold]#{i} {vuln.vuln_type}[/bold]")
        #         console.print(f"   Severity: [{color}]{sev.upper()}[/{color}]")
        #         console.print(f"   URL: {vuln.url}")
        #         if vuln.parameter:
        #             console.print(f"   Parameter: {vuln.parameter}")
        #         if vuln.payload:
        #             console.print(f"   Payload: {vuln.payload[:60]}...")
        #         if hasattr(vuln, 'evidence') and vuln.evidence:
        #             console.print(f"   Evidence: {vuln.evidence[:80]}...")
        #         if hasattr(vuln, 'cwe_id') and vuln.cwe_id:
        #             console.print(f"   CWE: {vuln.cwe_id}")
        #         if hasattr(vuln, 'description') and vuln.description:
        #             console.print(f"   Description: {vuln.description}")
        #         if ai_mode and hasattr(vuln, 'confidence') and vuln.confidence:
        #             console.print(f"   Confidence: {vuln.confidence:.0%}")
                
        #         # Show remediation if requested
        #         if show_remediation:
        #             if hasattr(vuln, 'remediation') and vuln.remediation:
        #                 console.print(f"\n   [green]💡 Remediation:[/green] {vuln.remediation}")
        #             elif vuln.vuln_type in results.get("remediations", {}):
        #                 console.print(f"\n   [green]💡 Remediation:[/green]")
        #                 for advice in results["remediations"][vuln.vuln_type]:
        #                     if hasattr(advice, 'framework'):
        #                         console.print(f"      Framework: {advice.framework}")
        #                     if hasattr(advice, 'description'):
        #                         console.print(f"      {advice.description}")
                
        #         console.print()
        # else:
        #     console.print(Panel(
        #         "[green]✅ No vulnerabilities found![/green]\n\nGreat job! The scan did not detect any security issues.",
        #         title="Results",
        #         border_style="green"
        #     ))
    else:
        # Fallback without rich
        print("\n" + "="*60)
        print("SCAN RESULTS")
        print("="*60)
        print(f"Target: {results.get('target', results.get('target_url', 'N/A'))}")
        print(f"Scan Time: {results.get('scan_time', results.get('scan_date', 'N/A'))}")
        print(f"Pages Scanned: {results.get('pages_scanned', 0)}")
        print(f"Forms Tested: {results.get('forms_tested', 0)}")
        print(f"AI Enhanced: {'Yes' if ai_mode else 'No'}")
        print(f"Vulnerabilities: {len(vulns)}")
        
        if show_stats and stats:
            print("-"*60)
            print("EXECUTION STATISTICS")
            if ai_mode:
                print(f"AI Enhanced Findings: {stats.get('ai_enhanced_findings', 0)}")
                print(f"False Positives Filtered: {stats.get('false_positives_filtered', 0)}")
            else:
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
                if hasattr(vuln, 'description') and vuln.description:
                    print(f"    Description: {vuln.description}")
                if ai_mode and hasattr(vuln, 'confidence') and vuln.confidence:
                    print(f"    Confidence: {vuln.confidence:.0%}")
                if show_remediation and hasattr(vuln, 'remediation') and vuln.remediation:
                    print(f"    Remediation: {vuln.remediation}")
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
@click.version_option(version="2.0.1")
def cli():
    """VulnFlow - AI-Enhanced Web Vulnerability Scanner with Contextual Remediation
    
    Features:
    - AI-powered vulnerability analysis with Groq LLM
    - Smart payload generation based on tech stack
    - False positive reduction with confidence scoring
    - Context-aware remediation advice
    - Parallel scanning for faster results
    - OWASP Top 10 2021 coverage
    
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
@click.option('--no-ai', is_flag=True, help='Disable AI-powered analysis')
@click.option('--api-key', default=None, help='Groq API key (overrides GROQ_API_KEY env var)')
@click.option('--smart-payloads/--no-smart-payloads', default=True, help='Use AI-generated payloads (default: enabled)')
@click.option('--confidence-threshold', default=0.6, type=float, help='Minimum confidence score (0.0-1.0, default: 0.6)')
# Scan mode options
@click.option('--mode', type=click.Choice(['quick', 'standard', 'owasp', 'full']), 
              default='full', help='Scan mode (default: full)')
# Performance options
@click.option('--workers', '-w', default=8, help='Number of concurrent scanner workers (default: 8)')
@click.option('--concurrent-targets', '-c', default=15, help='Number of concurrent targets (default: 15)')
@click.option('--rate-limit', default=75.0, help='Max requests per second (default: 75)')
@click.option('--timeout', '-t', default=30.0, help='Timeout per scan in seconds (default: 30)')
# Timing and stats options
@click.option('--stats', is_flag=True, help='Show execution statistics')
@click.option('--timing', is_flag=True, help='Show detailed timing breakdown')
@click.option('--no-timing', is_flag=True, help='Hide timing information')
def scan(target_url, depth, max_pages, output, output_format, fail_on, verbose, 
         remediation, no_ai, api_key, smart_payloads, confidence_threshold,
         mode, workers, concurrent_targets, rate_limit, timeout, 
         stats, timing, no_timing):
    """Scan a target URL for vulnerabilities with optional AI-powered analysis
    
    Examples:
    
        vulnflow scan http://example.com
        
        vulnflow scan http://example.com -d 3 -m 100 -o report.html -f html
        
        vulnflow scan http://example.com --fail-on high --verbose
        
        # AI-powered scan with custom confidence threshold
        vulnflow scan http://example.com --confidence-threshold 0.8
        
        # Disable AI for faster scanning
        vulnflow scan http://example.com --no-ai
        
        # OWASP Top 10 focused scan
        vulnflow scan http://example.com --mode owasp
        
        # Show detailed timing breakdown
        vulnflow scan http://example.com --timing
        
        # High concurrency with rate limiting
        vulnflow scan http://example.com -w 20 -c 50 --rate-limit 100
    """
    # Check AI availability
    ai_enabled = not no_ai
    has_api_key = api_key or os.environ.get("GROQ_API_KEY")
    ai_mode = ai_enabled and has_api_key and ENHANCED_SCANNER_AVAILABLE
    
    print_banner()
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    if RICH_AVAILABLE:
        # Display scan configuration
        config_table = Table(show_header=False, box=None, padding=(0, 1))
        config_table.add_column("Setting", style="cyan")
        config_table.add_column("Value", style="white")
        
        config_table.add_row("Target URL", target_url)
        config_table.add_row("Scan Mode", mode.upper())
        config_table.add_row("AI Mode", "[green]✓ ENABLED[/green]" if ai_mode else "[yellow]✗ DISABLED[/yellow]")
        if ai_mode:
            config_table.add_row("Confidence Threshold", f"{confidence_threshold:.1%}")
        config_table.add_row("Max Depth", str(depth))
        config_table.add_row("Max Pages", str(max_pages))
        config_table.add_row("Workers", str(workers))
        config_table.add_row("Concurrent Targets", str(concurrent_targets))
        
        console.print(config_table)
        console.print()
        
        if verbose:
            if ai_mode:
                console.print("[green]✓ AI-powered analysis enabled[/green] - Using Groq LLM (Llama 3.3 70B)")
            elif ai_enabled and not has_api_key:
                console.print("[yellow]⚠ AI-powered analysis disabled[/yellow] - Set GROQ_API_KEY to enable")
            elif ai_enabled and not ENHANCED_SCANNER_AVAILABLE:
                console.print("[yellow]⚠ AI-powered analysis disabled[/yellow] - Enhanced scanner not available")
            elif no_ai:
                console.print("[dim]AI-powered analysis disabled by user[/dim]")
            console.print()
    else:
        print(f"\nTarget: {target_url}")
        print(f"Scan Mode: {mode.upper()}")
        print(f"AI Mode: {'ENABLED' if ai_mode else 'DISABLED'}")
        if ai_mode:
            print(f"Confidence Threshold: {confidence_threshold:.1%}")
        print(f"Depth: {depth} | Max Pages: {max_pages}")
        print(f"Workers: {workers} | Targets: {concurrent_targets}")
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
            workers=workers,
            concurrent_targets=concurrent_targets,
            rate_limit=rate_limit,
            timeout=timeout,
            timer=scan_timer,
            # AI options
            ai_enabled=ai_enabled,
            api_key=api_key,
            smart_payloads=smart_payloads,
            confidence_threshold=confidence_threshold,
            mode=mode,
            show_remediation=remediation
        ))
    except KeyboardInterrupt:
        scan_timer.stop()
        if RICH_AVAILABLE:
            console.print("\n[yellow]⚠️ Scan interrupted by user[/yellow]")
            console.print(f"[dim]Elapsed time: {scan_timer.total_duration_formatted}[/dim]")
        else:
            print("\n⚠️ Scan interrupted by user")
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
            display_timing(scan_timer, results)
        else:
            if RICH_AVAILABLE:
                console.print(f"\n[bold cyan]⏱️  Total scan time:[/bold cyan] [bold white]{scan_timer.total_duration_formatted}[/bold white]")
            else:
                print(f"\nTotal scan time: {scan_timer.total_duration_formatted}")
    
    # Generate and save report if output specified
    if output:
        generator = ReportGenerator()
        
        results["timing"] = scan_timer.get_summary()
        if ai_mode:
            results["ai_metadata"] = {
                "enabled": True,
                "smart_payloads": smart_payloads,
                "confidence_threshold": confidence_threshold,
                "model": "llama-3.3-70b-versatile"
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
        
        from api.main import app

        uvicorn.run(app, host=host, port=port, reload=True)
    except ImportError as e:
        if RICH_AVAILABLE:
            console.print(f"[red]Error: {e}[/red]")
            console.print("[dim]Install with: pip install uvicorn[/dim]")
        else:
            print(f"Error: {e}")
            print("Install with: pip install uvicorn")
        sys.exit(1)


@cli.command()
def version():
    """Show version information"""
    print_banner()
    
    has_api_key = os.environ.get("GROQ_API_KEY")
    ai_available = has_api_key and ENHANCED_SCANNER_AVAILABLE
    
    if RICH_AVAILABLE:
        console.print("\n[bold]VulnFlow[/bold] version 2.0.1")
        console.print("[dim]AI-Enhanced Web Vulnerability Scanner with Contextual Remediation[/dim]")
        console.print()
        console.print("[bold]Features:[/bold]")
        console.print("  • AI-powered vulnerability analysis")
        console.print("  • Smart payload generation based on tech stack")
        console.print("  • False positive reduction with confidence scoring")
        console.print("  • Context-aware remediation advice")
        console.print("  • Parallel scanning for faster results")
        console.print("  • OWASP Top 10 2021 coverage")
        console.print()
        
        if ai_available:
            console.print("[green]✓ AI features available[/green] - GROQ_API_KEY is set")
        else:
            console.print("[yellow]⚠ AI features disabled[/yellow]")
            if not ENHANCED_SCANNER_AVAILABLE:
                console.print("  [dim]Enhanced scanner module not found[/dim]")
            if not has_api_key:
                console.print("  [dim]Set GROQ_API_KEY environment variable to enable[/dim]")
                console.print("  [dim]Get your free API key at: https://console.groq.com[/dim]")
    else:
        print("\nVulnFlow version 2.0.1")
        print("AI-Enhanced Web Vulnerability Scanner with Contextual Remediation")
        print()
        print("Features:")
        print("  • AI-powered vulnerability analysis")
        print("  • Smart payload generation based on tech stack")
        print("  • False positive reduction with confidence scoring")
        print("  • Context-aware remediation advice")
        print("  • Parallel scanning for faster results")
        print("  • OWASP Top 10 2021 coverage")
        print()
        
        if ai_available:
            print("✓ AI features available - GROQ_API_KEY is set")
        else:
            print("⚠ AI features disabled")
            if not ENHANCED_SCANNER_AVAILABLE:
                print("  Enhanced scanner module not found")
            if not has_api_key:
                print("  Set GROQ_API_KEY environment variable to enable")
                print("  Get your free API key at: https://console.groq.com")


@cli.command()
def benchmark():
    """Run a benchmark to test parallel scanning performance"""
    print_banner()
    
    if RICH_AVAILABLE:
        console.print("\n[bold]Running parallel scanning benchmark...[/bold]\n")
        
        console.print("[cyan]Testing different worker configurations:[/cyan]\n")
        
        configs = [
            (1, 1, "Sequential"),
            (5, 5, "Light parallel"),
            (8, 15, "Default"),
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
        
        console.print("\n[bold cyan]AI Mode Performance:[/bold cyan]")
        console.print("  • AI analysis adds ~0.5-2s per vulnerability for enhanced accuracy")
        console.print("  • Use --no-ai for maximum speed when AI features aren't needed")
        console.print("  • Smart payloads can reduce total scan time by targeting likely vulnerabilities")
    else:
        print("\nBenchmark requires rich library for display")
        print("Install with: pip install rich")


def main():
    """Main entry point"""
    cli()


if __name__ == "__main__":
    main()