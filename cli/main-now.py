# cli/main.py
"""
VulnFlow CLI with Full AI Integration + Rich Terminal Output + OWASP 2025 + Live Status Updates
"""

import click
import asyncio
import sys
import json
import os
from datetime import datetime
from typing import Optional, Dict, List
import time
import threading

try:
    from rich.console import Console, Group
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
    from rich.panel import Panel
    from rich.live import Live
    from rich.layout import Layout
    from rich.text import Text
    from rich.style import Style
    from rich import box
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
from scanner.base import OWASPCategory

if RICH_AVAILABLE:
    console = Console()


# OWASP 2025 Category Information
OWASP_2025_INFO = {
    "A01": {"name": "Broken Access Control", "color": "red", "emoji": "🔓"},
    "A02": {"name": "Security Misconfiguration", "color": "orange1", "emoji": "⚙️"},
    "A03": {"name": "Supply Chain Failures", "color": "magenta", "emoji": "📦"},
    "A04": {"name": "Cryptographic Failures", "color": "purple", "emoji": "🔐"},
    "A05": {"name": "Injection", "color": "red", "emoji": "💉"},
    "A06": {"name": "Insecure Design", "color": "cyan", "emoji": "📐"},
    "A07": {"name": "Authentication Failures", "color": "blue", "emoji": "🔑"},
    "A08": {"name": "Data Integrity Failures", "color": "green", "emoji": "✅"},
    "A09": {"name": "Logging Failures", "color": "dim", "emoji": "📝"},
    "A10": {"name": "Exceptional Conditions", "color": "yellow", "emoji": "⚠️"},
}


class LiveScanStatus:
    """
    Real-time scan status tracker with live display updates.
    Provides a dashboard showing current scan progress.
    """
    
    def __init__(self, target_url: str, ai_enabled: bool = False):
        self.target_url = target_url
        self.ai_enabled = ai_enabled
        self.start_time = time.time()
        
        # Current state
        self.current_phase = "Initializing"
        self.current_task = ""
        self.current_scanner = ""
        
        # Progress tracking
        self.phase_progress = 0
        self.overall_progress = 0
        self.tasks_completed = 0
        self.tasks_total = 0
        
        # Findings
        self.urls_found = 0
        self.forms_found = 0
        self.vulns_found = 0
        self.vulns_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        self.vulns_by_owasp = {}
        self.recent_findings = []  # Last 5 findings
        
        # Tech stack
        self.tech_stack = []
        
        # AI stats
        self.ai_calls = 0
        self.ai_filtered = 0
        
        # Phases
        self.phases = [
            ("Crawling", "🕷️", 0, 20),
            ("Tech Detection", "🔍", 20, 30),
            ("Scanning", "🔬", 30, 85),
            ("Remediation", "💊", 85, 100)
        ]
        self.phase_index = 0
        
        # Lock for thread safety
        self._lock = threading.Lock()
    
    def update(self, **kwargs):
        """Thread-safe update of status"""
        with self._lock:
            for key, value in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, value)
    
    def add_finding(self, vuln_type: str, severity: str, url: str, owasp_cat: str = None):
        """Add a new finding"""
        with self._lock:
            self.vulns_found += 1
            
            sev_lower = severity.lower()
            if sev_lower in self.vulns_by_severity:
                self.vulns_by_severity[sev_lower] += 1
            
            # Track by OWASP category
            if owasp_cat:
                cat_id = owasp_cat.split(":")[0] if ":" in owasp_cat else owasp_cat
                if cat_id not in self.vulns_by_owasp:
                    self.vulns_by_owasp[cat_id] = 0
                self.vulns_by_owasp[cat_id] += 1
            
            # Add to recent findings (keep last 5)
            finding_summary = f"[{severity.upper()}] {vuln_type[:40]}"
            self.recent_findings.insert(0, finding_summary)
            self.recent_findings = self.recent_findings[:5]
    
    def set_phase(self, phase_name: str):
        """Set current phase"""
        with self._lock:
            self.current_phase = phase_name
            for i, (name, _, _, _) in enumerate(self.phases):
                if name.lower() in phase_name.lower():
                    self.phase_index = i
                    break
    
    @property
    def elapsed_time(self) -> str:
        """Get formatted elapsed time"""
        elapsed = time.time() - self.start_time
        if elapsed < 60:
            return f"{elapsed:.1f}s"
        elif elapsed < 3600:
            mins = int(elapsed // 60)
            secs = int(elapsed % 60)
            return f"{mins}m {secs}s"
        else:
            hours = int(elapsed // 3600)
            mins = int((elapsed % 3600) // 60)
            return f"{hours}h {mins}m"
    
    def generate_display(self) -> Panel:
        """Generate the rich display panel"""
        if not RICH_AVAILABLE:
            return None
        
        # Create layout sections
        sections = []
        
        # Header with target and time
        header = Table(show_header=False, box=None, padding=(0, 1))
        header.add_column("Label", style="cyan", width=15)
        header.add_column("Value", style="white")
        header.add_row("🎯 Target", self.target_url[:60] + "..." if len(self.target_url) > 60 else self.target_url)
        header.add_row("⏱️  Elapsed", f"[bold]{self.elapsed_time}[/bold]")
        header.add_row("🤖 AI Mode", "[green]ENABLED[/green]" if self.ai_enabled else "[dim]DISABLED[/dim]")
        sections.append(header)
        sections.append(Text(""))
        
        # Current phase with progress bar
        phase_name, phase_emoji, phase_start, phase_end = self.phases[min(self.phase_index, len(self.phases)-1)]
        
        # Calculate overall progress
        if self.phase_index < len(self.phases):
            phase_range = phase_end - phase_start
            within_phase = (self.phase_progress / 100) * phase_range if self.phase_progress else 0
            self.overall_progress = phase_start + within_phase
        
        progress_bar_width = 40
        filled = int((self.overall_progress / 100) * progress_bar_width)
        bar = "█" * filled + "░" * (progress_bar_width - filled)
        
        phase_display = Table(show_header=False, box=None, padding=(0, 1))
        phase_display.add_column("", width=60)
        phase_display.add_row(f"[bold cyan]{phase_emoji} Current Phase:[/bold cyan] [white]{self.current_phase}[/white]")
        phase_display.add_row(f"[cyan]{bar}[/cyan] [bold]{self.overall_progress:.0f}%[/bold]")
        
        if self.current_task:
            phase_display.add_row(f"[dim]└─ {self.current_task}[/dim]")
        if self.current_scanner:
            phase_display.add_row(f"[dim]   Scanner: {self.current_scanner}[/dim]")
        
        sections.append(phase_display)
        sections.append(Text(""))
        
        # Stats grid
        stats_table = Table(show_header=True, box=box.SIMPLE, padding=(0, 2))
        stats_table.add_column("Crawling", justify="center", style="cyan")
        stats_table.add_column("Scanning", justify="center", style="yellow")
        stats_table.add_column("Findings", justify="center", style="red" if self.vulns_found > 0 else "green")
        
        stats_table.add_row(
            f"📄 {self.urls_found} URLs\n📝 {self.forms_found} Forms",
            f"✓ {self.tasks_completed}/{self.tasks_total}\n🔧 {len(self.tech_stack)} techs",
            f"🚨 {self.vulns_found} total\n🔴 {self.vulns_by_severity['critical']} crit"
        )
        sections.append(stats_table)
        
        # Severity breakdown if we have findings
        if self.vulns_found > 0:
            sections.append(Text(""))
            
            sev_row = Text()
            sev_row.append("  Severity: ", style="bold")
            sev_row.append(f"🔴 {self.vulns_by_severity['critical']} ", style="red")
            sev_row.append(f"🟠 {self.vulns_by_severity['high']} ", style="orange1")
            sev_row.append(f"🟡 {self.vulns_by_severity['medium']} ", style="yellow")
            sev_row.append(f"🔵 {self.vulns_by_severity['low']} ", style="blue")
            sections.append(sev_row)
            
            # OWASP 2025 breakdown
            if self.vulns_by_owasp:
                owasp_row = Text()
                owasp_row.append("  OWASP 2025: ", style="bold")
                for cat_id, count in sorted(self.vulns_by_owasp.items()):
                    info = OWASP_2025_INFO.get(cat_id, {"emoji": "•", "color": "white"})
                    owasp_row.append(f"{info['emoji']}{cat_id}:{count} ", style=info['color'])
                sections.append(owasp_row)
        
        # Recent findings
        if self.recent_findings:
            sections.append(Text(""))
            sections.append(Text("  📋 Recent Findings:", style="bold"))
            for finding in self.recent_findings[:3]:
                if "CRITICAL" in finding:
                    color = "red"
                elif "HIGH" in finding:
                    color = "orange1"
                elif "MEDIUM" in finding:
                    color = "yellow"
                else:
                    color = "dim"
                sections.append(Text(f"     • {finding}", style=color))
        
        # AI stats if enabled
        if self.ai_enabled and (self.ai_calls > 0 or self.ai_filtered > 0):
            sections.append(Text(""))
            ai_row = Text()
            ai_row.append("  🤖 AI Stats: ", style="bold")
            ai_row.append(f"{self.ai_calls} analyzed, ", style="cyan")
            ai_row.append(f"{self.ai_filtered} filtered", style="green")
            sections.append(ai_row)
        
        # Combine all sections
        content = Group(*sections)
        
        return Panel(
            content,
            title="[bold blue]🛡️ VulnFlow Scanner - OWASP 2025[/bold blue]",
            subtitle=f"[dim]Press Ctrl+C to stop[/dim]",
            border_style="blue",
            padding=(1, 2)
        )


class ScanTimer:
    """Timer class to track scan duration and phase timings."""
    
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
║         AI-Enhanced Web Vulnerability Scanner v2.1.0                      ║
║                    OWASP Top 10 2025 Edition                              ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
    """
    if RICH_AVAILABLE:
        console.print(banner, style="bold blue")
    else:
        print(banner)


def get_owasp_category_id(vuln) -> Optional[str]:
    """Extract OWASP category ID from vulnerability"""
    owasp_cat = getattr(vuln, 'owasp_category', None)
    if owasp_cat:
        cat_value = owasp_cat.value if hasattr(owasp_cat, 'value') else str(owasp_cat)
        if ":" in cat_value:
            return cat_value.split(":")[0]
    return None


async def run_full_scan_with_live_status(
    target_url: str, 
    depth: int, 
    max_pages: int,
    verbose: bool = False,
    workers: int = 8,
    concurrent_targets: int = 15,
    rate_limit: float = 75.0,
    timeout: float = 30.0,
    timer: Optional[ScanTimer] = None,
    ai_enabled: bool = True,
    api_key: Optional[str] = None,
    smart_payloads: bool = True,
    confidence_threshold: float = 0.6,
    mode: str = 'full',
    show_remediation: bool = False,
    live_display: bool = True,
    update_interval: float = 0.5
) -> dict:
    """
    Run a complete scan with live status updates.
    
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
        api_key: Groq API key
        smart_payloads: Use AI-generated payloads
        confidence_threshold: Minimum confidence score
        mode: Scan mode
        show_remediation: Generate remediation advice
        live_display: Enable live status display
        update_interval: How often to update display (seconds)
    """
    if timer is None:
        timer = ScanTimer()
        timer.start()
    
    has_api_key = api_key or os.environ.get("GROQ_API_KEY")
    ai_mode = ai_enabled and has_api_key and ENHANCED_SCANNER_AVAILABLE
    
    # Initialize live status tracker
    status = LiveScanStatus(target_url, ai_mode)
    
    results = {
        "target": target_url,
        "target_url": target_url,
        "scan_time": datetime.now().isoformat(),
        "scan_date": datetime.now().isoformat(),
        "ai_enabled": ai_mode,
        "scan_mode": mode,
        "owasp_version": "2025",
        "confidence_threshold": confidence_threshold if ai_mode else None,
        "vulnerabilities": [],
        "tech_stack": {},
        "remediations": {},
        "pages_scanned": 0,
        "forms_tested": 0,
        "scan_stats": {},
        "timing": {},
        "owasp_breakdown": {}
    }
    
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
    
    async def update_live_display(live: Live):
        """Background task to update the live display"""
        while True:
            live.update(status.generate_display())
            await asyncio.sleep(update_interval)
    
    async def run_scan_phases():
        """Run all scan phases"""
        nonlocal results
        
        # Phase 1: Crawling
        timer.start_phase("Crawling")
        status.set_phase("Crawling")
        status.update(current_task="Initializing crawler...")
        
        crawler = AsyncWebCrawler(target_url, depth, max_pages)
        
        # Hook into crawler progress if available
        async def crawl_with_updates():
            nonlocal status
            crawl_results = await crawler.crawl()
            return crawl_results
        
        crawl_results = await crawl_with_updates()
        
        results["pages_scanned"] = len(crawl_results.get("urls", {}))
        results["forms_tested"] = len(crawl_results.get("forms", []))
        status.update(
            urls_found=results["pages_scanned"],
            forms_found=results["forms_tested"],
            phase_progress=100,
            current_task=f"Found {results['pages_scanned']} URLs, {results['forms_tested']} forms"
        )
        timer.end_phase()
        
        # Phase 2: Technology Detection
        timer.start_phase("Technology Detection")
        status.set_phase("Tech Detection")
        status.update(current_task="Fingerprinting technologies...", phase_progress=0)
        
        detector = TechnologyDetector()
        results["tech_stack"] = detector.detect_from_crawl_results(crawl_results)
        
        tech_list = list(results["tech_stack"].keys())
        status.update(
            tech_stack=tech_list,
            phase_progress=100,
            current_task=f"Detected {len(tech_list)} technologies"
        )
        timer.end_phase()
        
        # Phase 3: Vulnerability Scanning
        scan_phase_name = "AI-Enhanced Scanning" if ai_mode else "Vulnerability Scanning"
        timer.start_phase(scan_phase_name)
        status.set_phase("Scanning")
        status.update(current_task="Initializing scanners...", phase_progress=0)
        
        def scan_progress_callback(completed, total, message):
            """Callback for scanner progress updates"""
            progress = (completed / total * 100) if total > 0 else 0
            
            # Extract scanner name from message if possible
            scanner_name = ""
            if ":" in message:
                scanner_name = message.split(":")[0].strip()
            
            status.update(
                tasks_completed=completed,
                tasks_total=total,
                phase_progress=progress,
                current_task=message,
                current_scanner=scanner_name
            )
        
        if ai_mode:
            scanner = EnhancedVulnerabilityScanner(scan_config)
            
            if hasattr(scanner, 'set_progress_callback'):
                scanner.set_progress_callback(scan_progress_callback)
            
            vulnerabilities = await scanner.scan_async(crawl_results, tech_list)
            results["scan_stats"] = scanner.get_metrics() if hasattr(scanner, 'get_metrics') else {}
            
            # Update AI stats
            stats = results["scan_stats"]
            status.update(
                ai_calls=stats.get('total_ai_calls', 0),
                ai_filtered=stats.get('false_positives_filtered', 0)
            )
        else:
            scanner = VulnerabilityScanner(scan_config)
            scanner.set_progress_callback(scan_progress_callback)
            vulnerabilities = await scanner.scan_target(crawl_results)
            results["scan_stats"] = scanner.get_execution_stats()
        
        results["vulnerabilities"] = vulnerabilities
        
        # Update findings in status
        for vuln in vulnerabilities:
            severity = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
            owasp_cat = get_owasp_category_id(vuln)
            owasp_value = getattr(vuln, 'owasp_category', None)
            owasp_str = owasp_value.value if hasattr(owasp_value, 'value') else str(owasp_value) if owasp_value else None
            status.add_finding(vuln.vuln_type, severity, vuln.url, owasp_str)
        
        status.update(phase_progress=100, current_task=f"Found {len(vulnerabilities)} vulnerabilities")
        timer.end_phase()
        
        # Phase 4: Remediation Generation
        timer.start_phase("Remediation Generation")
        status.set_phase("Remediation")
        status.update(current_task="Generating remediation advice...", phase_progress=0)
        
        remediation_engine = RemediationEngine()
        for i, vuln in enumerate(results["vulnerabilities"]):
            advice = remediation_engine.get_remediation(vuln.vuln_type, tech_list if ai_mode else results["tech_stack"])
            if advice:
                results["remediations"][vuln.vuln_type] = advice
            
            progress = ((i + 1) / len(results["vulnerabilities"])) * 100 if results["vulnerabilities"] else 100
            status.update(phase_progress=progress)
        
        status.update(phase_progress=100, current_task="Complete!")
        timer.end_phase()
        
        if hasattr(scanner, 'shutdown'):
            scanner.shutdown()
        
        return results
    
    # Run with or without live display
    if RICH_AVAILABLE and live_display:
        # Use Live display for real-time updates
        with Live(status.generate_display(), console=console, refresh_per_second=2, transient=False) as live:
            # Create background update task
            update_task = asyncio.create_task(update_live_display(live))
            
            try:
                results = await run_scan_phases()
            finally:
                update_task.cancel()
                try:
                    await update_task
                except asyncio.CancelledError:
                    pass
                
                # Final update
                live.update(status.generate_display())
    else:
        # Run without live display (fallback)
        results = await run_scan_phases()
    
    # Stop timer and add timing to results
    timer.stop()
    results["timing"] = timer.get_summary()
    
    # Calculate OWASP breakdown
    owasp_breakdown = {}
    for vuln in results["vulnerabilities"]:
        cat_id = get_owasp_category_id(vuln)
        if cat_id:
            if cat_id not in owasp_breakdown:
                owasp_breakdown[cat_id] = {"count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
            owasp_breakdown[cat_id]["count"] += 1
            severity = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
            if severity in owasp_breakdown[cat_id]:
                owasp_breakdown[cat_id][severity] += 1
    
    results["owasp_breakdown"] = owasp_breakdown
    
    # Add AI metadata if applicable
    if ai_mode:
        results["ai_metadata"] = {
            "enabled": True,
            "smart_payloads": smart_payloads,
            "confidence_threshold": confidence_threshold,
            "model": "llama-3.3-70b-versatile"
        }
    
    return results


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
    ai_enabled: bool = True,
    api_key: Optional[str] = None,
    smart_payloads: bool = True,
    confidence_threshold: float = 0.6,
    mode: str = 'full',
    show_remediation: bool = False
) -> dict:
    """
    Run a complete scan (compatibility wrapper).
    """
    return await run_full_scan_with_live_status(
        target_url=target_url,
        depth=depth,
        max_pages=max_pages,
        verbose=verbose,
        workers=workers,
        concurrent_targets=concurrent_targets,
        rate_limit=rate_limit,
        timeout=timeout,
        timer=timer,
        ai_enabled=ai_enabled,
        api_key=api_key,
        smart_payloads=smart_payloads,
        confidence_threshold=confidence_threshold,
        mode=mode,
        show_remediation=show_remediation,
        live_display=True
    )


def display_results(results: dict, show_remediation: bool = False, show_stats: bool = False):
    """Display scan results with OWASP 2025 categorization"""
    vulns = results.get("vulnerabilities", [])
    stats = results.get("scan_stats", {})
    ai_mode = results.get("ai_enabled", False)
    owasp_breakdown = results.get("owasp_breakdown", {})
    
    if RICH_AVAILABLE:
        # Summary panel
        summary_text = f"""
[bold]Target:[/bold] {results.get('target', results.get('target_url', 'N/A'))}
[bold]Scan Time:[/bold] {results.get('scan_time', results.get('scan_date', 'N/A'))}
[bold]OWASP Version:[/bold] 2025
[bold]Pages Scanned:[/bold] {results.get('pages_scanned', 0)}
[bold]Forms Tested:[/bold] {results.get('forms_tested', 0)}
[bold]AI Enhanced:[/bold] {'Yes ✓' if ai_mode else 'No'}
[bold]Total Vulnerabilities:[/bold] {len(vulns)}
        """
        console.print(Panel(summary_text, title="📊 Scan Summary", border_style="blue"))
        
        # Severity breakdown
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in vulns:
            sev = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        severity_table = Table(title="🎯 Severity Breakdown", show_header=True)
        severity_table.add_column("Severity", style="bold")
        severity_table.add_column("Count", justify="center")
        severity_table.add_column("Bar", justify="left", width=20)
        
        severity_colors = {
            "critical": ("red", "🔴"),
            "high": ("orange1", "🟠"),
            "medium": ("yellow", "🟡"),
            "low": ("blue", "🔵"),
            "info": ("dim", "⚪")
        }
        
        max_count = max(severity_counts.values()) if severity_counts.values() else 1
        for sev, count in severity_counts.items():
            if count > 0:
                color, emoji = severity_colors.get(sev, ("white", "•"))
                bar_width = int((count / max_count) * 15) if max_count > 0 else 0
                bar = "█" * bar_width
                severity_table.add_row(
                    f"[{color}]{emoji} {sev.upper()}[/{color}]",
                    str(count),
                    f"[{color}]{bar}[/{color}]"
                )
        
        console.print(severity_table)
        console.print()
        
        # OWASP 2025 breakdown
        if owasp_breakdown:
            owasp_table = Table(title="📋 OWASP Top 10 2025 Breakdown", show_header=True)
            owasp_table.add_column("Category", style="bold", width=35)
            owasp_table.add_column("Count", justify="center", width=8)
            owasp_table.add_column("Crit", justify="center", width=6, style="red")
            owasp_table.add_column("High", justify="center", width=6, style="orange1")
            owasp_table.add_column("Med", justify="center", width=6, style="yellow")
            owasp_table.add_column("Low", justify="center", width=6, style="blue")
            
            for cat_id in sorted(owasp_breakdown.keys()):
                data = owasp_breakdown[cat_id]
                info = OWASP_2025_INFO.get(cat_id, {"name": "Unknown", "emoji": "•", "color": "white"})
                
                owasp_table.add_row(
                    f"[{info['color']}]{info['emoji']} {cat_id}: {info['name']}[/{info['color']}]",
                    str(data['count']),
                    str(data['critical']) if data['critical'] > 0 else "-",
                    str(data['high']) if data['high'] > 0 else "-",
                    str(data['medium']) if data['medium'] > 0 else "-",
                    str(data['low']) if data['low'] > 0 else "-"
                )
            
            console.print(owasp_table)
            console.print()
        
        # Performance stats if requested
        if show_stats and stats:
            stats_table = Table(title="⚡ Execution Statistics")
            stats_table.add_column("Metric", style="cyan")
            stats_table.add_column("Value", justify="right")
            
            if ai_mode:
                stats_table.add_row("AI Enhanced Findings", str(stats.get('ai_enhanced_findings', 0)))
                stats_table.add_row("False Positives Filtered", str(stats.get('false_positives_filtered', 0)))
                stats_table.add_row("Total AI Calls", str(stats.get('total_ai_calls', 0)))
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
        
        # Vulnerability details (top 10)
        if vulns:
            vuln_table = Table(title="🔍 Vulnerability Details (Top 10)", show_header=True, show_lines=True)
            vuln_table.add_column("#", style="dim", width=3)
            vuln_table.add_column("Type", style="bold", width=30)
            vuln_table.add_column("Severity", justify="center", width=10)
            vuln_table.add_column("OWASP", width=8)
            vuln_table.add_column("URL", width=40, overflow="ellipsis")
            
            for i, vuln in enumerate(vulns[:10], 1):
                sev = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
                color, emoji = severity_colors.get(sev.lower(), ("white", "•"))
                
                cat_id = get_owasp_category_id(vuln) or "N/A"
                owasp_info = OWASP_2025_INFO.get(cat_id, {"color": "dim"})
                
                vuln_table.add_row(
                    str(i),
                    vuln.vuln_type[:30],
                    f"[{color}]{emoji} {sev.upper()}[/{color}]",
                    f"[{owasp_info['color']}]{cat_id}[/{owasp_info['color']}]",
                    vuln.url[:40]
                )
            
            console.print(vuln_table)
            
            if len(vulns) > 10:
                console.print(f"[dim]... and {len(vulns) - 10} more vulnerabilities[/dim]")
            console.print()
        
    else:
        # Fallback without rich
        print("\n" + "="*60)
        print("SCAN RESULTS (OWASP 2025)")
        print("="*60)
        print(f"Target: {results.get('target', results.get('target_url', 'N/A'))}")
        print(f"Scan Time: {results.get('scan_time', results.get('scan_date', 'N/A'))}")
        print(f"OWASP Version: 2025")
        print(f"Pages Scanned: {results.get('pages_scanned', 0)}")
        print(f"Forms Tested: {results.get('forms_tested', 0)}")
        print(f"AI Enhanced: {'Yes' if ai_mode else 'No'}")
        print(f"Vulnerabilities: {len(vulns)}")
        
        if owasp_breakdown:
            print("\nOWASP 2025 Breakdown:")
            for cat_id in sorted(owasp_breakdown.keys()):
                data = owasp_breakdown[cat_id]
                info = OWASP_2025_INFO.get(cat_id, {"name": "Unknown"})
                print(f"  {cat_id}: {info['name']} - {data['count']} findings")
        
        print("-"*60)
        
        if vulns:
            for i, vuln in enumerate(vulns[:10], 1):
                sev = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
                cat_id = get_owasp_category_id(vuln) or "N/A"
                print(f"\n[{i}] {vuln.vuln_type}")
                print(f"    Severity: {sev.upper()}")
                print(f"    OWASP: {cat_id}")
                print(f"    URL: {vuln.url}")
                if vuln.parameter:
                    print(f"    Parameter: {vuln.parameter}")
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
@click.version_option(version="2.0.2")
def cli():
    """VulnFlow - AI-Enhanced Web Vulnerability Scanner (OWASP 2025)
    
    Features:
    - AI-powered vulnerability analysis with Groq LLM
    - Smart payload generation based on tech stack
    - False positive reduction with confidence scoring
    - Context-aware remediation advice
    - Real-time scan progress display
    - Parallel scanning for faster results
    - Complete OWASP Top 10 2025 coverage
    
    OWASP 2025 Key Changes:
    - A01: Broken Access Control (now includes SSRF)
    - A02: Security Misconfiguration (moved up)
    - A03: Software Supply Chain Failures (expanded)
    - A10: Mishandling of Exceptional Conditions (NEW)
    
    Set GROQ_API_KEY environment variable to enable AI features.
    """
    pass


@cli.command()
@click.argument('target_url')
@click.option('--depth', '-d', default=2, help='Maximum crawl depth (default: 2)')
@click.option('--max-pages', '-m', default=50, help='Maximum pages to crawl (default: 50)')
@click.option('--output', '-o', default=None, help='Output file path')
@click.option('--format', '-f', 'output_format', 
              type=click.Choice(['json', 'html', 'sarif', 'markdown']), 
              default='json', help='Report format (default: json)')
@click.option('--fail-on', 
              type=click.Choice(['critical', 'high', 'medium', 'any', 'none']),
              default='critical', help='Severity threshold for non-zero exit (default: critical)')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--remediation', '-r', is_flag=True, help='Show remediation advice')
# AI-specific options
@click.option('--no-ai', is_flag=True, help='Disable AI-powered analysis')
@click.option('--api-key', default=None, help='Groq API key (overrides GROQ_API_KEY env var)')
@click.option('--smart-payloads/--no-smart-payloads', default=True, help='Use AI-generated payloads')
@click.option('--confidence-threshold', default=0.6, type=float, help='Minimum confidence (0.0-1.0)')
# Scan mode options
@click.option('--mode', type=click.Choice(['quick', 'standard', 'owasp', 'owasp2025', 'full', 'api', 'injection', 'auth', 'supply_chain', 'resilience']), 
              default='full', help='Scan mode (default: full)')
# Performance options
@click.option('--workers', '-w', default=8, help='Concurrent scanner workers (default: 8)')
@click.option('--concurrent-targets', '-c', default=15, help='Concurrent targets (default: 15)')
@click.option('--rate-limit', default=75.0, help='Max requests/second (default: 75)')
@click.option('--timeout', '-t', default=30.0, help='Timeout per scan (default: 30)')
# Display options
@click.option('--stats', is_flag=True, help='Show execution statistics')
@click.option('--timing', is_flag=True, help='Show detailed timing breakdown')
@click.option('--no-timing', is_flag=True, help='Hide timing information')
@click.option('--no-live', is_flag=True, help='Disable live status updates')
@click.option('--update-interval', default=0.5, type=float, help='Live update interval in seconds')
def scan(target_url, depth, max_pages, output, output_format, fail_on, verbose, 
         remediation, no_ai, api_key, smart_payloads, confidence_threshold,
         mode, workers, concurrent_targets, rate_limit, timeout, 
         stats, timing, no_timing, no_live, update_interval):
    """Scan a target URL for vulnerabilities (OWASP 2025)
    
    Examples:
    
        vulnflow scan http://example.com
        
        vulnflow scan http://example.com -d 3 -m 100 -o report.html -f html
        
        vulnflow scan http://example.com --fail-on high --verbose
        
        # OWASP 2025 focused scan
        vulnflow scan http://example.com --mode owasp2025
        
        # Supply chain focused scan (A03:2025)
        vulnflow scan http://example.com --mode supply_chain
        
        # Test error handling (A10:2025)
        vulnflow scan http://example.com --mode resilience
        
        # Disable live updates for CI/CD
        vulnflow scan http://example.com --no-live
        
        # Faster live updates
        vulnflow scan http://example.com --update-interval 0.25
    """
    ai_enabled = not no_ai
    has_api_key = api_key or os.environ.get("GROQ_API_KEY")
    ai_mode = ai_enabled and has_api_key and ENHANCED_SCANNER_AVAILABLE
    
    print_banner()
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    # Map 'owasp' mode to 'owasp2025' for clarity
    if mode == 'owasp':
        mode = 'owasp2025'
    
    if RICH_AVAILABLE and not no_live:
        # Display scan configuration briefly before live display takes over
        config_table = Table(show_header=False, box=None, padding=(0, 1))
        config_table.add_column("Setting", style="cyan")
        config_table.add_column("Value", style="white")
        
        config_table.add_row("Target URL", target_url)
        config_table.add_row("Scan Mode", f"{mode.upper()} (OWASP 2025)")
        config_table.add_row("AI Mode", "[green]✓ ENABLED[/green]" if ai_mode else "[yellow]✗ DISABLED[/yellow]")
        config_table.add_row("Live Display", "[green]✓ ON[/green]" if not no_live else "[dim]OFF[/dim]")
        
        console.print(config_table)
        console.print()
        console.print("[dim]Starting scan with live status updates...[/dim]\n")
    else:
        print(f"\nTarget: {target_url}")
        print(f"Scan Mode: {mode.upper()} (OWASP 2025)")
        print(f"AI Mode: {'ENABLED' if ai_mode else 'DISABLED'}")
        print()
    
    # Initialize timer
    scan_timer = ScanTimer()
    scan_timer.start()
    
    # Run scan
    try:
        results = asyncio.run(run_full_scan_with_live_status(
            target_url, 
            depth, 
            max_pages, 
            verbose,
            workers=workers,
            concurrent_targets=concurrent_targets,
            rate_limit=rate_limit,
            timeout=timeout,
            timer=scan_timer,
            ai_enabled=ai_enabled,
            api_key=api_key,
            smart_payloads=smart_payloads,
            confidence_threshold=confidence_threshold,
            mode=mode,
            show_remediation=remediation,
            live_display=not no_live,
            update_interval=update_interval
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
    
    scan_timer.stop()
    
    # Clear line after live display
    if RICH_AVAILABLE and not no_live:
        console.print()
    
    # Display results
    display_results(results, show_remediation=remediation, show_stats=stats)
    
    # Display timing information
    if not no_timing:
        if timing:
            display_timing(scan_timer, results)
        else:
            if RICH_AVAILABLE:
                console.print(f"\n[bold cyan]⏱️  Total scan time:[/bold cyan] [bold white]{scan_timer.total_duration_formatted}[/bold white]")
            else:
                print(f"\nTotal scan time: {scan_timer.total_duration_formatted}")
    
    # Generate and save report
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
        elif output_format == 'markdown':
            report_content = generator.generate_markdown_report(results)
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
            console.print(f"[dim]OWASP Version: 2025[/dim]")
            console.print(f"[dim]API docs available at: http://{host}:{port}/docs[/dim]\n")
        else:
            print(f"\nStarting VulnFlow API server on {host}:{port}")
            print(f"OWASP Version: 2025")
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
        console.print("\n[bold]VulnFlow[/bold] version 2.1.0")
        console.print("[dim]AI-Enhanced Web Vulnerability Scanner - OWASP 2025 Edition[/dim]")
        console.print()
        console.print("[bold]Features:[/bold]")
        console.print("  • AI-powered vulnerability analysis (Groq LLM)")
        console.print("  • Smart payload generation based on tech stack")
        console.print("  • False positive reduction with confidence scoring")
        console.print("  • Context-aware remediation advice")
        console.print("  • Real-time scan progress display")
        console.print("  • Parallel scanning for faster results")
        console.print("  • [bold cyan]Complete OWASP Top 10 2025 coverage[/bold cyan]")
        console.print()
        
        console.print("[bold]OWASP 2025 New Features:[/bold]")
        console.print("  • A01: SSRF now included in Broken Access Control")
        console.print("  • A03: Supply Chain scanners (dependencies, SRI)")
        console.print("  • A10: Exceptional Conditions (error handling, fail-open)")
        console.print()
        
        console.print("[bold]Scanner Stats:[/bold]")
        console.print("  • Total Scanners: 35+")
        console.print("  • OWASP Categories Covered: 10/10")
        console.print("  • New in 2025: 6 scanners")
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
        
        console.print()
        console.print("[bold]Quick Start:[/bold]")
        console.print("  [cyan]vulnflow scan http://target.com[/cyan]")
        console.print("  [cyan]vulnflow scan http://target.com --mode owasp2025[/cyan]")
        console.print("  [cyan]vulnflow owasp-info[/cyan]  # View OWASP 2025 details")
        console.print("  [cyan]vulnflow list-scanners[/cyan]  # View all scanners")
        
    else:
        print("\nVulnFlow version 2.1.0")
        print("AI-Enhanced Web Vulnerability Scanner - OWASP 2025 Edition")
        print()
        print("Features:")
        print("  • AI-powered vulnerability analysis")
        print("  • Smart payload generation based on tech stack")
        print("  • False positive reduction with confidence scoring")
        print("  • Context-aware remediation advice")
        print("  • Real-time scan progress display")
        print("  • Parallel scanning for faster results")
        print("  • Complete OWASP Top 10 2025 coverage")
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