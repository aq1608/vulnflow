# api/main.py
"""
VulnFlow API Server
Web Vulnerability Scanner with Contextual Remediation
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import uuid
import asyncio
import time
import json

# Import from project modules
from crawler.spider import AsyncWebCrawler
from scanner.vuln_scanner import VulnerabilityScanner
from detector.tech_fingerprint import TechnologyDetector
from remediation.engine import RemediationEngine
from reports.generator import ReportGenerator


# ============================================================================
# Application Setup
# ============================================================================

app = FastAPI(
    title="VulnFlow API",
    description="""
## Web Vulnerability Scanner with Contextual Remediation

VulnFlow provides comprehensive web application security scanning with:

- **Parallel Scanning Engine** - Concurrent vulnerability testing
- **OWASP Top 10 Coverage** - Complete coverage of OWASP Top 10 2021
- **12 Security Modules** - SQLi, XSS, SSRF, IDOR, and more
- **Smart Crawling** - Async web crawler with form detection
- **Technology Detection** - Automatic fingerprinting
- **Contextual Remediation** - Framework-specific fixes
- **Performance Metrics** - Detailed timing and statistics

### Quick Start

1. Create a scan: `POST /api/v1/scans`
2. Check status: `GET /api/v1/scans/{scan_id}`
3. Get results: `GET /api/v1/scans/{scan_id}/results`
    """,
    version="1.0.4",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Enums and Models
# ============================================================================

class ScanMode(str, Enum):
    """Scan mode options"""
    QUICK = "quick"
    OWASP = "owasp"
    FULL = "full"


class ScanStatus(str, Enum):
    """Scan status options"""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ReportFormat(str, Enum):
    """Report format options"""
    JSON = "json"
    HTML = "html"
    SARIF = "sarif"


class ParallelConfig(BaseModel):
    """Parallel execution configuration"""
    enabled: bool = Field(default=True, description="Enable parallel scanning")
    workers: int = Field(default=5, ge=1, le=50, description="Number of concurrent scanner workers")
    concurrent_targets: int = Field(default=10, ge=1, le=100, description="Number of concurrent targets")
    rate_limit: float = Field(default=50.0, ge=1.0, le=500.0, description="Max requests per second")
    fast_mode: bool = Field(default=False, description="Enable fast worker pool mode")


class ScanConfig(BaseModel):
    """Scan configuration options"""
    mode: ScanMode = Field(default=ScanMode.FULL, description="Scan mode")
    depth: int = Field(default=2, ge=1, le=10, description="Maximum crawl depth")
    max_pages: int = Field(default=50, ge=1, le=1000, description="Maximum pages to crawl")
    timeout: float = Field(default=30.0, ge=5.0, le=120.0, description="Timeout per scan in seconds")
    modules: Optional[List[str]] = Field(default=None, description="Specific modules to run")
    parallel: ParallelConfig = Field(default_factory=ParallelConfig, description="Parallel execution settings")


class ScanRequest(BaseModel):
    """Request model for creating a new scan"""
    target_url: HttpUrl = Field(..., description="Target URL to scan")
    config: ScanConfig = Field(default_factory=ScanConfig, description="Scan configuration")
    
    class Config:
        schema_extra = {
            "example": {
                "target_url": "http://example.com",
                "config": {
                    "mode": "owasp",
                    "depth": 3,
                    "max_pages": 100,
                    "timeout": 30,
                    "parallel": {
                        "enabled": True,
                        "workers": 10,
                        "concurrent_targets": 20,
                        "rate_limit": 50,
                        "fast_mode": False
                    }
                }
            }
        }


class TimingInfo(BaseModel):
    """Timing information for a scan"""
    total_duration: float = Field(..., description="Total scan duration in seconds")
    total_formatted: str = Field(..., description="Human-readable duration")
    phases: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="Phase-by-phase timing")


class ScanStats(BaseModel):
    """Execution statistics"""
    total_tasks: int = Field(default=0, description="Total scan tasks")
    completed_tasks: int = Field(default=0, description="Completed tasks")
    failed_tasks: int = Field(default=0, description="Failed tasks")
    total_duration: float = Field(default=0.0, description="Total execution time")
    throughput: Optional[float] = Field(default=None, description="Tasks per second")


class ScanStatusResponse(BaseModel):
    """Response model for scan status"""
    scan_id: str = Field(..., description="Unique scan identifier")
    status: ScanStatus = Field(..., description="Current scan status")
    progress: float = Field(..., ge=0.0, le=1.0, description="Scan progress (0-1)")
    target: str = Field(..., description="Target URL")
    findings_count: int = Field(default=0, description="Number of vulnerabilities found")
    current_phase: Optional[str] = Field(default=None, description="Current scan phase")
    timing: Optional[TimingInfo] = Field(default=None, description="Timing information")
    created_at: str = Field(..., description="Scan creation timestamp")
    updated_at: str = Field(..., description="Last update timestamp")


class ScanListItem(BaseModel):
    """List item for scan listing"""
    scan_id: str
    target: str
    status: ScanStatus
    progress: float
    findings_count: int
    created_at: str


class VulnerabilityItem(BaseModel):
    """Vulnerability item in results"""
    vuln_type: str
    severity: str
    url: str
    parameter: Optional[str]
    description: str
    evidence: Optional[str]
    cwe_id: Optional[str]
    payload: Optional[str]


class ScanResultsResponse(BaseModel):
    """Response model for scan results"""
    scan_id: str
    target: str
    status: ScanStatus
    vulnerabilities: List[VulnerabilityItem]
    tech_stack: Dict[str, Any]
    remediations: Dict[str, List[Dict[str, Any]]]
    pages_scanned: int
    forms_tested: int
    timing: TimingInfo
    stats: ScanStats
    created_at: str
    completed_at: Optional[str]


class ErrorResponse(BaseModel):
    """Error response model"""
    detail: str
    error_code: Optional[str] = None


# ============================================================================
# Timer Class (from cli/main.py)
# ============================================================================

class ScanTimer:
    """Timer class to track scan duration and phase timings"""
    
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
    
    @property
    def current_phase(self) -> Optional[str]:
        """Get current phase name"""
        return self._current_phase


# ============================================================================
# In-Memory Store (use Redis/Database in production)
# ============================================================================

scans: Dict[str, dict] = {}


# ============================================================================
# Helper Functions
# ============================================================================

def get_scan_or_404(scan_id: str) -> dict:
    """Get scan by ID or raise 404"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans[scan_id]


def serialize_vulnerability(vuln) -> dict:
    """Serialize a Vulnerability object to dict"""
    return {
        "vuln_type": vuln.vuln_type,
        "severity": vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity),
        "url": vuln.url,
        "parameter": vuln.parameter,
        "description": vuln.description,
        "evidence": vuln.evidence[:200] if vuln.evidence else None,
        "cwe_id": vuln.cwe_id,
        "payload": vuln.payload[:100] if vuln.payload else None
    }


def get_enabled_modules(mode: ScanMode, custom_modules: Optional[List[str]] = None) -> Optional[List[str]]:
    """Get enabled modules based on scan mode"""
    if custom_modules:
        return custom_modules
    
    if mode == ScanMode.QUICK:
        return ['sqli', 'xss', 'headers', 'cors']
    elif mode == ScanMode.OWASP:
        return None  # All modules
    else:  # FULL
        return None  # All modules


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/", tags=["General"])
async def root():
    """
    API root endpoint.
    
    Returns basic API information and links to documentation.
    """
    return {
        "name": "VulnFlow API",
        "version": "1.0.4",
        "description": "Web Vulnerability Scanner with Contextual Remediation",
        "features": [
            "Parallel scanning engine",
            "OWASP Top 10 coverage",
            "12 security modules",
            "Technology detection",
            "Contextual remediation",
            "Multiple report formats"
        ],
        "endpoints": {
            "docs": "/docs",
            "redoc": "/redoc",
            "health": "/health",
            "scans": "/api/v1/scans"
        }
    }


@app.get("/health", tags=["General"])
async def health_check():
    """
    Health check endpoint.
    
    Returns the health status of the API server.
    """
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.4",
        "active_scans": len([s for s in scans.values() if s["status"] == ScanStatus.RUNNING])
    }


@app.get("/api/v1/modules", tags=["Configuration"])
async def list_modules():
    """
    List all available scanner modules.
    
    Returns information about each security module including
    its OWASP category and description.
    """
    scanner = VulnerabilityScanner()
    return {
        "modules": scanner.get_scanner_info(),
        "scan_modes": {
            "quick": {
                "description": "Fast security check",
                "modules": ["sqli", "xss", "headers", "cors"]
            },
            "owasp": {
                "description": "OWASP Top 10 focused scan",
                "modules": "all"
            },
            "full": {
                "description": "Complete security audit",
                "modules": "all"
            }
        }
    }


@app.post(
    "/api/v1/scans",
    response_model=ScanStatusResponse,
    status_code=201,
    tags=["Scans"],
    responses={
        201: {"description": "Scan created successfully"},
        400: {"model": ErrorResponse, "description": "Invalid request"},
        422: {"model": ErrorResponse, "description": "Validation error"}
    }
)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Create and start a new security scan.
    
    This endpoint initiates an asynchronous vulnerability scan against the
    specified target URL. The scan runs in the background and can be monitored
    using the status endpoint.
    
    **Scan Modes:**
    - `quick`: Fast scan with essential checks (SQLi, XSS, Headers, CORS)
    - `owasp`: OWASP Top 10 focused comprehensive scan
    - `full`: Complete security audit with all modules
    
    **Parallel Execution:**
    Configure parallel scanning for faster results:
    - `workers`: Number of concurrent scanner workers (1-50)
    - `concurrent_targets`: Number of targets scanned simultaneously (1-100)
    - `rate_limit`: Maximum requests per second to avoid blocking
    - `fast_mode`: Enable aggressive parallelization
    
    **Example Request:**
    ```json
    {
        "target_url": "http://example.com",
        "config": {
            "mode": "owasp",
            "depth": 3,
            "max_pages": 100,
            "parallel": {
                "enabled": true,
                "workers": 10,
                "fast_mode": true
            }
        }
    }
    ```
    """
    scan_id = str(uuid.uuid4())
    now = datetime.now().isoformat()
    
    scans[scan_id] = {
        "status": ScanStatus.QUEUED,
        "progress": 0.0,
        "target": str(request.target_url),
        "config": request.config.dict(),
        "results": None,
        "error": None,
        "current_phase": None,
        "timing": None,
        "stats": None,
        "created_at": now,
        "updated_at": now,
        "completed_at": None
    }
    
    # Add background task
    background_tasks.add_task(run_scan, scan_id, request)
    
    return ScanStatusResponse(
        scan_id=scan_id,
        status=ScanStatus.QUEUED,
        progress=0.0,
        target=str(request.target_url),
        findings_count=0,
        current_phase=None,
        timing=None,
        created_at=now,
        updated_at=now
    )


@app.get(
    "/api/v1/scans",
    response_model=List[ScanListItem],
    tags=["Scans"]
)
async def list_scans(
    status: Optional[ScanStatus] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=100, description="Maximum items to return"),
    offset: int = Query(0, ge=0, description="Number of items to skip")
):
    """
    List all scans with optional filtering.
    
    Returns a paginated list of all scans with basic information.
    Use the status parameter to filter by scan status.
    """
    scan_list = []
    
    for scan_id, scan_data in scans.items():
        # Apply status filter
        if status and scan_data["status"] != status:
            continue
        
        findings_count = 0
        if scan_data.get("results"):
            vulns = scan_data["results"].get("vulnerabilities", [])
            findings_count = len(vulns) if isinstance(vulns, list) else 0
        
        scan_list.append(ScanListItem(
            scan_id=scan_id,
            target=scan_data["target"],
            status=scan_data["status"],
            progress=scan_data["progress"],
            findings_count=findings_count,
            created_at=scan_data["created_at"]
        ))
    
    # Sort by creation time (newest first)
    scan_list.sort(key=lambda x: x.created_at, reverse=True)
    
    # Apply pagination
    return scan_list[offset:offset + limit]


@app.get(
    "/api/v1/scans/{scan_id}",
    response_model=ScanStatusResponse,
    tags=["Scans"],
    responses={
        404: {"model": ErrorResponse, "description": "Scan not found"}
    }
)
async def get_scan_status(scan_id: str):
    """
    Get the current status of a scan.
    
    Returns detailed status information including:
    - Current progress (0-1)
    - Current phase being executed
    - Number of findings so far
    - Timing information (if available)
    """
    scan = get_scan_or_404(scan_id)
    
    findings_count = 0
    if scan.get("results"):
        vulns = scan["results"].get("vulnerabilities", [])
        findings_count = len(vulns) if isinstance(vulns, list) else 0
    
    timing_info = None
    if scan.get("timing"):
        timing_info = TimingInfo(**scan["timing"])
    
    return ScanStatusResponse(
        scan_id=scan_id,
        status=scan["status"],
        progress=scan["progress"],
        target=scan["target"],
        findings_count=findings_count,
        current_phase=scan.get("current_phase"),
        timing=timing_info,
        created_at=scan["created_at"],
        updated_at=scan["updated_at"]
    )


@app.get(
    "/api/v1/scans/{scan_id}/results",
    tags=["Scans"],
    responses={
        200: {"description": "Scan results"},
        400: {"model": ErrorResponse, "description": "Scan not completed"},
        404: {"model": ErrorResponse, "description": "Scan not found"},
        500: {"model": ErrorResponse, "description": "Scan failed"}
    }
)
async def get_scan_results(
    scan_id: str,
    format: ReportFormat = Query(ReportFormat.JSON, description="Output format")
):
    """
    Get scan results in the specified format.
    
    **Available Formats:**
    - `json`: Structured JSON data (default)
    - `html`: Formatted HTML report
    - `sarif`: SARIF format for CI/CD integration
    
    The results include:
    - All discovered vulnerabilities with details
    - Detected technology stack
    - Remediation advice for each vulnerability type
    - Performance metrics and timing information
    """
    scan = get_scan_or_404(scan_id)
    
    if scan["status"] == ScanStatus.FAILED:
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {scan.get('error', 'Unknown error')}"
        )
    
    if scan["status"] != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail=f"Scan not completed. Current status: {scan['status']}"
        )
    
    results = scan["results"]
    
    # Add timing and stats to results
    results["timing"] = scan.get("timing", {})
    results["stats"] = scan.get("stats", {})
    results["scan_id"] = scan_id
    results["created_at"] = scan["created_at"]
    results["completed_at"] = scan.get("completed_at")
    
    generator = ReportGenerator()
    
    if format == ReportFormat.HTML:
        html_content = generator.generate_html_report(results)
        return HTMLResponse(content=html_content)
    
    elif format == ReportFormat.SARIF:
        sarif_content = generator.generate_sarif_report(results)
        return JSONResponse(content=json.loads(sarif_content))
    
    else:  # JSON
        # Serialize vulnerabilities properly
        serialized_results = {
            "scan_id": scan_id,
            "target": results["target"],
            "status": scan["status"],
            "vulnerabilities": [
                serialize_vulnerability(v) if hasattr(v, 'vuln_type') else v
                for v in results.get("vulnerabilities", [])
            ],
            "tech_stack": results.get("tech_stack", {}),
            "remediations": results.get("remediations", {}),
            "pages_scanned": results.get("pages_scanned", 0),
            "forms_tested": results.get("forms_tested", 0),
            "timing": results.get("timing", {}),
            "stats": results.get("stats", {}),
            "created_at": scan["created_at"],
            "completed_at": scan.get("completed_at")
        }
        return JSONResponse(content=serialized_results)


@app.get(
    "/api/v1/scans/{scan_id}/timing",
    tags=["Scans"],
    responses={
        404: {"model": ErrorResponse, "description": "Scan not found"}
    }
)
async def get_scan_timing(scan_id: str):
    """
    Get detailed timing information for a scan.
    
    Returns performance metrics including:
    - Total scan duration
    - Phase-by-phase breakdown
    - Throughput statistics
    """
    scan = get_scan_or_404(scan_id)
    
    if not scan.get("timing"):
        return {
            "scan_id": scan_id,
            "status": scan["status"],
            "message": "Timing information not available yet"
        }
    
    timing = scan["timing"]
    stats = scan.get("stats", {})
    results = scan.get("results", {})
    
    # Calculate throughput metrics
    total_duration = timing.get("total_duration", 0)
    pages_scanned = results.get("pages_scanned", 0)
    forms_tested = results.get("forms_tested", 0)
    
    return {
        "scan_id": scan_id,
        "status": scan["status"],
        "timing": timing,
        "stats": stats,
        "throughput": {
            "pages_per_second": pages_scanned / total_duration if total_duration > 0 else 0,
            "forms_per_second": forms_tested / total_duration if total_duration > 0 else 0,
            "tasks_per_second": stats.get("completed_tasks", 0) / total_duration if total_duration > 0 else 0
        }
    }


@app.delete(
    "/api/v1/scans/{scan_id}",
    tags=["Scans"],
    responses={
        200: {"description": "Scan deleted successfully"},
        404: {"model": ErrorResponse, "description": "Scan not found"}
    }
)
async def delete_scan(scan_id: str):
    """
    Delete a scan and its results.
    
    This will remove all data associated with the scan.
    Running scans will be cancelled before deletion.
    """
    scan = get_scan_or_404(scan_id)
    
    # Mark as cancelled if still running
    if scan["status"] == ScanStatus.RUNNING:
        scan["status"] = ScanStatus.CANCELLED
    
    del scans[scan_id]
    
    return {
        "message": "Scan deleted successfully",
        "scan_id": scan_id
    }


@app.post(
    "/api/v1/scans/{scan_id}/cancel",
    tags=["Scans"],
    responses={
        200: {"description": "Scan cancelled successfully"},
        400: {"model": ErrorResponse, "description": "Scan cannot be cancelled"},
        404: {"model": ErrorResponse, "description": "Scan not found"}
    }
)
async def cancel_scan(scan_id: str):
    """
    Cancel a running scan.
    
    Only scans with status 'queued' or 'running' can be cancelled.
    """
    scan = get_scan_or_404(scan_id)
    
    if scan["status"] not in [ScanStatus.QUEUED, ScanStatus.RUNNING]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel scan with status: {scan['status']}"
        )
    
    scan["status"] = ScanStatus.CANCELLED
    scan["updated_at"] = datetime.now().isoformat()
    
    return {
        "message": "Scan cancelled successfully",
        "scan_id": scan_id,
        "status": ScanStatus.CANCELLED
    }


# ============================================================================
# Background Task: Run Scan
# ============================================================================

async def run_scan(scan_id: str, request: ScanRequest):
    """
    Background task to run the vulnerability scan.
    
    This function executes all scan phases:
    1. Web crawling
    2. Technology detection
    3. Vulnerability scanning (parallel)
    4. Remediation generation
    """
    timer = ScanTimer()
    timer.start()
    
    try:
        # Update status to running
        scans[scan_id]["status"] = ScanStatus.RUNNING
        scans[scan_id]["updated_at"] = datetime.now().isoformat()
        
        config = request.config
        target_url = str(request.target_url)
        
        # Build scanner configuration
        scanner_config = {
            'parallel': config.parallel.enabled,
            'max_concurrent_scanners': config.parallel.workers,
            'max_concurrent_targets': config.parallel.concurrent_targets,
            'requests_per_second': config.parallel.rate_limit,
            'timeout': config.timeout,
            'enabled_scanners': get_enabled_modules(config.mode, config.modules)
        }
        
        # ============================================
        # Phase 1: Crawling
        # ============================================
        timer.start_phase("Crawling")
        scans[scan_id]["current_phase"] = "Crawling"
        scans[scan_id]["progress"] = 0.1
        scans[scan_id]["updated_at"] = datetime.now().isoformat()
        
        # Check for cancellation
        if scans[scan_id]["status"] == ScanStatus.CANCELLED:
            return
        
        crawler = AsyncWebCrawler(target_url, config.depth, config.max_pages)
        crawl_results = await crawler.crawl()
        timer.end_phase()
        
        pages_scanned = len(crawl_results.get("urls", {}))
        forms_tested = len(crawl_results.get("forms", []))
        
        scans[scan_id]["progress"] = 0.25
        scans[scan_id]["updated_at"] = datetime.now().isoformat()
        
        # ============================================
        # Phase 2: Technology Detection
        # ============================================
        timer.start_phase("Technology Detection")
        scans[scan_id]["current_phase"] = "Technology Detection"
        scans[scan_id]["progress"] = 0.3
        scans[scan_id]["updated_at"] = datetime.now().isoformat()
        
        if scans[scan_id]["status"] == ScanStatus.CANCELLED:
            return
        
        detector = TechnologyDetector()
        tech_stack = detector.detect_from_crawl_results(crawl_results)
        timer.end_phase()
        
        scans[scan_id]["progress"] = 0.35
        scans[scan_id]["updated_at"] = datetime.now().isoformat()
        
        # ============================================
        # Phase 3: Vulnerability Scanning
        # ============================================
        timer.start_phase("Vulnerability Scanning")
        scans[scan_id]["current_phase"] = "Vulnerability Scanning"
        scans[scan_id]["progress"] = 0.4
        scans[scan_id]["updated_at"] = datetime.now().isoformat()
        
        if scans[scan_id]["status"] == ScanStatus.CANCELLED:
            return
        
        scanner = VulnerabilityScanner(scanner_config)
        
        # Progress callback for real-time updates
        def progress_callback(completed, total, message):
            if total > 0:
                # Map scanner progress to 40-80%
                pct = 0.4 + (completed / total) * 0.4
                scans[scan_id]["progress"] = pct
                scans[scan_id]["updated_at"] = datetime.now().isoformat()
        
        scanner.set_progress_callback(progress_callback)
        
        # Run scan (parallel or fast mode)
        if config.parallel.fast_mode:
            vulnerabilities = await scanner.scan_target_fast(crawl_results)
        else:
            vulnerabilities = await scanner.scan_target(crawl_results)
        
        # Get execution stats
        exec_stats = scanner.get_execution_stats()
        timer.end_phase()
        
        # Cleanup scanner
        scanner.shutdown()
        
        scans[scan_id]["progress"] = 0.85
        scans[scan_id]["updated_at"] = datetime.now().isoformat()
        
        # ============================================
        # Phase 4: Remediation Generation
        # ============================================
        timer.start_phase("Remediation Generation")
        scans[scan_id]["current_phase"] = "Remediation Generation"
        scans[scan_id]["progress"] = 0.9
        scans[scan_id]["updated_at"] = datetime.now().isoformat()
        
        if scans[scan_id]["status"] == ScanStatus.CANCELLED:
            return
        
        remediation_engine = RemediationEngine()
        remediations = {}
        
        for vuln in vulnerabilities:
            vuln_type = vuln.vuln_type if hasattr(vuln, 'vuln_type') else vuln.get('vuln_type')
            if vuln_type and vuln_type not in remediations:
                advice = remediation_engine.get_remediation(vuln_type, tech_stack)
                if advice:
                    remediations[vuln_type] = [
                        {
                            "framework": a.framework,
                            "description": a.description,
                            "code_example": a.code_example,
                            "references": a.references
                        }
                        for a in advice
                    ]
        
        timer.end_phase()
        
        # ============================================
        # Complete
        # ============================================
        timer.stop()
        
        # Calculate throughput
        throughput = None
        if exec_stats.get('total_duration', 0) > 0:
            throughput = exec_stats.get('completed_tasks', 0) / exec_stats['total_duration']
        
        scans[scan_id]["results"] = {
            "target": target_url,
            "vulnerabilities": vulnerabilities,
            "tech_stack": tech_stack,
            "remediations": remediations,
            "pages_scanned": pages_scanned,
            "forms_tested": forms_tested
        }
        
        scans[scan_id]["timing"] = timer.get_summary()
        scans[scan_id]["stats"] = {
            "total_tasks": exec_stats.get('total_tasks', 0),
            "completed_tasks": exec_stats.get('completed_tasks', 0),
            "failed_tasks": exec_stats.get('failed_tasks', 0),
            "total_duration": exec_stats.get('total_duration', 0),
            "throughput": throughput
        }
        
        scans[scan_id]["status"] = ScanStatus.COMPLETED
        scans[scan_id]["progress"] = 1.0
        scans[scan_id]["current_phase"] = None
        scans[scan_id]["completed_at"] = datetime.now().isoformat()
        scans[scan_id]["updated_at"] = datetime.now().isoformat()
        
    except Exception as e:
        timer.stop()
        scans[scan_id]["status"] = ScanStatus.FAILED
        scans[scan_id]["error"] = str(e)
        scans[scan_id]["timing"] = timer.get_summary()
        scans[scan_id]["updated_at"] = datetime.now().isoformat()


# ============================================================================
# WebSocket for Real-time Updates (Optional Enhancement)
# ============================================================================

from fastapi import WebSocket, WebSocketDisconnect
from typing import Set

# Active WebSocket connections
active_connections: Dict[str, Set[WebSocket]] = {}


@app.websocket("/ws/scans/{scan_id}")
async def websocket_scan_updates(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint for real-time scan updates.
    
    Connect to receive live progress updates for a specific scan.
    """
    await websocket.accept()
    
    # Register connection
    if scan_id not in active_connections:
        active_connections[scan_id] = set()
    active_connections[scan_id].add(websocket)
    
    try:
        while True:
            # Send current status
            if scan_id in scans:
                scan = scans[scan_id]
                await websocket.send_json({
                    "scan_id": scan_id,
                    "status": scan["status"],
                    "progress": scan["progress"],
                    "current_phase": scan.get("current_phase"),
                    "updated_at": scan["updated_at"]
                })
                
                # Close connection if scan is complete
                if scan["status"] in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]:
                    break
            else:
                await websocket.send_json({
                    "error": "Scan not found"
                })
                break
            
            await asyncio.sleep(1)  # Update every second
            
    except WebSocketDisconnect:
        pass
    finally:
        # Unregister connection
        if scan_id in active_connections:
            active_connections[scan_id].discard(websocket)


# ============================================================================
# Startup and Shutdown Events
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize resources on startup"""
    print("🚀 VulnFlow API starting up...")
    print("📚 API documentation available at /docs")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup resources on shutdown"""
    print("🛑 VulnFlow API shutting down...")
    # Cancel any running scans
    for scan_id, scan in scans.items():
        if scan["status"] == ScanStatus.RUNNING:
            scan["status"] = ScanStatus.CANCELLED


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )