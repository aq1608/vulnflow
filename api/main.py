# websec/api/main.py
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict
import uuid
import asyncio

# Import from project modules
from crawler.spider import AsyncWebCrawler
from scanner.vuln_scanner import VulnerabilityScanner
from detector.tech_fingerprint import TechnologyDetector
from remediation.engine import RemediationEngine
from reports.generator import ReportGenerator

app = FastAPI(
    title="VulnFlow API",
    description="Web Vulnerability Scanner with Contextual Remediation",
    version="1.0.0"
)

# Request/Response models
class ScanRequest(BaseModel):
    target_url: HttpUrl
    scan_depth: int = 3
    max_pages: int = 100

class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: float
    findings_count: int

class ScanListItem(BaseModel):
    scan_id: str
    target: str
    status: str
    findings_count: int

# In-memory store (use Redis in production)
scans: Dict[str, dict] = {}


@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "message": "VulnFlow API",
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy"}


@app.post("/api/v1/scans", response_model=ScanStatus)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Initiate a new security scan"""
    scan_id = str(uuid.uuid4())
    
    scans[scan_id] = {
        "status": "queued",
        "progress": 0.0,
        "target": str(request.target_url),
        "config": request.dict(),
        "results": None,
        "error": None
    }
    
    background_tasks.add_task(run_scan, scan_id, request)
    
    return ScanStatus(
        scan_id=scan_id,
        status="queued",
        progress=0.0,
        findings_count=0
    )


@app.get("/api/v1/scans", response_model=List[ScanListItem])
async def list_scans():
    """List all scans"""
    scan_list = []
    for scan_id, scan_data in scans.items():
        findings_count = 0
        if scan_data.get("results"):
            findings_count = len(scan_data["results"].get("vulnerabilities", []))
        
        scan_list.append(ScanListItem(
            scan_id=scan_id,
            target=scan_data["target"],
            status=scan_data["status"],
            findings_count=findings_count
        ))
    
    return scan_list


@app.get("/api/v1/scans/{scan_id}", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    """Get scan status"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = scans[scan_id]
    findings_count = 0
    if scan.get("results"):
        findings_count = len(scan["results"].get("vulnerabilities", []))
    
    return ScanStatus(
        scan_id=scan_id,
        status=scan["status"],
        progress=scan["progress"],
        findings_count=findings_count
    )


@app.get("/api/v1/scans/{scan_id}/results")
async def get_scan_results(scan_id: str, format: str = "json"):
    """Get scan results in specified format (json, html, sarif)"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = scans[scan_id]
    
    if scan["status"] == "failed":
        raise HTTPException(status_code=500, detail=scan.get("error", "Scan failed"))
    
    if scan["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed yet")
    
    generator = ReportGenerator()
    results = scan["results"]
    
    if format == "html":
        html_content = generator.generate_html_report(results)
        return HTMLResponse(content=html_content)
    elif format == "sarif":
        sarif_content = generator.generate_sarif_report(results)
        return JSONResponse(content=json.loads(sarif_content))
    else:
        json_content = generator.generate_json_report(results)
        return JSONResponse(content=json.loads(json_content))


@app.delete("/api/v1/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    del scans[scan_id]
    return {"message": "Scan deleted successfully"}


async def run_scan(scan_id: str, request: ScanRequest):
    """Background task to run the scan"""
    try:
        scans[scan_id]["status"] = "running"
        
        # Phase 1: Crawl
        scans[scan_id]["progress"] = 0.1
        crawler = AsyncWebCrawler(
            str(request.target_url),
            request.scan_depth,
            request.max_pages
        )
        crawl_results = await crawler.crawl()
        
        # Phase 2: Detect technology
        scans[scan_id]["progress"] = 0.3
        detector = TechnologyDetector()
        tech_stack = detector.detect_from_crawl_results(crawl_results)
        
        # Phase 3: Scan for vulnerabilities
        scans[scan_id]["progress"] = 0.5
        scanner = VulnerabilityScanner()
        vulnerabilities = await scanner.scan_target(crawl_results)
        
        # Phase 4: Generate remediations
        scans[scan_id]["progress"] = 0.8
        remediation_engine = RemediationEngine()
        remediations = {}
        for vuln in vulnerabilities:
            advice = remediation_engine.get_remediation(vuln.vuln_type, tech_stack)
            if advice:
                remediations[vuln.vuln_type] = [
                    {
                        "framework": a.framework,
                        "description": a.description,
                        "code_example": a.code_example,
                        "references": a.references
                    }
                    for a in advice
                ]
        
        # Complete
        scans[scan_id]["results"] = {
            "target": str(request.target_url),
            "vulnerabilities": vulnerabilities,
            "tech_stack": tech_stack,
            "remediations": remediations,
            "pages_scanned": len(crawl_results.get("urls", {})),
            "forms_tested": len(crawl_results.get("forms", []))
        }
        scans[scan_id]["status"] = "completed"
        scans[scan_id]["progress"] = 1.0
        
    except Exception as e:
        scans[scan_id]["status"] = "failed"
        scans[scan_id]["error"] = str(e)


# Import json for responses
import json

# Run with: uvicorn websec.api.main:app --reload
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)