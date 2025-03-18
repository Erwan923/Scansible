from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Query, Body, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
import uuid
import subprocess
import os
import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
import asyncio

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scansible")

# Define paths
BASE_DIR = Path(__file__).parent.parent
TEMPLATES_DIR = BASE_DIR / "scansible" / "templates"
REPORTS_DIR = BASE_DIR / "reports"
SCANS_DIR = BASE_DIR / "scans"

# Ensure directories exist
REPORTS_DIR.mkdir(exist_ok=True)
SCANS_DIR.mkdir(exist_ok=True)

# Create FastAPI app
app = FastAPI(
    title="Scansible API",
    description="API for Scansible - Automated Security Scanning Tool",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class ScanRequest(BaseModel):
    target: str
    scan_type: str = "basic"
    tags: List[str] = []
    generate_report: bool = True
    ai_enhanced_report: bool = False

    @validator('scan_type')
    def validate_scan_type(cls, v):
        allowed_types = ["basic", "web", "infrastructure", "passive", "rustscan", "trivy", "light"]
        if v not in allowed_types:
            raise ValueError(f"Scan type must be one of {allowed_types}")
        return v
    
    @validator('target')
    def validate_target(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError("Target cannot be empty")
        return v

class ScanStatus(BaseModel):
    id: str
    status: str
    target: str
    scan_type: str
    start_time: str
    end_time: Optional[str] = None
    percent: int = 0
    current_task: Optional[str] = None
    error: Optional[str] = None
    report_url: Optional[str] = None

class ScanSummary(BaseModel):
    id: str
    target: str
    scan_type: str
    status: str
    start_time: str
    end_time: Optional[str] = None
    vulnerabilities_count: Dict[str, int] = Field(default_factory=dict)

# In-memory store for active scans (in production, use a database)
active_scans = {}

# Function to run scan in background
async def run_scan(scan_id: str, scan_request: ScanRequest):
    scan_dir = SCANS_DIR / scan_id
    scan_dir.mkdir(exist_ok=True)
    
    report_path = REPORTS_DIR / f"{scan_id}.json"
    
    try:
        # Update scan status
        active_scans[scan_id]["status"] = "running"
        active_scans[scan_id]["percent"] = 10
        active_scans[scan_id]["current_task"] = "Preparing scan"
        
        # Build command arguments
        cmd = ["python", str(BASE_DIR / "main.py")]
        cmd.append(scan_request.target)
        cmd.extend(["--type", scan_request.scan_type])
        
        if scan_request.tags:
            for tag in scan_request.tags:
                cmd.extend(["--tags", tag])
        
        if not scan_request.generate_report:
            cmd.append("--no-report")
        
        # Log the command
        logger.info(f"Running scan command: {' '.join(cmd)}")
        
        # Update status
        active_scans[scan_id]["current_task"] = "Running security scan"
        active_scans[scan_id]["percent"] = 20
        
        # Run the scan process
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        # Check if the process was successful
        if process.returncode != 0:
            logger.error(f"Scan failed with error: {stderr.decode()}")
            active_scans[scan_id]["status"] = "failed"
            active_scans[scan_id]["error"] = stderr.decode()
            return
        
        # Process completed successfully
        active_scans[scan_id]["percent"] = 80
        active_scans[scan_id]["current_task"] = "Processing results"
        
        # Find the JSON report file
        json_reports = list(REPORTS_DIR.glob("*.json"))
        if json_reports:
            # Use the most recent report
            latest_report = max(json_reports, key=lambda p: p.stat().st_mtime)
            
            # Copy to reports directory with scan_id as name
            shutil.copy(latest_report, report_path)
            
            # Parse vulnerabilities count if report exists
            try:
                vuln_count = count_vulnerabilities(report_path)
                active_scans[scan_id]["vulnerabilities_count"] = vuln_count
            except Exception as e:
                logger.error(f"Error counting vulnerabilities: {str(e)}")
            
            # Generate AI-enhanced report if requested
            if scan_request.ai_enhanced_report and scan_request.generate_report:
                active_scans[scan_id]["current_task"] = "Generating AI-enhanced report"
                active_scans[scan_id]["percent"] = 90
                
                try:
                    ai_report_path = REPORTS_DIR / f"{scan_id}_ai_report.pdf"
                    # Here you would call your AI report generation function
                    # Example: generate_ai_report(report_path, ai_report_path)
                    # For now, we'll simulate it
                    await asyncio.sleep(2)  # Simulate AI processing
                    
                    # Create a dummy PDF report
                    with open(ai_report_path, "w") as f:
                        f.write("This is a placeholder for the AI report")
                        
                    active_scans[scan_id]["report_url"] = f"/api/reports/{scan_id}/ai"
                except Exception as e:
                    logger.error(f"Error generating AI report: {str(e)}")
        
        # Mark as completed
        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["percent"] = 100
        active_scans[scan_id]["end_time"] = datetime.now().isoformat()
        active_scans[scan_id]["report_url"] = f"/api/reports/{scan_id}"
        
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["error"] = str(e)
        active_scans[scan_id]["percent"] = 0

def count_vulnerabilities(report_path):
    """Count vulnerabilities by severity from a scan report"""
    try:
        with open(report_path, "r") as f:
            report_data = json.load(f)
        
        # Initialize counters
        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
            "UNKNOWN": 0
        }
        
        # For Nmap reports
        if "nmaprun" in report_data:
            hosts = report_data.get("nmaprun", {}).get("host", [])
            if not isinstance(hosts, list):
                hosts = [hosts]
            
            for host in hosts:
                ports = host.get("ports", {}).get("port", [])
                if not isinstance(ports, list):
                    ports = [ports]
                
                for port in ports:
                    scripts = port.get("script", [])
                    if not isinstance(scripts, list):
                        scripts = [scripts]
                    
                    for script in scripts:
                        if "@id" in script and script["@id"] == "vulners":
                            # Process vulners script output for vulnerabilities
                            if "table" in script:
                                tables = script["table"]
                                if not isinstance(tables, list):
                                    tables = [tables]
                                
                                for table in tables:
                                    if "elem" in table:
                                        elems = table["elem"]
                                        if not isinstance(elems, list):
                                            elems = [elems]
                                        
                                        for elem in elems:
                                            if "@key" in elem and elem["@key"] == "cvss":
                                                cvss = float(elem.get("#text", "0"))
                                                if cvss >= 9.0:
                                                    counts["CRITICAL"] += 1
                                                elif cvss >= 7.0:
                                                    counts["HIGH"] += 1
                                                elif cvss >= 4.0:
                                                    counts["MEDIUM"] += 1
                                                elif cvss > 0:
                                                    counts["LOW"] += 1
        
        # For Trivy reports
        elif "Results" in report_data:
            results = report_data.get("Results", [])
            
            for result in results:
                vulns = result.get("Vulnerabilities", [])
                
                for vuln in vulns:
                    severity = vuln.get("Severity", "UNKNOWN").upper()
                    if severity in counts:
                        counts[severity] += 1
                    else:
                        counts["UNKNOWN"] += 1
        
        return counts
    except Exception as e:
        logger.error(f"Error counting vulnerabilities: {str(e)}")
        return {"ERROR": str(e)}

# Routes
@app.get("/")
async def root():
    return {"message": "Scansible API - Security Scanning Tool"}

@app.post("/api/scans", status_code=status.HTTP_201_CREATED, response_model=ScanStatus)
async def create_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    # Generate a unique ID for this scan
    scan_id = str(uuid.uuid4())
    
    # Create initial scan status
    scan_status = {
        "id": scan_id,
        "status": "starting",
        "target": scan_request.target,
        "scan_type": scan_request.scan_type,
        "start_time": datetime.now().isoformat(),
        "end_time": None,
        "percent": 0,
        "current_task": "Initializing",
        "error": None,
        "report_url": None,
        "vulnerabilities_count": {}
    }
    
    # Store scan status
    active_scans[scan_id] = scan_status
    
    # Run the scan in background
    background_tasks.add_task(run_scan, scan_id, scan_request)
    
    return scan_status

@app.get("/api/scans/{scan_id}", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return active_scans[scan_id]

@app.get("/api/scans", response_model=List[ScanSummary])
async def list_scans(limit: int = Query(10, ge=1, le=100), offset: int = Query(0, ge=0)):
    # Convert active_scans to list and sort by start_time (newest first)
    scans = list(active_scans.values())
    scans.sort(key=lambda x: x["start_time"], reverse=True)
    
    # Apply pagination
    paginated_scans = scans[offset:offset+limit]
    
    # Convert to ScanSummary objects
    summaries = []
    for scan in paginated_scans:
        summary = ScanSummary(
            id=scan["id"],
            target=scan["target"],
            scan_type=scan["scan_type"],
            status=scan["status"],
            start_time=scan["start_time"],
            end_time=scan.get("end_time"),
            vulnerabilities_count=scan.get("vulnerabilities_count", {})
        )
        summaries.append(summary)
    
    return summaries

@app.get("/api/reports/{scan_id}")
async def get_scan_report(scan_id: str):
    report_path = REPORTS_DIR / f"{scan_id}.json"
    
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    
    return FileResponse(report_path, media_type="application/json")

@app.get("/api/reports/{scan_id}/ai")
async def get_ai_report(scan_id: str):
    report_path = REPORTS_DIR / f"{scan_id}_ai_report.pdf"
    
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="AI report not found")
    
    return FileResponse(report_path, media_type="application/pdf")

@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str):
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Check if scan is running
    if active_scans[scan_id]["status"] == "running":
        raise HTTPException(status_code=400, detail="Cannot delete a running scan")
    
    # Remove scan data
    scan_dir = SCANS_DIR / scan_id
    if scan_dir.exists():
        shutil.rmtree(scan_dir)
    
    # Remove reports
    report_path = REPORTS_DIR / f"{scan_id}.json"
    if report_path.exists():
        report_path.unlink()
    
    ai_report_path = REPORTS_DIR / f"{scan_id}_ai_report.pdf"
    if ai_report_path.exists():
        ai_report_path.unlink()
    
    # Remove from active scans
    del active_scans[scan_id]
    
    return {"message": "Scan deleted successfully"}

@app.get("/api/tags")
async def get_available_tags():
    # In a real implementation, we would parse markdown files to get tags
    # For now, return a static list of common tags
    return {
        "tags": [
            "http", "ssl", "ssh", "ftp", "database", "smb", "dns", "docker", "web", 
            "vulners", "quick", "default", "scripts", "network", "firewall"
        ]
    }

# Main entry point
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
