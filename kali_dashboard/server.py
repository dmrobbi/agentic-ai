"""
KaliAgent Web Dashboard - FastAPI Backend
==========================================

REST API for executing KaliAgent playbooks and managing engagements.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from agentic_ai.agents.cyber.kali import KaliAgent, AuthorizationLevel
from agentic_ai.agents.cyber.redteam import RedTeamAgent, EngagementType


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


app = FastAPI(
    title="KaliAgent Dashboard API",
    description="Web interface for KaliAgent playbook execution",
    version="1.0.0",
)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================
# Pydantic Models
# ============================================

class EngagementCreate(BaseModel):
    name: str
    engagement_type: str = "penetration_test"
    scope: List[str] = []
    objectives: List[str] = []
    targets: List[str] = []


class PlaybookExecute(BaseModel):
    playbook_type: str  # recon, web_audit, password_audit, wireless_audit, ad_audit
    target: Optional[str] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    wordlist: Optional[str] = None
    hash_file: Optional[str] = None
    interface: Optional[str] = None
    bssid: Optional[str] = None


class AuthorizationUpdate(BaseModel):
    level: str  # NONE, BASIC, ADVANCED, CRITICAL
    engagement_id: Optional[str] = None


class SafetyConfig(BaseModel):
    whitelist: Optional[List[str]] = None
    blacklist: Optional[List[str]] = None


# ============================================
# Global State
# ============================================

kali_agent: Optional[KaliAgent] = None
redteam_agent: Optional[RedTeamAgent] = None

# Engagement results cache
engagement_results: Dict[str, Dict[str, Any]] = {}


# ============================================
# Startup/Shutdown
# ============================================

@app.on_event("startup")
async def startup_event():
    """Initialize agents on startup."""
    global kali_agent, redteam_agent
    
    logger.info("Initializing KaliAgent...")
    kali_agent = KaliAgent(
        workspace="/tmp/kali-dashboard",
        log_dir="/tmp/kali-dashboard/logs",
    )
    kali_agent.enable_audit_logging()
    logger.info(f"KaliAgent initialized with {len(kali_agent.tools)} tools")
    
    logger.info("Initializing RedTeamAgent...")
    redteam_agent = RedTeamAgent()
    logger.info("RedTeamAgent initialized")


# ============================================
# Health & Info Endpoints
# ============================================

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "tools_loaded": len(kali_agent.tools) if kali_agent else 0,
    }


@app.get("/api/tools")
async def list_tools(category: Optional[str] = None):
    """List available Kali tools."""
    if not kali_agent:
        raise HTTPException(status_code=503, detail="KaliAgent not initialized")
    
    tools = kali_agent.list_tools()
    
    if category:
        tools = [t for t in tools if t["category"] == category]
    
    return {"tools": tools, "total": len(tools)}


@app.get("/api/categories")
async def list_categories():
    """List tool categories."""
    categories = {}
    for tool in kali_agent.tools.values():
        cat = tool.category.value
        if cat not in categories:
            categories[cat] = 0
        categories[cat] += 1
    
    return {"categories": categories}


# ============================================
# Engagement Management
# ============================================

@app.get("/api/engagements")
async def list_engagements(
    engagement_type: Optional[str] = None,
    status: Optional[str] = None,
):
    """List all engagements."""
    if not redteam_agent:
        raise HTTPException(status_code=503, detail="RedTeamAgent not initialized")
    
    engagements = redteam_agent.get_engagements()
    
    # Filter
    if engagement_type:
        engagements = [e for e in engagements if e.engagement_type.value == engagement_type]
    if status:
        engagements = [e for e in engagements if e.status.value == status]
    
    return {
        "engagements": [
            {
                "engagement_id": e.engagement_id,
                "name": e.name,
                "type": e.engagement_type.value,
                "status": e.status.value,
                "start_date": e.start_date.isoformat(),
                "scope": e.scope,
                "objectives": e.objectives,
                "targets_count": len(e.targets),
                "findings_count": e.findings_count,
            }
            for e in engagements
        ],
        "total": len(engagements),
    }


@app.post("/api/engagements")
async def create_engagement(data: EngagementCreate):
    """Create a new engagement."""
    if not redteam_agent:
        raise HTTPException(status_code=503, detail="RedTeamAgent not initialized")
    
    try:
        engagement_type = EngagementType(data.engagement_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid engagement type: {data.engagement_type}")
    
    engagement = redteam_agent.create_engagement(
        name=data.name,
        engagement_type=engagement_type,
        start_date=datetime.utcnow(),
        scope=data.scope,
        objectives=data.objectives,
    )
    
    # Add targets
    for target in data.targets:
        redteam_agent.add_target_to_engagement(engagement.engagement_id, target)
    
    return {
        "engagement_id": engagement.engagement_id,
        "name": engagement.name,
        "status": engagement.status.value,
        "message": "Engagement created successfully",
    }


@app.get("/api/engagements/{engagement_id}")
async def get_engagement(engagement_id: str):
    """Get engagement details."""
    if not redteam_agent:
        raise HTTPException(status_code=503, detail="RedTeamAgent not initialized")
    
    engagements = [e for e in redteam_agent.get_engagements() if e.engagement_id == engagement_id]
    
    if not engagements:
        raise HTTPException(status_code=404, detail="Engagement not found")
    
    engagement = engagements[0]
    
    return {
        "engagement_id": engagement.engagement_id,
        "name": engagement.name,
        "type": engagement.engagement_type.value,
        "status": engagement.status.value,
        "start_date": engagement.start_date.isoformat(),
        "scope": engagement.scope,
        "objectives": engagement.objectives,
        "targets": engagement.targets,
        "findings_count": engagement.findings_count,
        "critical_findings": engagement.critical_findings,
    }


# ============================================
# Playbook Execution
# ============================================

@app.post("/api/engagements/{engagement_id}/playbook")
async def execute_playbook(
    engagement_id: str,
    data: PlaybookExecute,
    background_tasks: BackgroundTasks,
):
    """Execute a playbook for an engagement."""
    if not kali_agent or not redteam_agent:
        raise HTTPException(status_code=503, detail="Agents not initialized")
    
    # Verify engagement exists
    engagements = [e for e in redteam_agent.get_engagements() if e.engagement_id == engagement_id]
    if not engagements:
        raise HTTPException(status_code=404, detail="Engagement not found")
    
    # Set authorization based on playbook type
    auth_level = AuthorizationLevel.BASIC
    if data.playbook_type in ["web_audit", "password_audit", "wireless_audit"]:
        auth_level = AuthorizationLevel.ADVANCED
    
    kali_agent.set_authorization(auth_level)
    
    # Execute playbook based on type
    try:
        if data.playbook_type == "recon":
            results = kali_agent.run_recon_playbook(
                target=data.target,
                domain=data.domain,
            )
        elif data.playbook_type == "web_audit":
            results = kali_agent.run_web_audit_playbook(
                url=data.url or f"http://{data.target}",
                target=data.target,
            )
        elif data.playbook_type == "password_audit":
            results = kali_agent.run_password_audit_playbook(
                hash_file=data.hash_file or "/tmp/hashes.txt",
                wordlist=data.wordlist or "/usr/share/wordlists/rockyou.txt",
            )
        elif data.playbook_type == "wireless_audit":
            results = kali_agent.run_wireless_audit_playbook(
                interface=data.interface or "wlan0",
                target_bssid=data.bssid,
            )
        elif data.playbook_type == "ad_audit":
            results = kali_agent.run_ad_audit_playbook(
                domain=data.domain or "corp.local",
                username="admin",
                password="password",  # Should come from secure config
            )
        else:
            raise HTTPException(status_code=400, detail=f"Unknown playbook type: {data.playbook_type}")
        
        # Store results
        engagement_results[engagement_id] = {
            "playbook_type": data.playbook_type,
            "results": {k: v.__dict__ if hasattr(v, '__dict__') else v for k, v in results.items()},
            "executed_at": datetime.utcnow().isoformat(),
        }
        
        # Generate report
        report = kali_agent.generate_playbook_report(
            playbook_name=data.playbook_type,
            results=results,
        )
        
        return {
            "status": "success",
            "engagement_id": engagement_id,
            "playbook_type": data.playbook_type,
            "tools_executed": list(results.keys()),
            "report": report,
        }
        
    except Exception as e:
        logger.error(f"Playbook execution failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/engagements/{engagement_id}/results")
async def get_results(engagement_id: str):
    """Get execution results for an engagement."""
    if engagement_id not in engagement_results:
        raise HTTPException(status_code=404, detail="No results found")
    
    return engagement_results[engagement_id]


@app.get("/api/engagements/{engagement_id}/report")
async def generate_report(engagement_id: str, format: str = "markdown"):
    """Generate engagement report."""
    if not kali_agent:
        raise HTTPException(status_code=503, detail="KaliAgent not initialized")
    
    if engagement_id not in engagement_results:
        raise HTTPException(status_code=404, detail="No results found")
    
    result = engagement_results[engagement_id]
    
    report = kali_agent.generate_playbook_report(
        playbook_name=result["playbook_type"],
        results=result["results"],
        output_format=format,
    )
    
    if format == "markdown":
        return JSONResponse(
            content={"report": report},
            headers={"Content-Type": "text/markdown"},
        )
    else:
        return {"report": report}


# ============================================
# Safety Controls
# ============================================

@app.get("/api/authorization")
async def get_authorization():
    """Get current authorization level."""
    if not kali_agent:
        raise HTTPException(status_code=503, detail="KaliAgent not initialized")
    
    return {
        "level": kali_agent.authorization_level.name,
        "value": kali_agent.authorization_level.value,
    }


@app.post("/api/authorization")
async def update_authorization(data: AuthorizationUpdate):
    """Update authorization level."""
    if not kali_agent:
        raise HTTPException(status_code=503, detail="KaliAgent not initialized")
    
    try:
        level = AuthorizationLevel[data.level.upper()]
    except KeyError:
        raise HTTPException(status_code=400, detail=f"Invalid level: {data.level}")
    
    if data.engagement_id:
        kali_agent.set_authorization(level, engagement_id=data.engagement_id)
    else:
        kali_agent.set_authorization(level)
    
    return {
        "status": "success",
        "level": level.name,
        "value": level.value,
    }


@app.get("/api/safety")
async def get_safety_config():
    """Get safety configuration."""
    if not kali_agent:
        raise HTTPException(status_code=503, detail="KaliAgent not initialized")
    
    return {
        "whitelist": kali_agent.ip_whitelist,
        "blacklist": kali_agent.ip_blacklist,
        "safe_mode": kali_agent.safe_mode,
        "dry_run": kali_agent.dry_run,
        "audit_logging": kali_agent.audit_log_file is not None,
    }


@app.post("/api/safety")
async def update_safety_config(data: SafetyConfig):
    """Update safety configuration."""
    if not kali_agent:
        raise HTTPException(status_code=503, detail="KaliAgent not initialized")
    
    if data.whitelist is not None:
        kali_agent.set_ip_whitelist(data.whitelist)
    
    if data.blacklist is not None:
        kali_agent.ip_blacklist = data.blacklist
    
    return {
        "status": "success",
        "whitelist": kali_agent.ip_whitelist,
        "blacklist": kali_agent.ip_blacklist,
    }


# ============================================
# Main
# ============================================

if __name__ == "__main__":
    import uvicorn
    
    logger.info("Starting KaliAgent Dashboard API...")
    uvicorn.run(app, host="0.0.0.0", port=8001)
