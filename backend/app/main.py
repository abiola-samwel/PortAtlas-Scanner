from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional
from backend.app.scanner import run_port_scan
import socket
import time
import logging
from logging.handlers import TimedRotatingFileHandler
import os

# =========================================================
# Setup Logging (Rotating logs, 30-day retention)
# =========================================================
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

log_handler = TimedRotatingFileHandler(
    filename=os.path.join(LOG_DIR, "scan_api.log"),
    when="D",
    interval=1,
    backupCount=30,
    encoding="utf-8",
)
log_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
log_handler.setFormatter(log_formatter)

logger = logging.getLogger("portatlas")
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

# =========================================================
# FastAPI App
# =========================================================
app = FastAPI(
    title="PortAtlas API",
    version="1.0",
    description="FastAPI backend for PortAtlas Scanner. Use responsibly.",
)

# =========================================================
# Request Schema
# =========================================================
class ScanRequest(BaseModel):
    target: str
    ports: Optional[str] = "22,80"
    scan_type: Optional[str] = "tcp_connect"
    banner: Optional[bool] = False
    all_ports: Optional[bool] = False

# =========================================================
# Root Endpoint
# =========================================================
@app.get("/")
async def root():
    """
    Root endpoint providing basic information about the API.
    """
    return {
        "name": "PortAtlas",
        "version": "1.0",
        "description": "API wrapper for the PortAtlas port scanner.",
        "usage": "POST /scan with JSON body: { 'target': 'host', 'ports': '22,80', 'scan_type': 'tcp_connect' }",
    }

# =========================================================
# Scan Endpoint
# =========================================================
@app.post("/scan")
async def scan(request: Request, body: ScanRequest):
    """
    Perform a port scan using the scanner engine.
    - Uses protocol-aware detection (HTTP, Redis, PostgreSQL, MySQL, MongoDB, SNMP, etc.)
      when `banner=true`.
    - Respects Secure Mode vs Local Mode automatically.
    """

    try:
        # Parse ports
        if body.all_ports:
            port_list = list(range(1, 65536))
        elif "-" in body.ports:
            start, end = map(int, body.ports.split("-"))
            port_list = list(range(start, end + 1))
        else:
            port_list = [int(p) for p in body.ports.split(",")]

        start_time = time.time()
        result = run_port_scan(body.target, port_list, body.scan_type, body.banner, body.all_ports)
        end_time = time.time()

        # Add metadata
        result["api_duration_ms"] = int((end_time - start_time) * 1000)
        result["client"] = {"ip": request.client.host}

        logger.info(
            f"Client={request.client.host} Target={body.target} "
            f"Ports={len(port_list)} Type={body.scan_type} Banner={body.banner}"
        )

        return JSONResponse(content=result)

    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Invalid target hostname or IP")
    except Exception as e:
        logger.error(f"Error scanning {body.target}: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")
