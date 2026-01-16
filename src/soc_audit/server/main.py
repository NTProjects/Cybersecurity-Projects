"""FastAPI application for SOC Audit Server."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from soc_audit.core.config import load_config
from soc_audit.server.auth import get_auth_config
from soc_audit.server.incident_engine import ServerIncidentEngine
from soc_audit.server.routes import alerts, heartbeat, hosts, incidents, ingest, ingest_batch, reports
from soc_audit.server.routes.ws import websocket_stream
from soc_audit.server.storage import BackendStorage, SQLiteBackendStorage
from soc_audit.server.ws_manager import WebSocketManager

app = FastAPI(title="SOC Audit Server", version="1.0.0")

# CORS middleware (allow all for development)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Store dependencies in app.state during startup


@app.on_event("startup")
async def startup_event():
    """Initialize storage, engine, and WebSocket manager on startup."""
    import logging
    
    logger = logging.getLogger(__name__)
    
    # Load config (default path or from environment)
    config_path = Path("config/default.json")
    if not config_path.exists():
        server_config = {"storage": {"sqlite_path": "data/soc_audit_server.db"}}
    else:
        try:
            full_config = load_config(config_path)
            server_config = full_config.get("backend", {})
        except Exception:
            server_config = {"storage": {"sqlite_path": "data/soc_audit_server.db"}}

    # Initialize storage
    storage_config = server_config.get("storage", {})
    db_path = storage_config.get("sqlite_path", "data/soc_audit_server.db")

    storage: BackendStorage
    try:
        storage = SQLiteBackendStorage(db_path)
        storage.init()
    except Exception:
        # Fallback - for MVP, just use SQLite (JSONBackendStorage would need implementation)
        storage = SQLiteBackendStorage(db_path)
        storage.init()

    # Phase 8.1: Server startup recovery - load all hosts and check status
    try:
        all_hosts = storage.list_hosts()
        heartbeat_interval = 10  # Default, can be overridden from config
        
        # Load heartbeat_interval from agent config if available
        try:
            if config_path.exists():
                full_config = load_config(config_path)
                agent_config = full_config.get("agent", {})
                heartbeat_interval = agent_config.get("heartbeat_interval", 10)
        except Exception:
            pass
        
        logger.info(f"[STARTUP] Loaded {len(all_hosts)} known hosts")
        
        # Hosts are marked OFFLINE implicitly via get_host_status()
        # No need to update DB on startup - status is calculated on-demand
        online_count = 0
        for host in all_hosts:
            status = storage.get_host_status(host["host_id"], heartbeat_interval)
            if status == "ONLINE":
                online_count += 1
        
        if all_hosts:
            logger.info(f"[STARTUP] Host status: {online_count} ONLINE, {len(all_hosts) - online_count} OFFLINE")
    except Exception as e:
        logger.warning(f"[STARTUP] Could not load host registry: {e}")

    # Initialize incident engine
    incidents_config = server_config.get("incidents", {})
    group_window = incidents_config.get("group_window_seconds", 300)
    incident_engine = ServerIncidentEngine(storage, group_window_seconds=group_window)

    # Initialize WebSocket manager
    ws_manager = WebSocketManager()

    # Store in app.state for dependency injection
    app.state.storage = storage
    app.state.incident_engine = incident_engine
    app.state.ws_manager = ws_manager
    app.state.config = server_config


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    if hasattr(app.state, "storage") and hasattr(app.state.storage, "close"):
        app.state.storage.close()


# Include routers
app.include_router(ingest.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
# Phase 7.1: Multi-host federation routes
app.include_router(hosts.router)
app.include_router(heartbeat.router)
app.include_router(ingest_batch.router)
app.include_router(reports.router)  # Phase 9.3: Reporting endpoints

# Register WebSocket route directly (not via router)
app.add_api_websocket_route("/ws/stream", websocket_stream)


@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "SOC Audit Server", "version": "1.0.0"}


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "storage": hasattr(app.state, "storage") and app.state.storage is not None,
    }
