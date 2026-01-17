"""Active Response API endpoints.

Phase 16: Active Response (Controlled)
- Response playbooks
- Approval gates
- Audit trail
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from fastapi import APIRouter, Depends, HTTPException, Request

from soc_audit.core.response_playbooks import ResponsePlaybook
from soc_audit.server.auth import get_role_from_request
from soc_audit.server.deps import get_audit_logger, get_storage
from soc_audit.server.rbac import require_admin
from soc_audit.server.storage import BackendStorage

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/response", tags=["response"])


class ResponseRequest(BaseModel):
    """Request schema for response actions."""
    action: str  # isolate_host, block_ip, kill_process
    target: str  # host_id, ip_address, or process_id
    reason: str
    host_id: str | None = None  # Required for kill_process
    dry_run: bool = True  # Default to dry-run for safety


@router.post("/execute")
async def execute_response(
    request: Request,
    response_req: ResponseRequest,
    role: str = require_admin("execute_response"),  # Phase 16.2: Admin approval required
    storage: BackendStorage = Depends(get_storage),
    audit_logger = Depends(get_audit_logger),
):
    """
    Execute a response action.
    
    Phase 16.1: Executes response playbook actions.
    Phase 16.2: Requires admin approval and full audit trail.
    
    Actions:
    - isolate_host: Isolate a host from network
    - block_ip: Block an IP address
    - kill_process: Kill a process on a host
    """
    # Get user info for audit trail
    api_key = request.headers.get("X-API-Key", "")
    user_id = api_key[:16] if api_key else None
    
    # Create playbook executor
    playbook = ResponsePlaybook(dry_run=response_req.dry_run)
    
    # Execute action
    if response_req.action == "isolate_host":
        result = playbook.isolate_host(response_req.target, response_req.reason)
    elif response_req.action == "block_ip":
        result = playbook.block_ip(response_req.target, response_req.reason)
    elif response_req.action == "kill_process":
        if not response_req.host_id:
            raise HTTPException(status_code=400, detail="host_id required for kill_process action")
        result = playbook.kill_process(response_req.host_id, response_req.target, response_req.reason)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown action: {response_req.action}")
    
    # Phase 16.2: Log to audit trail
    if audit_logger:
        audit_logger.log(
            user_id=user_id,
            role=role,
            operation="execute_response",
            action=response_req.action,
            result=result.get("status", "error"),
            endpoint="/api/v1/response/execute",
            object_type="response",
            object_id=response_req.target,
            details={
                "action": response_req.action,
                "target": response_req.target,
                "reason": response_req.reason,
                "dry_run": response_req.dry_run,
                "result": result,
            },
        )
    
    # Append timeline entry
    storage.append_timeline({
        "timestamp": datetime.utcnow().isoformat(),
        "message": f"Response action executed: {response_req.action} on {response_req.target}",
        "level": "warning" if not response_req.dry_run else "info",
        "source": "api",
        "module": "response",
        "host_id": response_req.host_id or response_req.target if response_req.action == "isolate_host" else None,
    })
    
    return {
        "ok": True,
        "result": result,
        "dry_run": response_req.dry_run,
    }
