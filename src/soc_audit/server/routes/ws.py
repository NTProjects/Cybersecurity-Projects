"""WebSocket streaming endpoint."""
from __future__ import annotations

from fastapi import WebSocket, WebSocketDisconnect

from soc_audit.server.auth import get_role_from_websocket
from soc_audit.server.ws_manager import WebSocketManager


async def websocket_stream(websocket: WebSocket):
    """
    WebSocket endpoint for real-time streaming.

    Authenticates via API key in query parameter (?api_key=...) or header (X-API-Key).
    """
    # Authenticate (attempt to read query params before accept)
    # Note: query params are accessible before accept, but if auth fails,
    # we must accept then immediately close
    role = None
    try:
        role = get_role_from_websocket(websocket)
    except WebSocketDisconnect:
        # Auth failed - must accept before we can close
        await websocket.accept()
        await websocket.close(code=4401, reason="Authentication failed")
        return
    except Exception:
        # Unexpected error - accept then close
        await websocket.accept()
        await websocket.close(code=4401, reason="Authentication error")
        return

    # Accept connection after auth succeeds
    await websocket.accept()

    # Store role on websocket state (optional, for future use)
    websocket.state.role = role

    # Get ws_manager from app.state
    # In FastAPI, websocket has access to app through the application context
    try:
        ws_manager: WebSocketManager = websocket.app.state.ws_manager
    except AttributeError:
        await websocket.close(code=1011, reason="Server configuration error")
        return

    # Register websocket with manager (after auth succeeds and connection accepted)
    ws_manager.connect(websocket)

    try:
        # Send initial connection message
        await ws_manager.send_personal_json(
            websocket, {"type": "connected", "message": "WebSocket connected"}
        )

        # Keep connection alive and handle messages
        while True:
            try:
                # Wait for client messages (optional - can be one-way)
                data = await websocket.receive_text()
                # Echo or process message (optional)
                await ws_manager.send_personal_json(websocket, {"type": "echo", "data": data})
            except WebSocketDisconnect:
                break
            except Exception:
                # Connection error - break loop
                break

    except WebSocketDisconnect:
        pass
    finally:
        ws_manager.disconnect(websocket)
