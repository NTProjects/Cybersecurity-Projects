"""WebSocket streaming endpoint."""
from __future__ import annotations

import json

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

    # Phase 11.1: Register websocket with manager (returns connection object)
    conn = await ws_manager.connect(websocket, role)

    try:
        # Phase 11.1: Send initial connection message with subscription info
        await ws_manager.send_personal_json(
            websocket,
            {
                "type": "connected",
                "message": "WebSocket connected",
                "subscriptions": ["alert", "incident", "host"],  # Default subscriptions
                "role": role,
            }
        )

        # Phase 11.1: Keep connection alive and handle subscription messages
        while True:
            try:
                # Wait for client messages (subscription control)
                data = await websocket.receive_text()
                
                try:
                    message = json.loads(data)
                    msg_type = message.get("type")
                    
                    if msg_type == "subscribe":
                        # Subscribe to event types
                        event_types = message.get("events", [])
                        for event_type in event_types:
                            await ws_manager.subscribe(websocket, event_type)
                        await ws_manager.send_personal_json(
                            websocket,
                            {"type": "subscribed", "events": event_types}
                        )
                    elif msg_type == "unsubscribe":
                        # Unsubscribe from event types
                        event_types = message.get("events", [])
                        for event_type in event_types:
                            await ws_manager.unsubscribe(websocket, event_type)
                        await ws_manager.send_personal_json(
                            websocket,
                            {"type": "unsubscribed", "events": event_types}
                        )
                    elif msg_type == "ping":
                        # Keepalive ping
                        await ws_manager.send_personal_json(websocket, {"type": "pong"})
                    else:
                        # Unknown message type
                        await ws_manager.send_personal_json(
                            websocket,
                            {"type": "error", "message": f"Unknown message type: {msg_type}"}
                        )
                except json.JSONDecodeError:
                    # Invalid JSON - echo back as error
                    await ws_manager.send_personal_json(
                        websocket,
                        {"type": "error", "message": "Invalid JSON"}
                    )
                    
            except WebSocketDisconnect:
                break
            except Exception:
                # Connection error - break loop
                break

    except WebSocketDisconnect:
        pass
    finally:
        ws_manager.disconnect(websocket)
