"""WebSocket connection manager for real-time streaming."""
from __future__ import annotations

import json
from typing import Any

from fastapi import WebSocket


class WebSocketManager:
    """Manages active WebSocket connections and broadcasts."""

    def __init__(self):
        """Initialize the WebSocket manager."""
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_json(self, payload: dict[str, Any]) -> None:
        """
        Broadcast a JSON payload to all connected clients.

        Args:
            payload: Dictionary to send as JSON.

        Note:
            Silently handles disconnections to avoid breaking other clients.
        """
        if not self.active_connections:
            return

        message = json.dumps(payload)
        disconnected = []

        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                # Connection closed or error - mark for removal
                disconnected.append(connection)

        # Remove disconnected connections
        for conn in disconnected:
            self.disconnect(conn)

    async def send_personal_json(self, websocket: WebSocket, payload: dict[str, Any]) -> None:
        """
        Send a JSON payload to a specific WebSocket connection.

        Args:
            websocket: The WebSocket connection to send to.
            payload: Dictionary to send as JSON.
        """
        try:
            message = json.dumps(payload)
            await websocket.send_text(message)
        except Exception:
            # Connection closed - remove it
            self.disconnect(websocket)
