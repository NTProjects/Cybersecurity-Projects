"""WebSocket connection manager for real-time streaming.

Phase 11.1: Enhanced with explicit subscriptions, backpressure, and rate limits.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import defaultdict, deque
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketConnection:
    """
    Enhanced WebSocket connection with subscription and backpressure management.
    
    Phase 11.1: Tracks subscriptions, queue depth, and rate limits per connection.
    """
    
    def __init__(self, websocket: WebSocket, role: str = "unknown"):
        """
        Initialize WebSocket connection.
        
        Args:
            websocket: FastAPI WebSocket instance.
            role: User role (agent, analyst, admin).
        """
        self.websocket = websocket
        self.role = role
        self.subscriptions: set[str] = set()  # Event types this connection subscribes to
        self.queue_depth = 0  # Current message queue depth (backpressure tracking)
        self.max_queue_depth = 100  # Maximum queue depth before throttling
        self.message_count = 0  # Messages sent in current window
        self.rate_limit_window = 60  # Rate limit window in seconds
        self.rate_limit_max = 1000  # Maximum messages per window
        self.window_start = time.time()
        self.message_times: deque[float] = deque()  # Track message timestamps for rate limiting
        self.disconnected = False
    
    def subscribe(self, event_type: str) -> None:
        """Subscribe to an event type (e.g., 'alert', 'incident', 'host')."""
        self.subscriptions.add(event_type)
        logger.debug(f"Connection subscribed to {event_type}")
    
    def unsubscribe(self, event_type: str) -> None:
        """Unsubscribe from an event type."""
        self.subscriptions.discard(event_type)
        logger.debug(f"Connection unsubscribed from {event_type}")
    
    def is_subscribed(self, event_type: str) -> bool:
        """Check if connection is subscribed to an event type."""
        return not self.subscriptions or event_type in self.subscriptions  # Empty subscriptions = all events
    
    def check_rate_limit(self) -> bool:
        """
        Check if connection is within rate limits.
        
        Returns:
            True if within limits, False if rate limited.
        """
        now = time.time()
        
        # Reset window if expired
        if now - self.window_start >= self.rate_limit_window:
            self.window_start = now
            self.message_times.clear()
            self.message_count = 0
        
        # Remove old timestamps outside window
        while self.message_times and self.message_times[0] < now - self.rate_limit_window:
            self.message_times.popleft()
        
        # Check if over limit
        if len(self.message_times) >= self.rate_limit_max:
            return False
        
        return True
    
    def record_message(self) -> None:
        """Record that a message was sent."""
        self.message_count += 1
        self.message_times.append(time.time())


class WebSocketManager:
    """
    Manages active WebSocket connections with subscriptions and backpressure.
    
    Phase 11.1: Enhanced with explicit subscriptions, backpressure handling, and rate limits.
    """

    def __init__(self):
        """Initialize the WebSocket manager."""
        self.active_connections: dict[WebSocket, WebSocketConnection] = {}
        self._lock = asyncio.Lock()  # Async lock for thread safety

    async def connect(self, websocket: WebSocket, role: str = "unknown") -> WebSocketConnection:
        """
        Accept and register a new WebSocket connection.
        
        Phase 11.1: Returns WebSocketConnection with subscription support.
        
        Args:
            websocket: FastAPI WebSocket instance.
            role: User role (agent, analyst, admin).
        
        Returns:
            WebSocketConnection instance.
        """
        await websocket.accept()
        conn = WebSocketConnection(websocket, role)
        async with self._lock:
            self.active_connections[websocket] = conn
        logger.info(f"WebSocket connection established (role: {role}, total: {len(self.active_connections)})")
        return conn

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection."""
        async def _disconnect():
            async with self._lock:
                if websocket in self.active_connections:
                    conn = self.active_connections[websocket]
                    conn.disconnected = True
                    del self.active_connections[websocket]
                    logger.debug(f"WebSocket connection removed (remaining: {len(self.active_connections)})")
        
        # Run in event loop if available
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(_disconnect())
            else:
                loop.run_until_complete(_disconnect())
        except RuntimeError:
            # No event loop, just remove directly (fallback)
            if websocket in self.active_connections:
                del self.active_connections[websocket]

    async def broadcast_json(
        self,
        payload: dict[str, Any],
        event_type: str | None = None,
        filter_role: str | None = None,
    ) -> int:
        """
        Broadcast a JSON payload to subscribed connections.
        
        Phase 11.1: Enhanced with subscription filtering and backpressure handling.

        Args:
            payload: Dictionary to send as JSON.
            event_type: Event type (e.g., 'alert', 'incident') - only sent to subscribers.
            filter_role: Optional role filter - only send to connections with this role.

        Returns:
            Number of connections that received the message.

        Note:
            Silently handles disconnections to avoid breaking other clients.
        """
        async with self._lock:
            if not self.active_connections:
                return 0

            message = json.dumps(payload)
            disconnected = []
            sent_count = 0

            for websocket, conn in list(self.active_connections.items()):
                # Check if connection should receive this event
                if filter_role and conn.role != filter_role:
                    continue
                
                if event_type and not conn.is_subscribed(event_type):
                    continue
                
                # Check backpressure (queue depth)
                if conn.queue_depth >= conn.max_queue_depth:
                    logger.warning(
                        f"Connection queue depth {conn.queue_depth} >= max {conn.max_queue_depth}, skipping message"
                    )
                    continue
                
                # Check rate limit
                if not conn.check_rate_limit():
                    logger.warning(f"Connection rate limited, skipping message")
                    continue

                try:
                    await websocket.send_text(message)
                    conn.queue_depth += 1
                    conn.record_message()
                    sent_count += 1
                except Exception as e:
                    # Connection closed or error - mark for removal
                    logger.debug(f"Error sending to connection: {e}")
                    disconnected.append(websocket)

            # Remove disconnected connections
            for ws in disconnected:
                self.disconnect(ws)
            
            return sent_count
    
    async def subscribe(self, websocket: WebSocket, event_type: str) -> bool:
        """
        Subscribe a connection to an event type.
        
        Phase 11.1: Explicit subscription management.
        
        Args:
            websocket: WebSocket connection.
            event_type: Event type to subscribe to (e.g., 'alert', 'incident').
        
        Returns:
            True if subscribed, False if connection not found.
        """
        async with self._lock:
            if websocket not in self.active_connections:
                return False
            conn = self.active_connections[websocket]
            conn.subscribe(event_type)
            return True
    
    async def unsubscribe(self, websocket: WebSocket, event_type: str) -> bool:
        """
        Unsubscribe a connection from an event type.
        
        Phase 11.1: Explicit subscription management.
        
        Args:
            websocket: WebSocket connection.
            event_type: Event type to unsubscribe from.
        
        Returns:
            True if unsubscribed, False if connection not found.
        """
        async with self._lock:
            if websocket not in self.active_connections:
                return False
            conn = self.active_connections[websocket]
            conn.unsubscribe(event_type)
            return True

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
