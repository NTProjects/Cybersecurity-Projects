# Phase 11: Real-Time Without Polling

**Status:** ✅ Server-side complete (Phase 11.1), GUI ready for WebSocket integration (Phase 11.2)

## Phase 11.1: WebSocket Event Bus ✅

### Implemented Features

1. **Explicit Subscriptions**
   - Clients can subscribe to specific event types: `alert`, `incident`, `host`
   - Empty subscriptions = receive all events (backward compatible)
   - Subscription management via WebSocket messages:
     ```json
     {"type": "subscribe", "events": ["alert", "incident"]}
     {"type": "unsubscribe", "events": ["host"]}
     ```

2. **Backpressure Handling**
   - Each connection tracks queue depth
   - Default max queue depth: 100 messages
   - Messages skipped if queue depth exceeds limit
   - Prevents overwhelming slow clients

3. **Rate Limiting**
   - Per-connection rate limits: 1000 messages per 60 seconds
   - Sliding window tracking
   - Automatic throttling when limits exceeded

4. **Role-Based Filtering**
   - Optional role filter in `broadcast_json()`
   - Can restrict broadcasts to specific roles (e.g., admin-only events)

### Server Implementation

- `WebSocketManager`: Enhanced with subscription tracking
- `WebSocketConnection`: Per-connection state management
- All routes updated to use `event_type` parameter in broadcasts

## Phase 11.2: GUI Event Rehydration

### Current State

- **Backend Polling**: Disabled (per user preference for performance)
- **WebSocket Client**: Stub implementation ready for full integration
- **Manual Refresh**: Available via `refresh_now()` method

### Design Principles

1. **Event-Driven Updates**: UI updates only from WebSocket events (when connected)
2. **Manual Refresh Available**: Users can trigger refresh via UI button
3. **No Auto-Refresh Loops**: No background polling when WebSocket is available
4. **Graceful Degradation**: Falls back to manual refresh if WebSocket unavailable

### Future GUI Integration

When WebSocket client is fully implemented:

```python
# Connect to WebSocket
ws_client.connect()

# Subscribe to events
ws_client.subscribe(["alert", "incident"])

# Handle events
def on_alert(event):
    # Update UI from event only
    dashboard.process_alert(event)

# Manual refresh still available
def on_refresh_button():
    dashboard.refresh_now()
```

### Benefits

- **Live Visibility**: Real-time updates without polling overhead
- **Reduced Server Load**: Push-only, no constant polling requests
- **Better UX**: Instant updates when events occur
- **Scalability**: Handles many concurrent clients efficiently

## Migration Path

1. ✅ Server-side WebSocket infrastructure (Phase 11.1)
2. ⏳ GUI WebSocket client implementation (future)
3. ⏳ Remove polling fallback (when WebSocket stable)

## Current Configuration

- `backend.enabled`: `false` (polling disabled)
- `backend.use_websocket`: `true` (ready when implemented)
- Manual refresh: Available via dashboard UI
