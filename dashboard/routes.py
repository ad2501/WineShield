#!/usr/bin/env python3
"""REST route exports for the WineShield dashboard."""
from __future__ import annotations

from dashboard.app import (
    api_events,
    api_events_latest,
    api_layer_toggle,
    api_layers,
    api_sessions,
    api_stats,
    api_status,
    index,
    static_files,
)

__all__ = [
    "api_events",
    "api_events_latest",
    "api_layer_toggle",
    "api_layers",
    "api_sessions",
    "api_stats",
    "api_status",
    "index",
    "static_files",
]
