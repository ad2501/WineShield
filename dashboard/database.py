#!/usr/bin/env python3
"""Database helpers for the WineShield dashboard.

The dashboard implementation currently lives in :mod:`dashboard.app`.  This
module provides a stable import surface for callers that want database helpers
without duplicating schema code.
"""
from __future__ import annotations

from dashboard.app import DB_PATH, WINESHIELD_HOME, _get_db, init_db

__all__ = ["DB_PATH", "WINESHIELD_HOME", "_get_db", "init_db"]
