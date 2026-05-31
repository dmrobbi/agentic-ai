"""Shared utility functions."""
from datetime import datetime, timezone


def utcnow() -> datetime:
    """Return current UTC datetime as timezone-aware.

    Replaces deprecated datetime.utcnow() (removed in Python 3.12+).
    """
    return datetime.now(timezone.utc)