"""
Sliding window state management for M03 Traffic Analyzer.

Thin wrapper around the shared feature_engineering.SlidingWindowState
so m03 code stays clean.
"""

import sys
from pathlib import Path

# Allow import from repo root when running inside Docker
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ml.training.feature_engineering import SlidingWindowState  # re-export

__all__ = ["SlidingWindowState"]
