"""Kasauti: AI-driven multi-vendor network security compliance auditor.

The package is a modular monolith (PLAN §4.2). The pipeline core (text → tree → facts →
findings → fixes) is made of pure functions with no I/O; the API, CLI and workers are
adapters around it.
"""

__version__ = "0.1.0"
