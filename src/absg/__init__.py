# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""ShareGuard for Agent Builder (ABSG).

Governance daemon for Microsoft 365 Copilot Agent Builder agents: blocks
agents shared outside an approved, signed registry, validates approved agents
for configuration drift, notifies owners, and keeps a tamper-evident audit
trail.
"""
from .core import (AuditLog, Config, Guard, GraphClient, GraphError, StateStore,
                   audit_history, main, verify_audit_log)

__version__ = "0.1.0"

__all__ = ["AuditLog", "Config", "Guard", "GraphClient", "GraphError", "StateStore",
           "audit_history", "main", "verify_audit_log", "__version__"]
