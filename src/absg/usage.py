# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""Agent usage from the Microsoft Purview audit log, for ShareGuard for Agent Builder.

Sharing that is added and removed between two guard checks leaves no trace in an
agent's configuration, but every use of the agent does: Copilot interactions are
audited as ``CopilotInteraction`` records naming the user and the agent. If anyone
other than an owner used an unapproved agent, it was shared at that moment.

The Graph audit log query API (v1.0) is asynchronous: a query is created for a time
window, runs for a while, then its records are read. ``UsageMonitor.poll`` moves one
query forward each guard cycle and returns the usage events once a query has finished.
Audit records can arrive late, so each window overlaps the previous one, and records
already seen are skipped.

Needs the application permission ``AuditLogsQuery.Read.All`` (or the narrower one your
tenant requires) on the guard's identity.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

log = logging.getLogger("absg.usage")


class UsageQueryError(RuntimeError):
    pass


def _parse(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def find_values(obj: Any, keys: set[str]) -> list[str]:
    """Every string value under one of ``keys`` (case-insensitive), at any depth."""
    out: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in keys and isinstance(v, (str, int)):
                out.append(str(v))
            else:
                out += find_values(v, keys)
    elif isinstance(obj, list):
        for v in obj:
            out += find_values(v, keys)
    return out


def usage_event(record: dict, agent_keys: list[str]) -> dict:
    """The fields ShareGuard needs from one auditLogRecord."""
    data = record.get("auditData") or {}
    return {"recordId": record.get("id"),
            "time": record.get("createdDateTime") or data.get("CreationTime"),
            "userId": record.get("userId") or data.get("UserKey"),
            "userPrincipalName": record.get("userPrincipalName") or data.get("UserId"),
            "operation": record.get("operation") or data.get("Operation"),
            "agentIds": find_values(data, {k.lower() for k in agent_keys})}


class UsageMonitor:
    """Runs one audit log query at a time; its progress is kept in ``state.usage``."""

    def __init__(self, graph: Any, cfg: Any, state: Any):
        self.graph, self.cfg, self.state = graph, cfg, state

    @property
    def st(self) -> dict:
        if not isinstance(getattr(self.state, "usage", None), dict):
            self.state.usage = {}
        return self.state.usage

    def poll(self, now: datetime | None = None) -> list[dict] | None:
        """Advance the query. Returns usage events when one has finished, else None."""
        now = now or datetime.now(timezone.utc)
        st = self.st
        pending = st.get("pending")
        if pending:
            q = self.graph.request("GET", f"/security/auditLog/queries/{pending['id']}").json()
            status = str(q.get("status") or "").lower()
            if status == "succeeded":
                records = list(self.graph.get_paged(f"/security/auditLog/queries/{pending['id']}/records"))
                st.pop("pending", None)
                st["until"] = pending["end"]
                return self._new_events(records, now)
            if status in ("failed", "cancelled"):
                st.pop("pending", None)
                raise UsageQueryError(f"audit log query {pending['id']} {status}; the window is retried")
            created = _parse(pending.get("createdAt")) or now
            if now - created > timedelta(minutes=self.cfg.usage_query_timeout_minutes):
                st.pop("pending", None)
                raise UsageQueryError(f"audit log query {pending['id']} still {status or 'pending'} after "
                                      f"{self.cfg.usage_query_timeout_minutes} minutes; starting again")
            return None
        until = _parse(st.get("until")) or now - timedelta(hours=self.cfg.usage_lookback_hours)
        start = until - timedelta(minutes=self.cfg.usage_overlap_minutes)
        body = {"displayName": f"ShareGuard agent usage {now:%Y-%m-%dT%H:%M}Z",
                "filterStartDateTime": start.isoformat(), "filterEndDateTime": now.isoformat(),
                "recordTypeFilters": list(self.cfg.usage_record_types)}
        q = self.graph.request("POST", "/security/auditLog/queries", json=body).json()
        st["pending"] = {"id": q["id"], "start": start.isoformat(), "end": now.isoformat(),
                         "createdAt": now.isoformat()}
        return None

    def _new_events(self, records: list[dict], now: datetime) -> list[dict]:
        seen: dict[str, str] = self.st.setdefault("seen", {})
        keep_after = now - timedelta(minutes=2 * self.cfg.usage_overlap_minutes
                                     + 60 * self.cfg.usage_lookback_hours)
        for rid in [r for r, t in seen.items() if (_parse(t) or now) < keep_after]:
            seen.pop(rid, None)
        events = []
        for rec in records:
            rid = str(rec.get("id") or "")
            if not rid or rid in seen:
                continue
            seen[rid] = rec.get("createdDateTime") or now.isoformat()
            events.append(usage_event(rec, self.cfg.usage_agent_id_keys))
        return events
