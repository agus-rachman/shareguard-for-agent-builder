# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""Changes made and undone between two checks: audit-log usage, and edits that were reverted."""
import json

import pytest

from absg.ack import AckStore, AckTokenSigner
from absg.core import AuditLog, Config, Guard, StateStore
from absg.mail import Mailer, OwnerResolver
from absg.registry import Approval
from test_flows import OTHER, OWNER, SECRET, FakeTenant, Resp, agent

RITA, RITA_UPN = OTHER, "rita@contoso.com"


class AuditTenant(FakeTenant):
    """FakeTenant plus the Graph audit log query API and checkMemberGroups."""

    def __init__(self, packages):
        super().__init__(packages)
        self.queries, self.records, self.status = [], [], "succeeded"
        self.groups = {}                               # userId -> group ids

    def request(self, method, url, json=None, **kw):
        if url == "/security/auditLog/queries" and method == "POST":
            self.queries.append(json)
            return Resp({"id": f"q{len(self.queries)}"})
        if url.startswith("/security/auditLog/queries/") and method == "GET":
            return Resp({"id": url.rsplit("/", 1)[1], "status": self.status})
        if url.endswith("/checkMemberGroups"):
            uid = url.split("/")[2]
            return Resp({"value": [g for g in json["groupIds"] if g in self.groups.get(uid, [])]})
        return super().request(method, url, json=json, **kw)

    def get_paged(self, url):
        assert url.endswith("/records")
        return list(self.records)

    def member_of(self, user_id, group_ids):
        return set(self.request("POST", f"/users/{user_id}/checkMemberGroups",
                                json={"groupIds": group_ids}).json()["value"])


def interaction(rid, pid, user=RITA, upn=RITA_UPN, when="2026-11-23T09:00:00Z"):
    return {"id": rid, "createdDateTime": when, "auditLogRecordType": "copilotInteraction",
            "operation": "CopilotInteraction", "userId": user, "userPrincipalName": upn,
            "auditData": {"CopilotEventData": {"AgentId": f"declarative.{pid}", "AppHost": "Copilot"}}}


class FakeRegistry:
    loaded, invalid, file_hash, raw_agents = True, {}, None, []

    def __init__(self, approved=None):
        self.approved = approved or {}
        self.entries = {}

    def load(self):
        pass

    def entry_hashes(self):
        return {}

    def reject_rollbacks(self, newest):
        return []

    def lookup(self, d):
        e = self.approved.get(d.get("id"))
        return Approval(e, True, "approved") if e else None


@pytest.fixture
def build(tmp_path):
    def make(packages, registry=None, **over):
        cfg = Config(tenant_id="t", client_id="c", client_secret="x", state_file=str(tmp_path / "state.json"),
                     audit_file=str(tmp_path / "audit.jsonl"), ack_store_file=str(tmp_path / "acks.json"),
                     lock_releases_file=str(tmp_path / "releases.json"),
                     mail_sender="governance@contoso.com", admin_emails=["it@contoso.com"],
                     ack_enabled=True, ack_base_url="https://guard.contoso.com/ack", ack_secret=SECRET, **over)
        tenant = AuditTenant(packages)
        state = StateStore(cfg.state_file)
        audit = AuditLog(cfg.audit_file)
        guard = Guard(cfg, tenant, state, audit=audit, mailer=Mailer(tenant, cfg.mail_sender, cfg.admin_emails),
                      owner_resolver=OwnerResolver([], None, state.package_owners),
                      signer=AckTokenSigner(SECRET, 1), acks=AckStore(cfg.ack_store_file),
                      delegated_graph=tenant, registry=registry)
        return guard, tenant, audit
    return make


def records(audit, event):
    return [json.loads(line) for line in open(audit.path) if json.loads(line)["event"] == event]


def alerts(tenant, words):
    return [m for m in tenant.mails_to("it@contoso.com") if words in m["subject"]]


# ---- 1. Usage from the audit log ----------------------------------------------------
def test_usage_query_runs_across_cycles_and_flags_non_owner_use(build):
    guard, tenant, audit = build([agent("P_hr1")], usage_monitoring=True)
    tenant.status = "running"
    guard.run_cycle()                                   # creates the query
    assert len(tenant.queries) == 1 and tenant.queries[0]["recordTypeFilters"] == ["copilotInteraction"]
    guard.run_cycle()                                   # still running: nothing yet
    assert not records(audit, "usage_violation")
    tenant.status = "succeeded"
    tenant.records = [interaction("r1", "P_hr1"), interaction("r2", "P_hr1"),
                      interaction("r3", "P_hr1", user=OWNER, upn="olivia@contoso.com")]
    guard.run_cycle()
    (v,) = records(audit, "usage_violation")
    assert v["userPrincipalName"] == RITA_UPN and v["interactions"] == 2 and v["violationCount"] == 1
    assert "isn't approved for sharing" in v["reason"]
    assert alerts(tenant, "used by someone it isn't shared with")
    assert len(guard.state.violation_history["P_hr1"]) == 1   # counted once, not per interaction
    assert not tenant.packages["P_hr1"]["isBlocked"]          # evidence only: below the lock limit


def test_overlapping_windows_skip_records_already_seen(build):
    guard, tenant, audit = build([agent("P_hr1")], usage_monitoring=True)
    tenant.records = [interaction("r1", "P_hr1")]
    for _ in range(4):                                   # two full query rounds over the same record
        guard.run_cycle()
    assert len(tenant.queries) == 2 and len(records(audit, "usage_violation")) == 1
    second = tenant.queries[1]
    assert second["filterStartDateTime"] < guard.state.usage["until"]   # windows overlap


def test_use_reaching_the_lock_limit_blocks_and_locks_an_unshared_agent(build):
    guard, tenant, audit = build([agent("P_hr1")], usage_monitoring=True, repeat_violation_limit=1)
    tenant.records = [interaction("r1", "P_hr1")]
    guard.run_cycle()
    guard.run_cycle()
    assert tenant.packages["P_hr1"]["isBlocked"] and guard.state.data["P_hr1"]["locked"]
    assert records(audit, "repeat_violation_locked")
    guard.run_cycle()                                    # not shared, but locked: stays blocked
    assert ("unblock", "P_hr1") not in tenant.calls


def test_approved_agent_used_inside_and_outside_its_audience(build):
    entry = {"packageId": "P_hr1", "sharing": {"allowedPrincipals": [{"resourceType": "group", "resourceId": "g-hr"}]}}
    guard, tenant, audit = build([agent("P_hr1")], registry=FakeRegistry({"P_hr1": entry}), usage_monitoring=True)
    tenant.groups = {"u-member": ["g-hr"]}
    tenant.records = [interaction("r1", "P_hr1", user="u-member", upn="mo@contoso.com"),
                      interaction("r2", "P_hr1")]
    guard.run_cycle()
    guard.run_cycle()
    (v,) = records(audit, "usage_violation")
    assert v["userPrincipalName"] == RITA_UPN and v["reason"] == "used by someone outside its approved audience"


def test_unmatched_records_are_counted_not_accused(build):
    guard, tenant, audit = build([agent("P_hr1")], usage_monitoring=True)
    tenant.records = [interaction("r1", "P_other")]
    guard.run_cycle()
    guard.run_cycle()
    assert not records(audit, "usage_violation")
    assert records(audit, "usage_checked")[-1]["unmatched"] == 1


def test_failed_query_is_retried(build):
    guard, tenant, audit = build([agent("P_hr1")], usage_monitoring=True)
    tenant.status = "failed"
    guard.run_cycle()
    guard.run_cycle()
    assert any(e.get("stage") == "usage" for e in records(audit, "error"))
    guard.run_cycle()
    assert len(tenant.queries) == 2 and "pending" in guard.state.usage


def test_usage_monitoring_is_off_by_default(build):
    guard, tenant, audit = build([agent("P_hr1")])
    guard.run_cycle()
    assert tenant.queries == []


# ---- 2. Edits made and undone between checks ------------------------------------------
def edited(tenant, pid, when):
    tenant.packages[pid]["lastModifiedDateTime"] = when


def test_reverted_edit_is_reported(build):
    guard, tenant, audit = build([dict(agent("a"), lastModifiedDateTime="2026-11-23T08:00:00Z")])
    guard.run_cycle()
    edited(tenant, "a", "2026-11-23T08:03:00Z")          # modified, but reads the same
    guard.run_cycle()
    (rec,) = records(audit, "edit_between_checks")
    assert rec["previousModified"] == "2026-11-23T08:00:00Z" and rec["approved"] is False
    assert rec.get("violationCount") is None             # "report": not counted
    assert not alerts(tenant, "changed back")             # personal agent: audit only


def test_visible_changes_and_guard_actions_are_not_reported(build):
    guard, tenant, audit = build([dict(agent("a"), lastModifiedDateTime="2026-11-23T08:00:00Z")])
    guard.run_cycle()
    edited(tenant, "a", "2026-11-23T08:03:00Z")
    tenant.packages["a"]["displayName"] = "Renamed"      # a real change
    guard.run_cycle()
    tenant.packages["a"]["sharedWithUsersAndGroups"] = [{"resourceType": "user", "resourceId": RITA}]
    guard.run_cycle()                                     # blocked by the guard
    edited(tenant, "a", "2026-11-23T08:10:00Z")          # the block may touch lastModifiedDateTime
    guard.run_cycle()
    assert not records(audit, "edit_between_checks")


def test_reverted_edit_on_an_approved_agent_alerts_governance(build):
    entry = {"packageId": "a", "sharing": {"allowedPrincipals": []}, "governanceContacts": ["gov@contoso.com"]}
    guard, tenant, audit = build([dict(agent("a"), lastModifiedDateTime="2026-11-23T08:00:00Z")],
                                 registry=FakeRegistry({"a": entry}))
    guard.run_cycle()
    edited(tenant, "a", "2026-11-23T08:03:00Z")
    guard.run_cycle()
    assert records(audit, "edit_between_checks")[0]["approved"] is True
    assert alerts(tenant, "changed back")


def test_violation_mode_counts_and_can_lock(build):
    guard, tenant, audit = build([dict(agent("a"), lastModifiedDateTime="2026-11-23T08:00:00Z")],
                                 between_check_edits="violation", repeat_violation_limit=2)
    guard.run_cycle()
    edited(tenant, "a", "2026-11-23T08:03:00Z")
    guard.run_cycle()
    assert records(audit, "edit_between_checks")[0]["violationCount"] == 1 and not tenant.packages["a"]["isBlocked"]
    edited(tenant, "a", "2026-11-23T08:06:00Z")
    guard.run_cycle()
    assert tenant.packages["a"]["isBlocked"] and guard.state.data["a"]["locked"]


def test_edit_watch_off_and_validated(build, tmp_path):
    guard, tenant, audit = build([dict(agent("a"), lastModifiedDateTime="2026-11-23T08:00:00Z")],
                                 between_check_edits="off")
    guard.run_cycle()
    edited(tenant, "a", "2026-11-23T08:03:00Z")
    guard.run_cycle()
    assert not records(audit, "edit_between_checks")
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"tenant_id": "t", "client_id": "c", "client_secret": "s",
                             "between_check_edits": "sometimes"}))
    with pytest.raises(ValueError, match="between_check_edits"):
        Config.load(str(p))
