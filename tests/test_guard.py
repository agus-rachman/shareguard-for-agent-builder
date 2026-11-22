# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""Tests for ShareGuard for Agent Builder (ABSG) against an in-memory fake of the Package Management API."""
import os


import pytest

from absg.core import (AGENT_BUILDER_PLATFORM, Config, GraphClient, GraphError,
                               Guard, StateStore)


class FakeGraph:
    def __init__(self, packages):
        self.packages = {p["id"]: p for p in packages}
        self.calls = []

    def list_agent_builder_packages(self):
        return [p for p in self.packages.values() if p.get("platform") == AGENT_BUILDER_PLATFORM]

    def get_package(self, pid):
        if self.packages[pid].get("fail"):
            raise GraphError(500, "boom")
        return dict(self.packages[pid])

    def block(self, pid):
        self.calls.append(("block", pid))
        self.packages[pid]["isBlocked"] = True

    def unblock(self, pid):
        self.calls.append(("unblock", pid))
        self.packages[pid]["isBlocked"] = False


def pkg(pid, shared=None, blocked=False, platform=AGENT_BUILDER_PLATFORM, **kw):
    return {"id": pid, "displayName": pid, "platform": platform, "isBlocked": blocked,
            "sharedWithUsersAndGroups": shared or [], "availableTo": kw.pop("availableTo", "some"),
            **kw}


USER = {"resourceType": "user", "resourceId": "u-1"}
GROUP = {"resourceType": "group", "resourceId": "g-1"}


@pytest.fixture
def cfg(tmp_path):
    return Config(tenant_id="t", client_id="c", client_secret="s",
                  state_file=str(tmp_path / "state.json"))


def make(cfg, packages):
    graph = FakeGraph(packages)
    events = []
    guard = Guard(cfg, graph, StateStore(cfg.state_file), lambda e, p: events.append((e, p)))
    return guard, graph, events


def test_unshared_agent_left_alone(cfg):
    guard, graph, _ = make(cfg, [pkg("a")])
    guard.run_cycle()
    assert graph.calls == []


def test_shared_agent_is_blocked_and_recorded(cfg):
    guard, graph, events = make(cfg, [pkg("a", shared=[USER])])
    r = guard.run_cycle()
    assert graph.calls == [("block", "a")]
    assert r.blocked == ["a"]
    assert StateStore(cfg.state_file).is_ours("a")
    assert events[0][0] == "blocked"


def test_unblocked_after_sharing_removed(cfg):
    guard, graph, events = make(cfg, [pkg("a", shared=[GROUP])])
    guard.run_cycle()
    graph.packages["a"]["sharedWithUsersAndGroups"] = []
    r = guard.run_cycle()
    assert graph.calls == [("block", "a"), ("unblock", "a")]
    assert r.unblocked == ["a"]
    assert not StateStore(cfg.state_file).is_ours("a")


def test_stays_blocked_while_still_shared(cfg):
    guard, graph, _ = make(cfg, [pkg("a", shared=[USER])])
    guard.run_cycle()
    guard.run_cycle()
    assert graph.calls == [("block", "a")]


def test_admin_blocked_agent_never_unblocked(cfg):
    guard, graph, _ = make(cfg, [pkg("a", blocked=True)])
    guard.run_cycle()
    assert graph.calls == []


def test_manual_unblock_while_shared_is_reblocked(cfg):
    guard, graph, _ = make(cfg, [pkg("a", shared=[USER])])
    guard.run_cycle()
    graph.packages["a"]["isBlocked"] = False  # someone unblocks in admin centre
    r = guard.run_cycle()
    assert r.reblocked == ["a"]
    assert graph.calls == [("block", "a"), ("block", "a")]


def test_non_agent_builder_packages_ignored(cfg):
    guard, graph, _ = make(cfg, [pkg("cs", shared=[USER], platform="Copilot Studio")])
    guard.run_cycle()
    assert graph.calls == []


def test_available_to_all_counts_as_shared(cfg):
    guard, graph, _ = make(cfg, [pkg("a", availableTo="all")])
    guard.run_cycle()
    assert graph.calls == [("block", "a")]


def test_ignored_principal_not_counted(cfg):
    cfg.ignore_principal_ids = ["svc-1"]
    guard, graph, _ = make(cfg, [pkg("a", shared=[{"resourceType": "user", "resourceId": "svc-1"}])])
    guard.run_cycle()
    assert graph.calls == []


def test_exemption_skips_and_releases_existing_block(cfg):
    guard, graph, _ = make(cfg, [pkg("a", shared=[USER])])
    guard.run_cycle()
    cfg.exempt_ids = ["a"]
    r = guard.run_cycle()
    assert graph.calls == [("block", "a"), ("unblock", "a")]
    assert r.skipped_exempt == ["a"]


def test_dry_run_makes_no_changes(cfg):
    cfg.dry_run = True
    guard, graph, events = make(cfg, [pkg("a", shared=[USER])])
    r = guard.run_cycle()
    assert graph.calls == [] and r.blocked == ["a"]
    assert events[0][1]["dryRun"] is True
    assert not os.path.exists(cfg.state_file)


def test_circuit_breaker_limits_mass_blocking(cfg):
    cfg.max_blocks_per_cycle = 2
    guard, graph, events = make(cfg, [pkg(f"a{i}", shared=[USER]) for i in range(5)])
    r = guard.run_cycle()
    assert len(graph.calls) == 2 and r.circuit_breaker_tripped
    assert sum(1 for e, _ in events if e == "circuit_breaker") == 1


def test_error_on_one_package_does_not_stop_cycle(cfg):
    guard, graph, _ = make(cfg, [pkg("bad", fail=True), pkg("a", shared=[USER])])
    r = guard.run_cycle()
    assert r.errors == ["bad"] and graph.calls == [("block", "a")]


def test_deleted_package_forgotten(cfg):
    guard, graph, _ = make(cfg, [pkg("a", shared=[USER])])
    guard.run_cycle()
    del graph.packages["a"]
    guard.run_cycle()
    assert not StateStore(cfg.state_file).is_ours("a")


# ---- GraphClient paging / retry ----------------------------------------
class FakeResp:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body or {}, headers or {}
        self.text = str(body)

    def json(self):
        return self._body


class FakeSession:
    def __init__(self, responses):
        self.responses, self.urls = list(responses), []

    def request(self, method, url, **kw):
        self.urls.append((method, url))
        return self.responses.pop(0)


def test_graph_paging_and_retry(cfg, monkeypatch):
    monkeypatch.setattr("absg.core.time.sleep", lambda s: None)
    session = FakeSession([
        FakeResp(429, headers={"Retry-After": "1"}),
        FakeResp(200, {"value": [{"id": "a"}], "@odata.nextLink": "https://graph/next?x=1"}),
        FakeResp(200, {"value": [{"id": "b"}]}),
    ])
    client = GraphClient(cfg, session=session, token_provider=lambda: "tok")
    ids = [p["id"] for p in client.list_agent_builder_packages()]
    assert ids == ["a", "b"]
    assert "platform%20eq%20%27Microsoft%20365%20Copilot%20Agent%20Builder%27" in session.urls[0][1]
    assert session.urls[2][1] == "https://graph/next?x=1"


def test_graph_error_raised(cfg):
    client = GraphClient(cfg, session=FakeSession([FakeResp(403, {"error": "denied"})]),
                         token_provider=lambda: "tok")
    with pytest.raises(GraphError) as exc:
        client.get_package("a")
    assert exc.value.status == 403


# ---- Audit trail ---------------------------------------------------------
import json as _json

from absg.core import AuditLog, audit_history, main, verify_audit_log


def make_audited(cfg, tmp_path, packages):
    graph = FakeGraph(packages)
    audit = AuditLog(str(tmp_path / "audit.jsonl"), actor={"clientId": "c"})
    guard = Guard(cfg, graph, StateStore(cfg.state_file), audit=audit)
    return guard, graph, audit


def read(path):
    return [_json.loads(l) for l in open(path) if l.strip()]


def test_audit_records_block_and_unblock_lifecycle(cfg, tmp_path):
    guard, graph, audit = make_audited(cfg, tmp_path, [pkg("a", shared=[USER])])
    guard.run_cycle()
    graph.packages["a"]["sharedWithUsersAndGroups"] = []
    guard.run_cycle()
    recs = read(audit.path)
    events = [r["event"] for r in recs]
    assert events == ["cycle_start", "block", "welcome_baseline", "cycle_end",
                      "cycle_start", "unblock", "cycle_end"]
    block = recs[1]
    assert block["package"]["id"] == "a" and block["outcome"] == "success"
    assert block["before"]["isBlocked"] is False and block["after"]["isBlocked"] is True
    assert block["recipients"] == [USER] and block["actor"] == {"clientId": "c"}
    assert recs[5]["originallyBlockedAt"] is not None
    assert block["cycleId"] == recs[0]["cycleId"] != recs[4]["cycleId"]
    assert verify_audit_log(audit.path).ok


def test_audit_dry_run_marked_simulated(cfg, tmp_path):
    cfg.dry_run = True
    guard, _, audit = make_audited(cfg, tmp_path, [pkg("a", shared=[USER])])
    guard.run_cycle()
    block = [r for r in read(audit.path) if r["event"] == "block"][0]
    assert block["outcome"] == "simulated" and block["dryRun"] is True


def test_audit_records_failed_block(cfg, tmp_path):
    guard, graph, audit = make_audited(cfg, tmp_path, [pkg("a", shared=[USER])])
    graph.block = lambda pid: (_ for _ in ()).throw(GraphError(403, "denied"))
    r = guard.run_cycle()
    block = [x for x in read(audit.path) if x["event"] == "block"]
    assert len(block) == 1 and block[0]["outcome"] == "failed" and "403" in block[0]["error"]
    assert r.errors == ["a"] and not StateStore(cfg.state_file).is_ours("a")


def test_audit_reblock_exempt_and_breaker_events(cfg, tmp_path):
    cfg.max_blocks_per_cycle = 1
    guard, graph, audit = make_audited(cfg, tmp_path,
                                       [pkg("a", shared=[USER]), pkg("b", shared=[USER])])
    guard.run_cycle()
    events = [r["event"] for r in read(audit.path)]
    assert "circuit_breaker" in events and "block_deferred" in events
    graph.packages["a"]["isBlocked"] = False
    cfg.exempt_ids = ["b"]
    guard.run_cycle()
    events = [r["event"] for r in read(audit.path)]
    assert "reblock" in events and "exempt_skip" in events


def test_audit_no_action_optional(cfg, tmp_path):
    guard, _, audit = make_audited(cfg, tmp_path, [pkg("a")])
    guard.run_cycle()
    assert "no_action" not in [r["event"] for r in read(audit.path)]
    cfg.audit_no_action = True
    guard.run_cycle()
    na = [r for r in read(audit.path) if r["event"] == "no_action"]
    assert na and na[0]["reason"] == "compliant: not shared"


def test_audit_chain_resumes_across_restarts(cfg, tmp_path):
    guard, _, audit = make_audited(cfg, tmp_path, [pkg("a", shared=[USER])])
    guard.run_cycle()
    AuditLog(audit.path).record("daemon_stop")
    v = verify_audit_log(audit.path)
    assert v.ok and v.records == 5


@pytest.mark.parametrize("tamper", ["edit", "delete", "reorder"])
def test_audit_tamper_detected(cfg, tmp_path, tamper):
    guard, graph, audit = make_audited(cfg, tmp_path, [pkg("a", shared=[USER])])
    guard.run_cycle()
    graph.packages["a"]["sharedWithUsersAndGroups"] = []
    guard.run_cycle()
    lines = open(audit.path).read().splitlines()
    if tamper == "edit":
        rec = _json.loads(lines[1]); rec["reason"] = "nothing to see"; lines[1] = _json.dumps(rec)
    elif tamper == "delete":
        del lines[1]
    else:
        lines[1], lines[2] = lines[2], lines[1]
    open(audit.path, "w").write("\n".join(lines) + "\n")
    v = verify_audit_log(audit.path)
    assert not v.ok and v.first_bad_seq == 2


def test_audit_history_filters(cfg, tmp_path):
    guard, graph, audit = make_audited(cfg, tmp_path,
                                       [pkg("a", shared=[USER]), pkg("b", shared=[GROUP])])
    guard.run_cycle()
    assert {r["event"] for r in audit_history(audit.path, package_id="a")} == {"block"}
    assert len(audit_history(audit.path, event="block")) == 2
    assert audit_history(audit.path, since="2999-01-01") == []


def test_cli_verify_and_history(cfg, tmp_path, capsys):
    guard, _, audit = make_audited(cfg, tmp_path, [pkg("a", shared=[USER])])
    guard.run_cycle()
    assert main(["--verify-audit", audit.path]) == 0
    assert _json.loads(capsys.readouterr().out)["ok"] is True
    assert main(["--audit-history", audit.path, "--event", "block"]) == 0
    out = [l for l in capsys.readouterr().out.splitlines() if l]
    assert len(out) == 1 and _json.loads(out[0])["package"]["id"] == "a"


# ---- A cycle that aborts part-way must not orphan its blocks ---------------------
def test_blocks_survive_a_listing_failure_and_are_released_later(cfg):
    class FlakyGraph(FakeGraph):
        def list_agent_builder_packages(self):
            yield self.packages["a"]
            raise GraphError(503, "paging failed")

    graph = FlakyGraph([pkg("a", shared=[USER])])
    guard = Guard(cfg, graph, StateStore(cfg.state_file))
    with pytest.raises(GraphError):
        guard.run_cycle()
    assert graph.calls == [("block", "a")]
    assert StateStore(cfg.state_file).is_ours("a")

    graph2 = FakeGraph([dict(graph.packages["a"], sharedWithUsersAndGroups=[])])
    Guard(cfg, graph2, StateStore(cfg.state_file)).run_cycle()
    assert graph2.calls == [("unblock", "a")]


def test_unexpected_error_on_one_package_does_not_abort_the_cycle(cfg):
    class Graph(FakeGraph):
        def get_package(self, pid):
            if pid == "a":
                raise KeyError("unexpected shape")
            return super().get_package(pid)

    graph = Graph([pkg("a", shared=[USER]), pkg("b", shared=[USER])])
    r = Guard(cfg, graph, StateStore(cfg.state_file)).run_cycle()
    assert r.errors == ["a"] and r.blocked == ["b"]
    assert StateStore(cfg.state_file).is_ours("b")


# ---- Block and unblock run as the delegated account ------------------------------
class DelegatedGraph(FakeGraph):
    """The delegated client: same tenant, its own call log."""

    def __init__(self, app_graph, fail=None):
        self.packages = app_graph.packages
        self.calls = []
        self.fail = fail

    def block(self, pid):
        if self.fail:
            raise GraphError(self.fail, "Delegated sign-in missing or expired: run --login-delegated")
        super().block(pid)


def test_block_and_unblock_use_the_delegated_account(cfg):
    cfg.delegated_username = "svc-absg@contoso.com"
    graph = FakeGraph([pkg("a", shared=[USER])])
    delegated = DelegatedGraph(graph)
    guard = Guard(cfg, graph, StateStore(cfg.state_file), delegated_graph=delegated)
    guard.run_cycle()
    graph.packages["a"]["sharedWithUsersAndGroups"] = []
    guard.run_cycle()
    assert graph.calls == []                                   # never app-only
    assert delegated.calls == [("block", "a"), ("unblock", "a")]


def test_application_identity_when_configured_or_no_delegated_client(cfg, caplog):
    graph = FakeGraph([pkg("a", shared=[USER])])
    Guard(cfg, graph, StateStore(cfg.state_file)).run_cycle()  # no delegated client: falls back
    assert graph.calls == [("block", "a")]
    assert "no delegated client is configured" in caplog.text

    cfg.block_identity = "application"
    graph2 = FakeGraph([pkg("b", shared=[USER])])
    delegated = DelegatedGraph(graph2)
    Guard(cfg, graph2, StateStore(cfg.state_file), delegated_graph=delegated).run_cycle()
    assert graph2.calls == [("block", "b")] and delegated.calls == []


def test_refused_delegated_block_alerts_once_per_cycle(cfg, tmp_path):
    from absg.core import AuditLog
    import json
    cfg.delegated_username = "svc-absg@contoso.com"
    graph = FakeGraph([pkg("a", shared=[USER]), pkg("b", shared=[USER])])
    events = []
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    guard = Guard(cfg, graph, StateStore(cfg.state_file), lambda e, p: events.append(e), audit=audit,
                  delegated_graph=DelegatedGraph(graph, fail=401))
    r = guard.run_cycle()
    assert sorted(r.errors) == ["a", "b"] and not r.blocked
    assert not StateStore(cfg.state_file).is_ours("a")          # nothing recorded as blocked
    recs = [json.loads(line) for line in open(tmp_path / "audit.jsonl")]
    failed = [x for x in recs if x["event"] == "block"]
    assert {x["outcome"] for x in failed} == {"failed"}
    assert {x["actingIdentity"] for x in failed} == {"svc-absg@contoso.com"}
    assert [x["event"] for x in recs].count("enforcement_identity_failed") == 1
    assert events.count("enforcement_identity_failed") == 1
    guard.run_cycle()                                           # alerted again next cycle
    assert events.count("enforcement_identity_failed") == 2


def test_block_identity_is_validated(tmp_path):
    import json
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"tenant_id": "t", "client_id": "c", "client_secret": "s", "block_identity": "root"}))
    with pytest.raises(ValueError, match="block_identity"):
        Config.load(str(p))


def test_reassign_uses_the_delegated_account(cfg):
    from absg.mail import OwnerResolver
    cfg.ownerless_action = "reassign_to_manager"
    cfg.delegated_username = "svc-absg@contoso.com"

    class Directory(FakeGraph):
        def user_status(self, uid):
            return {"u-1": "disabled", "mgr": "active"}.get(uid, "deleted")

        def manager_of(self, uid):
            return "mgr" if uid == "u-1" else None

        def reassign(self, pid, uid):
            self.calls.append(("reassign", pid, uid))

    class DelegatedDirectory(DelegatedGraph):
        def reassign(self, pid, uid):
            self.calls.append(("reassign", pid, uid))

    graph = Directory([pkg("a", allowedUsersAndGroups=[{"resourceType": "user", "resourceId": "u-1"}])])
    delegated = DelegatedDirectory(graph)
    state = StateStore(cfg.state_file)
    guard = Guard(cfg, graph, state, owner_resolver=OwnerResolver([], None, state.package_owners),
                  delegated_graph=delegated)
    assert guard.run_cycle().reassigned == ["a"]
    assert delegated.calls == [("reassign", "a", "mgr")] and graph.calls == []
