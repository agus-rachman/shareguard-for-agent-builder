# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""Repeat violations: the Nth block in the window locks the agent until governance releases it."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from absg.core import Config, FileLockReleases, main
from absg.sharepoint import SharePointLockReleases, SharePointSite
import test_flows
from test_flows import OTHER, OWNER, agent

env = test_flows.env            # the flows test fixture: guard, fake tenant, mailer, acknowledgements

SHARE = [{"resourceType": "user", "resourceId": OTHER}]


def records(audit, event):
    return [json.loads(line) for line in open(audit.path) if json.loads(line)["event"] == event]


def share_and_unshare(guard, tenant, times):
    for _ in range(times):
        tenant.packages["a"]["sharedWithUsersAndGroups"] = SHARE
        guard.run_cycle()
        tenant.packages["a"]["sharedWithUsersAndGroups"] = []
        guard.run_cycle()


@pytest.fixture
def locked(env, tmp_path):
    """An agent blocked for sharing three times: locked on the third block."""
    guard, tenant, audit, signer, acks, cfg = env([agent("a")], lock_releases_file=str(tmp_path / "releases.json"))
    share_and_unshare(guard, tenant, 2)
    assert tenant.calls.count(("unblock", "a")) == 2 and not guard.state.data.get("a")
    tenant.packages["a"]["sharedWithUsersAndGroups"] = SHARE
    guard.run_cycle()                                       # third violation
    return guard, tenant, audit, acks, cfg


def test_third_violation_locks_the_agent(locked):
    guard, tenant, audit, acks, cfg = locked
    entry = guard.state.data["a"]
    assert entry["locked"] and len(entry["violationTimes"]) == 3
    (rec,) = records(audit, "repeat_violation_locked")
    assert rec["violationCount"] == 3 and rec["windowDays"] == 30
    assert records(audit, "block")[-1]["violationCount"] == 3
    notice = [m for m in tenant.mails_to("olivia@contoso.com") if "until governance reviews it" in m["subject"]]
    assert len(notice) == 1 and "guard.contoso.com/ack" not in notice[0]["body"]["content"]   # no self-service
    assert any("locked after repeated violations" in m["subject"] for m in tenant.mails_to("it@contoso.com"))


def test_removing_sharing_does_not_release_a_locked_agent(locked):
    guard, tenant, audit, acks, cfg = locked
    tenant.packages["a"]["sharedWithUsersAndGroups"] = []
    guard.run_cycle()
    guard.run_cycle()
    assert tenant.calls.count(("unblock", "a")) == 2 and tenant.packages["a"]["isBlocked"]
    assert len(records(audit, "unblock_withheld")) == 1          # reported once, not every cycle


def test_owner_confirmation_is_rejected_while_locked(locked):
    guard, tenant, audit, acks, cfg = locked
    # A link from an earlier notice, for the current case, would otherwise remove sharing and unblock.
    acks.submit({"caseId": guard.state.data["a"]["caseId"], "packageId": "a", "ownerId": OWNER, "tokenId": "t"})
    guard.run_cycle()
    assert not tenant.patches and tenant.packages["a"]["isBlocked"]
    assert "locked after repeated violations" in records(audit, "ack_rejected")[-1]["reason"]


def test_governance_release_unblocks_and_resets_the_count(locked):
    guard, tenant, audit, acks, cfg = locked
    FileLockReleases(cfg.lock_releases_file).add("a", "jane.risk@contoso.com", "Reviewed with the owner")
    tenant.packages["a"]["sharedWithUsersAndGroups"] = []
    guard.run_cycle()
    (rec,) = records(audit, "lock_released")
    assert rec["releasedBy"] == "jane.risk@contoso.com" and rec["reason"] == "Reviewed with the owner"
    assert tenant.calls.count(("unblock", "a")) == 3 and "a" not in guard.state.violation_history
    tenant.packages["a"]["sharedWithUsersAndGroups"] = SHARE       # a fresh start: one violation, not locked
    guard.run_cycle()
    assert not guard.state.data["a"].get("locked") and records(audit, "block")[-1]["violationCount"] == 1


def test_release_while_still_shared_keeps_it_blocked_for_sharing(locked):
    guard, tenant, audit, acks, cfg = locked
    FileLockReleases(cfg.lock_releases_file).add("a", "jane.risk@contoso.com", "ok")
    guard.run_cycle()
    assert records(audit, "lock_released") and tenant.packages["a"]["isBlocked"]
    assert not guard.state.data["a"].get("locked")


def test_owner_cannot_release_their_own_agent(locked):
    guard, tenant, audit, acks, cfg = locked
    FileLockReleases(cfg.lock_releases_file).add("a", "olivia@contoso.com", "please")
    tenant.packages["a"]["sharedWithUsersAndGroups"] = []
    guard.run_cycle()
    assert records(audit, "lock_release_rejected") and guard.state.data["a"]["locked"]


def test_release_older_than_the_lock_is_ignored(locked):
    guard, tenant, audit, acks, cfg = locked
    path = cfg.lock_releases_file
    FileLockReleases(path).add("a", "jane.risk@contoso.com", "old")
    data = json.load(open(path))
    data["releases"][0]["requestedAt"] = "2020-01-01T00:00:00+00:00"
    json.dump(data, open(path, "w"))
    tenant.packages["a"]["sharedWithUsersAndGroups"] = []
    guard.run_cycle()
    assert guard.state.data["a"]["locked"] and not records(audit, "lock_released")


def test_violations_outside_the_window_do_not_count(env, tmp_path):
    guard, tenant, audit, *_ = env([agent("a")], repeat_violation_window_days=7)
    share_and_unshare(guard, tenant, 2)
    old = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
    guard.state.violation_history["a"] = [old, old]
    tenant.packages["a"]["sharedWithUsersAndGroups"] = SHARE
    guard.run_cycle()
    assert not guard.state.data["a"].get("locked")
    assert records(audit, "block")[-1]["violationCount"] == 1


def test_limit_zero_turns_it_off(env):
    guard, tenant, audit, *_ = env([agent("a")], repeat_violation_limit=0)
    share_and_unshare(guard, tenant, 4)
    assert tenant.calls.count(("unblock", "a")) == 4 and not records(audit, "repeat_violation_locked")


def test_drift_blocks_can_be_left_out(env):
    guard, tenant, audit, *_ = env([agent("a")], repeat_violation_block_types=["drift"])
    share_and_unshare(guard, tenant, 3)
    assert not records(audit, "repeat_violation_locked")


def test_settings_are_validated(tmp_path):
    base = {"tenant_id": "t", "client_id": "c", "client_secret": "s"}
    for bad in ({"repeat_violation_limit": -1}, {"repeat_violation_window_days": 0},
                {"repeat_violation_block_types": ["retired"]}):
        p = tmp_path / "c.json"
        p.write_text(json.dumps({**base, **bad}))
        with pytest.raises(ValueError, match="repeat_violation"):
            Config.load(str(p))


def test_cli_lists_and_releases_locks(locked, capsys):
    guard, tenant, audit, acks, cfg = locked
    guard.state.save()
    conf = cfg.state_file.replace("state.json", "config.json")
    json.dump({"tenant_id": "t", "client_id": "c", "client_secret": "s", "state_file": cfg.state_file,
               "lock_releases_file": cfg.lock_releases_file}, open(conf, "w"))
    assert main(["--config", conf, "--list-locked"]) == 0
    assert json.loads(capsys.readouterr().out.splitlines()[0])["packageId"] == "a"
    assert main(["--config", conf, "--release-lock", "a"]) == 1          # --by and --reason required
    assert main(["--config", conf, "--release-lock", "a", "--by", "jane.risk@contoso.com",
                 "--reason", "Reviewed"]) == 0
    assert json.load(open(cfg.lock_releases_file))["releases"][0]["releasedBy"] == "jane.risk@contoso.com"
    assert main(["--config", conf, "--release-lock", "zzz", "--by", "x", "--reason", "y"]) == 1


def test_sharepoint_release_list(tmp_path):
    from test_azure import DownloadSession, FakeGraph
    g = FakeGraph()
    g.lists["Agent Lock Releases"] = {"5": {
        "id": "5", "createdDateTime": "2026-11-23T10:00:00Z",
        "createdBy": {"user": {"id": "jane-id", "email": "jane.risk@contoso.com"}},
        "fields": {"Title": " a ", "Reason": "Reviewed", "Status": "New"}}}
    site = SharePointSite(g, "ops", session=DownloadSession(g))
    src = SharePointLockReleases(site)
    (r,) = src.fetch()
    assert r == {"packageId": "a", "releasedBy": "jane.risk@contoso.com", "releasedById": "jane-id",
                 "reason": "Reviewed", "requestedAt": "2026-11-23T10:00:00Z", "ref": "5"}
    src.mark(r, "Applied")
    assert g.lists["Agent Lock Releases"]["5"]["fields"]["Status"] == "Applied"


# ---- Daily sharing limit per owner ------------------------------------------------
IDS = [f"a{i}" for i in range(1, 8)]


@pytest.fixture
def seven(env, tmp_path):
    """One owner shares seven agents in a day: the 6th and 7th are held until tomorrow."""
    guard, tenant, audit, signer, acks, cfg = env([agent(p) for p in IDS],
                                                  lock_releases_file=str(tmp_path / "releases.json"))
    guard.run_cycle()                                       # owners learned while unshared
    for p in IDS:
        tenant.packages[p]["sharedWithUsersAndGroups"] = SHARE
    guard.run_cycle()
    return guard, tenant, audit, acks, cfg


def test_agents_beyond_the_daily_limit_are_held(seven):
    guard, tenant, audit, acks, cfg = seven
    held = sorted(p for p, e in guard.state.data.items() if e.get("locked"))
    assert held == ["a6", "a7"] and all(guard.state.data[p]["lockKind"] == "daily" for p in held)
    until = guard.state.data["a6"]["lockUntil"]
    assert until == (datetime.now(timezone.utc).date() + timedelta(days=1)).isoformat() + "T00:00:00+00:00"
    recs = records(audit, "daily_share_limit_locked")
    assert [r["position"] for r in recs] == [6, 7] and recs[0]["limit"] == 5
    held_mail = [m for m in tenant.mails_to("olivia@contoso.com") if "is blocked until" in m["subject"]]
    assert len(held_mail) == 2 and "guard.contoso.com/ack" not in held_mail[0]["body"]["content"]
    normal = [m for m in tenant.mails_to("olivia@contoso.com") if m["subject"].startswith("Action needed")]
    assert len(normal) == 5                                  # the first five get the usual link


def test_held_agents_stay_blocked_until_the_next_day(seven):
    guard, tenant, audit, acks, cfg = seven
    for p in IDS:
        tenant.packages[p]["sharedWithUsersAndGroups"] = []
    guard.run_cycle()
    unblocked = {c[1] for c in tenant.calls if c[0] == "unblock"}
    assert unblocked == {"a1", "a2", "a3", "a4", "a5"}
    for p in ("a6", "a7"):                                   # next day
        guard.state.data[p]["lockUntil"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    guard.run_cycle()
    assert {c[1] for c in tenant.calls if c[0] == "unblock"} == set(IDS)
    assert len(records(audit, "lock_expired")) == 2


def test_still_shared_after_the_hold_gets_the_usual_link(seven):
    guard, tenant, audit, acks, cfg = seven
    guard.state.data["a6"]["lockUntil"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    before = len(tenant.mails_to("olivia@contoso.com"))
    guard.run_cycle()
    assert tenant.packages["a6"]["isBlocked"] and not guard.state.data["a6"].get("locked")
    new = tenant.mails_to("olivia@contoso.com")[before:]
    assert any("guard.contoso.com/ack" in m["body"]["content"] for m in new)


def test_governance_can_release_a_held_agent_early(seven):
    guard, tenant, audit, acks, cfg = seven
    FileLockReleases(cfg.lock_releases_file).add("a6", "jane.risk@contoso.com", "Pilot team agent")
    tenant.packages["a6"]["sharedWithUsersAndGroups"] = []
    guard.run_cycle()
    assert ("unblock", "a6") in tenant.calls and guard.state.data["a7"]["locked"]


def test_daily_count_starts_again_each_day(env):
    guard, tenant, audit, *_ = env([agent(p) for p in IDS])
    guard.run_cycle()
    guard.state.daily_shares[OWNER] = {"day": "2020-01-01", "agents": ["x1", "x2", "x3", "x4", "x5"]}
    tenant.packages["a1"]["sharedWithUsersAndGroups"] = SHARE
    guard.run_cycle()
    assert not guard.state.data["a1"].get("locked")
    assert guard.state.daily_shares[OWNER]["agents"] == ["a1"]


def test_same_agent_reblocked_counts_once_a_day(env):
    guard, tenant, audit, *_ = env([agent("a")], daily_share_limit_per_owner=1, repeat_violation_limit=0)
    guard.run_cycle()
    share_and_unshare(guard, tenant, 3)
    assert guard.state.daily_shares[OWNER]["agents"] == ["a"] and not records(audit, "daily_share_limit_locked")


def test_daily_limit_zero_turns_it_off(env):
    guard, tenant, audit, *_ = env([agent(p) for p in IDS], daily_share_limit_per_owner=0)
    guard.run_cycle()
    for p in IDS:
        tenant.packages[p]["sharedWithUsersAndGroups"] = SHARE
    guard.run_cycle()
    assert not records(audit, "daily_share_limit_locked")


def test_daily_limit_is_validated(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"tenant_id": "t", "client_id": "c", "client_secret": "s",
                             "daily_share_limit_per_owner": -1}))
    with pytest.raises(ValueError, match="daily_share_limit_per_owner"):
        Config.load(str(p))
