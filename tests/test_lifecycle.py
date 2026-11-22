# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""Multiple owners, ownerless agents and inactivity retirement."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from absg.ack import AckStore, AckTokenSigner
from absg.core import AuditLog, Config, GraphError, Guard, StateStore
from absg.mail import Mailer, OwnerResolver
from absg.registry import draft_entry, entry_owners, evaluate, generate_keypair, sign_entry
from test_flows import AGENT_BUILDER_PLATFORM, OWNER, SECRET, FakeTenant, Resp, ack_token_from, events

CO = "owner-2"
SHARE = [{"resourceType": "group", "resourceId": "g-fin"}]


def ago(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")


def agent(pid, owners=(OWNER,), shared=None, blocked=False, last_used=None, created=400):
    return {"id": pid, "displayName": f"Agent {pid}", "platform": AGENT_BUILDER_PLATFORM,
            "isBlocked": blocked, "availableTo": "some", "owners": list(owners),
            "allowedUsersAndGroups": [{"resourceType": "user", "resourceId": owners[0]}] if owners else [],
            "sharedWithUsersAndGroups": shared or [],
            "createdDateTime": ago(created), "lastModifiedDateTime": ago(created),
            "lastUsedDateTime": last_used,
            "elementDetails": [{"elementType": "declarativeAgent", "elements": [{"id": "e1", "definition": json.dumps(
                {"name": f"Agent {pid}", "instructions": "Help.", "capabilities": []})}]}]}


class LifecycleTenant(FakeTenant):
    def __init__(self, packages):
        super().__init__(packages)
        self.status = {OWNER: "active", CO: "active", "mgr-1": "active"}
        self.managers = {OWNER: "mgr-1"}
        self.users["mgr-1"] = {"id": "mgr-1", "displayName": "Mia Manager", "mail": "mia@contoso.com"}
        self.reassigned = []

    def user_status(self, uid):
        return self.status.get(uid, "deleted")

    def manager_of(self, uid):
        return self.managers.get(uid)

    def reassign(self, pid, uid):
        self.reassigned.append((pid, uid))
        self.packages[pid]["owners"] = [uid]


@pytest.fixture
def env(tmp_path):
    def build(packages, registry=None, **over):
        cfg = Config(tenant_id="t", client_id="c", client_secret="x",
                     state_file=str(tmp_path / "state.json"), audit_file=str(tmp_path / "audit.jsonl"),
                     ack_store_file=str(tmp_path / "acks.json"),
                     mail_sender="governance@contoso.com", admin_emails=["it@contoso.com"],
                     ack_enabled=True, ack_base_url="https://guard.contoso.com/ack", ack_secret=SECRET,
                     owner_fields=["owners"], **over)
        tenant = LifecycleTenant(packages)
        state = StateStore(cfg.state_file)
        state.baseline_done = True          # skip the first-run welcome baseline
        audit = AuditLog(cfg.audit_file, actor={"clientId": "c"})
        acks = AckStore(cfg.ack_store_file)
        guard = Guard(cfg, tenant, state, audit=audit,
                      mailer=Mailer(tenant, cfg.mail_sender, cfg.admin_emails),
                      owner_resolver=OwnerResolver(cfg.owner_fields, None, state.package_owners),
                      signer=AckTokenSigner(SECRET, 1), acks=acks, delegated_graph=tenant,
                      registry=registry)
        return guard, tenant, audit, acks
    return build


def records(audit, event):
    return [json.loads(line) for line in open(audit.path) if f'"{event}"' in line]


# ---- multiple owners --------------------------------------------------------
def test_every_owner_gets_a_notice_and_either_can_acknowledge(env):
    guard, tenant, audit, acks = env([agent("a", owners=(OWNER, CO), shared=SHARE)])
    guard.run_cycle()
    olivia, noah = tenant.mails_to("olivia@contoso.com"), tenant.mails_to("noah@contoso.com")
    notices = [m for m in olivia + noah if "blocked" in m["subject"]]
    assert len(notices) == 2
    block = records(audit, "block")[0]
    assert block["ownerIds"] == [OWNER, CO]
    # the co-owner confirms with their own link
    from absg.ack import AckTokenSigner as S
    claims = S(SECRET).verify(ack_token_from([m for m in noah if "blocked" in m["subject"]][0]))
    assert claims.owner_id == CO
    acks.submit({"caseId": claims.case_id, "packageId": "a", "ownerId": CO, "tokenId": claims.token_id})
    guard.run_cycle()
    assert tenant.patches and ("unblock", "a") in tenant.calls


def test_owner_rules_in_registry_evaluation():
    d = agent("a", owners=(OWNER, CO))
    entry = draft_entry(d, [OWNER], [])
    assert entry_owners(entry) == [OWNER] and entry["ownerId"] == OWNER
    ev = evaluate(d, entry, [], ownership={"reported": [OWNER, CO], "inactive": []})
    assert [f.rule for f in ev.violations] == ["OWNER-UNREGISTERED"]
    assert ev.violations[0].detail == {"unregisteredOwners": [CO]}
    entry2 = draft_entry(d, [OWNER, CO], [])
    assert evaluate(d, entry2, [], ownership={"reported": [OWNER, CO], "inactive": []}).compliant
    ev = evaluate(d, entry2, [], ownership={"reported": None, "inactive": [OWNER]})
    assert ev.compliant and [f.rule for f in ev.warnings] == ["OWNER-INACTIVE"]
    ev = evaluate(d, entry2, [], ownership={"reported": None, "inactive": [OWNER, CO]})
    assert [f.rule for f in ev.violations] == ["OWNER-NONE-ACTIVE"]
    assert evaluate(d, {**entry, "ownerId": OWNER, "owners": None}, [], ownership=None).compliant


def test_unregistered_co_owner_blocks_an_approved_agent(env, tmp_path):
    from absg.registry import Registry
    priv, pub = generate_keypair()
    d = agent("a", owners=(OWNER,), shared=SHARE)
    entry = sign_entry({**draft_entry(d, [OWNER], SHARE),
                        "approval": {"requestId": "REQ-1", "expiresAt": "2099-01-01"}}, priv)
    (tmp_path / "reg.json").write_text(json.dumps({"agents": [entry]}))
    (tmp_path / "pub.pem").write_bytes(pub)
    reg = Registry(str(tmp_path / "reg.json"), str(tmp_path / "pub.pem"))
    guard, tenant, audit, _ = env([d], registry=reg)
    guard.run_cycle()
    assert ("block", "a") not in tenant.calls                     # compliant
    tenant.packages["a"]["owners"] = [OWNER, CO]                  # a co-owner is added
    guard.run_cycle()
    assert ("block", "a") in tenant.calls
    assert records(audit, "block")[0]["violations"][0]["rule"] == "OWNER-UNREGISTERED"


# ---- ownerless ----------------------------------------------------------------
def test_ownerless_report_alerts_admins_once(env):
    guard, tenant, audit, _ = env([agent("a")])
    tenant.status[OWNER] = "deleted"
    guard.run_cycle()
    guard.run_cycle()
    assert len(records(audit, "ownerless_detected")) == 1
    assert len([m for m in tenant.mails_to("it@contoso.com") if "no active owner" in m["subject"]]) == 1
    assert ("block", "a") not in tenant.calls


def test_ownerless_reassigned_to_disabled_owners_manager(env):
    guard, tenant, audit, _ = env([agent("a")], ownerless_action="reassign_to_manager")
    tenant.status[OWNER] = "disabled"
    guard.run_cycle()
    assert tenant.reassigned == [("a", "mgr-1")]
    rec = records(audit, "ownership_reassigned")[0]
    assert rec["newOwner"] == "mgr-1" and rec["outcome"] == "success"
    assert any("You now own" in m["subject"] for m in tenant.mails_to("mia@contoso.com"))


def test_ownerless_block_and_release_when_an_owner_is_active(env):
    guard, tenant, audit, _ = env([agent("a")], ownerless_action="block")
    tenant.status[OWNER] = "disabled"
    guard.run_cycle()
    assert ("block", "a") in tenant.calls
    assert records(audit, "block")[0]["blockType"] == "ownerless"
    assert not [m for m in tenant.mails_to("olivia@contoso.com") if "blocked" in m["subject"]]
    assert any("no owner has an active account" in m["subject"] for m in tenant.mails_to("it@contoso.com"))
    tenant.packages["a"]["owners"] = [CO]                         # admin reassigned it
    guard.run_cycle()
    assert ("unblock", "a") in tenant.calls


# ---- inactivity ---------------------------------------------------------------
def shift(guard, pid, days):
    """Move the stored notice dates back in time, as if `days` had passed."""
    lc = guard.state.lifecycle[pid]
    for k in ("noticeAt", "retireOn", "reminderAt"):
        if lc.get(k):
            lc[k] = (datetime.fromisoformat(lc[k]) - timedelta(days=days)).isoformat()


def shift_entry(guard, pid, days, keys=("archiveOn", "retiredAt", "deletionRequestedAt",
                                         "deletionReminderAt", "deletionSubmittedAt")):
    e = guard.state.data[pid]
    for k in keys:
        if e.get(k):
            e[k] = (datetime.fromisoformat(e[k]) - timedelta(days=days)).isoformat()


def test_notice_period_before_retirement(env):
    # 90-day policy, 30-day notice: last used 59 days ago -> no notice yet; 61 -> notice
    guard, tenant, audit, _ = env([agent("a", last_used=ago(59))], inactivity_days=90)
    guard.run_cycle()
    assert not records(audit, "inactivity_warning")
    tenant.packages["a"]["lastUsedDateTime"] = ago(61)
    guard.run_cycle()
    rec = records(audit, "inactivity_warning")[0]
    assert rec["retireOn"][:10] == (datetime.now(timezone.utc) + timedelta(days=30)).date().isoformat()  # full notice
    mail = [m for m in tenant.mails_to("olivia@contoso.com") if "will be retired" in m["subject"]]
    assert len(mail) == 1 and "archives a copy" in mail[0]["body"]["content"]


def test_full_notice_even_when_already_past_the_limit(env):
    guard, tenant, audit, _ = env([agent("a", last_used=ago(300))], inactivity_days=90)
    guard.run_cycle()
    assert ("block", "a") not in tenant.calls
    rec = records(audit, "inactivity_warning")[0]
    assert rec["retireOn"][:10] == (datetime.now(timezone.utc) + timedelta(days=30)).date().isoformat()


def test_inactive_agent_noticed_reminded_retired_then_reactivated(env):
    guard, tenant, audit, acks = env([agent("a", last_used=ago(70))], inactivity_days=90)
    guard.run_cycle()
    assert len(records(audit, "inactivity_warning")) == 1
    guard.run_cycle()
    assert len(records(audit, "inactivity_warning")) == 1          # notice sent once
    shift(guard, "a", 24)                                         # 6 days left
    guard.run_cycle()
    assert records(audit, "inactivity_reminder")[0]["daysLeft"] <= 7
    assert any(m["subject"].startswith("Reminder:") for m in tenant.mails_to("olivia@contoso.com"))
    assert ("block", "a") not in tenant.calls
    shift(guard, "a", 7)                                          # retirement date passed
    guard.run_cycle()
    assert ("block", "a") in tenant.calls
    block = records(audit, "block")[-1]
    assert block["blockType"] == "retired" and block["archiveOn"]
    retired = [m for m in tenant.mails_to("olivia@contoso.com") if m["subject"].endswith("has been retired")][0]
    assert "Reactivate my agent" in retired["body"]["content"]
    assert "deletes it from Microsoft 365" in retired["body"]["content"]
    claims = AckTokenSigner(SECRET).verify(ack_token_from(retired))
    acks.submit({"caseId": claims.case_id, "packageId": "a", "ownerId": OWNER, "tokenId": claims.token_id})
    guard.run_cycle()
    assert ("unblock", "a") in tenant.calls and not tenant.patches  # no sharing to remove
    assert records(audit, "unblock")[-1]["reason"] == "owner reactivated a retired agent"
    assert any("active again" in m["subject"] for m in tenant.mails_to("olivia@contoso.com"))
    guard.run_cycle()
    assert tenant.calls.count(("block", "a")) == 1                 # the clock was reset


class ArchiveTenant(LifecycleTenant):
    def __init__(self, packages, delete_status=None):
        super().__init__(packages)
        self.deleted, self.delete_status = [], delete_status

    def request(self, method, url, json=None, **kw):
        if method == "DELETE":
            if self.delete_status:
                raise GraphError(self.delete_status, "not supported")
            pid = url.rsplit("/", 1)[1]
            self.deleted.append(pid)
            self.delete_urls = [*getattr(self, "delete_urls", []), url]
            self.packages.pop(pid)
            return Resp()
        return super().request(method, url, json=json, **kw)


def retire(guard, tenant):
    guard.run_cycle()                     # notice
    shift(guard, "a", 31)
    guard.run_cycle()                     # retired
    assert ("block", "a") in tenant.calls


def test_retired_agent_archived_then_deleted_by_admin(env, tmp_path):
    guard, tenant, audit, _ = env([agent("a", last_used=ago(200))], inactivity_days=90,
                                  archive_dir=str(tmp_path / "archive"))
    tenant.__class__ = ArchiveTenant
    tenant.deleted, tenant.delete_status = [], None
    retire(guard, tenant)
    guard.run_cycle()
    assert not records(audit, "agent_archived")                    # 30-day grace period
    shift_entry(guard, "a", 31)
    guard.run_cycle()
    arch = records(audit, "agent_archived")[0]
    folder = tmp_path / "archive" / arch["archive"]["reference"]
    manifest = json.loads((folder / "manifest.json").read_text())
    assert manifest["packageId"] == "a" and manifest["owners"][0]["displayName"] == "Olivia Owner"
    assert json.loads((folder / "agent.json").read_text())["id"] == "a"
    assert any("has been archived" in m["subject"] for m in tenant.mails_to("olivia@contoso.com"))
    req = records(audit, "deletion_requested")
    assert req and any("ready for deletion" in m["subject"] for m in tenant.mails_to("it@contoso.com"))
    guard.run_cycle()
    assert not records(audit, "deletion_reminder")                 # not yet
    shift_entry(guard, "a", 8)
    guard.run_cycle()
    assert len(records(audit, "deletion_reminder")) == 1
    tenant.packages.pop("a")                                       # admin deletes it in the portal
    guard.run_cycle()
    gone = records(audit, "agent_deleted")[0]
    assert gone["archiveReference"] == arch["archive"]["reference"]
    assert (folder / "status-deleted.json").exists()
    assert "a" not in guard.state.data


def test_api_deletion_mode_and_fallback(env, tmp_path):
    guard, tenant, audit, _ = env([agent("a", last_used=ago(200))], inactivity_days=90,
                                  archive_after_days=0, deletion_mode="api",
                                  archive_dir=str(tmp_path / "archive"))
    tenant.__class__ = ArchiveTenant
    tenant.deleted, tenant.delete_status = [], None
    retire(guard, tenant)
    guard.run_cycle()                     # archive (grace 0), then delete
    assert tenant.deleted == ["a"] and records(audit, "deletion_submitted")
    assert tenant.delete_urls == ["https://graph.microsoft.com/beta/copilot/admin/catalog/packages/a"]
    guard.run_cycle()
    assert records(audit, "agent_deleted")


def test_api_deletion_falls_back_to_admin(env, tmp_path):
    guard, tenant, audit, _ = env([agent("a", last_used=ago(200))], inactivity_days=90,
                                  archive_after_days=0, deletion_mode="api",
                                  archive_dir=str(tmp_path / "archive"))
    tenant.__class__ = ArchiveTenant
    tenant.deleted, tenant.delete_status = [], 405
    retire(guard, tenant)
    guard.run_cycle()
    assert records(audit, "deletion_failed") and records(audit, "deletion_requested")


def test_reactivation_after_archive_cancels_deletion(env, tmp_path):
    guard, tenant, audit, acks = env([agent("a", last_used=ago(200))], inactivity_days=90,
                                     archive_after_days=0, archive_dir=str(tmp_path / "archive"))
    retire(guard, tenant)
    guard.run_cycle()
    assert records(audit, "deletion_requested")
    retired = [m for m in tenant.mails_to("olivia@contoso.com") if m["subject"].endswith("has been retired")][0]
    claims = AckTokenSigner(SECRET).verify(ack_token_from(retired))
    acks.submit({"caseId": claims.case_id, "packageId": "a", "ownerId": OWNER, "tokenId": claims.token_id})
    guard.run_cycle()
    assert ("unblock", "a") in tenant.calls and records(audit, "deletion_cancelled")
    assert any("Don't delete" in m["subject"] for m in tenant.mails_to("it@contoso.com"))


def test_archive_off_keeps_agent_blocked(env):
    guard, tenant, audit, _ = env([agent("a", last_used=ago(200))], inactivity_days=90,
                                  archive_after_days=None)
    retire(guard, tenant)
    shift_entry(guard, "a", 400, keys=("retiredAt", "blockedAt"))
    guard.run_cycle()
    assert not records(audit, "agent_archived") and ("block", "a") in tenant.calls


def test_use_after_warning_cancels_retirement(env):
    guard, tenant, audit, _ = env([agent("a", last_used=ago(65))], inactivity_days=90)
    guard.run_cycle()
    tenant.packages["a"]["lastUsedDateTime"] = ago(0)
    guard.run_cycle()
    assert records(audit, "inactivity_cleared")
    assert "a" not in guard.state.lifecycle or "noticeAt" not in guard.state.lifecycle["a"]


def test_retirement_respects_the_circuit_breaker(env):
    pkgs = [agent(f"p{i}", last_used=ago(200)) for i in range(5)]
    guard, tenant, audit, _ = env(pkgs, inactivity_days=90, max_blocks_per_cycle=2)
    guard.run_cycle()
    for i in range(5):
        shift(guard, f"p{i}", 31)
    guard.run_cycle()
    assert sum(1 for c in tenant.calls if c[0] == "block") == 2
    assert "circuit_breaker" in events(audit)


def test_never_used_agent_measured_from_creation(env):
    guard, tenant, audit, _ = env([agent("a", last_used="0001-01-01T00:00:00Z", created=10)],
                                  inactivity_days=90)
    guard.run_cycle()
    assert not records(audit, "inactivity_warning")


def test_lifecycle_settings_validated(tmp_path):
    def load(**extra):
        path = tmp_path / "cfg.json"
        path.write_text(json.dumps({"tenant_id": "t", "client_id": "c", "client_secret": "x", **extra}))
        return Config.load(str(path))
    cfg = load()
    assert cfg.ownerless_action == "report" and cfg.inactivity_days is None
    with pytest.raises(ValueError):
        load(ownerless_action="delete")
    with pytest.raises(ValueError):
        load(inactivity_days=10, inactivity_warning_days=14)      # older name still checked
    with pytest.raises(ValueError):
        load(inactivity_days=90, inactivity_reminder_days=30)
    with pytest.raises(ValueError):
        load(deletion_mode="purge")
    assert load(inactivity_days=90).inactivity_notice_days == 30


def test_graph_user_status_and_reassign_calls():
    from absg.core import GraphClient

    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kw):
            self.calls.append((method, url, kw.get("json")))

            class R:
                status_code, headers, text = 200, {}, ""

                def json(self):
                    return {"accountEnabled": False}
            r = R()
            if "/users/gone" in url:
                r.status_code, r.text = 404, "not found"
            return r
    cfg = Config(tenant_id="t", client_id="c", client_secret="x")
    s = Session()
    g = GraphClient(cfg, session=s, token_provider=lambda: "tok")
    assert g.user_status("u1") == "disabled"
    assert g.user_status("gone") == "deleted"
    g.reassign("P1", "m1")
    assert s.calls[-1] == ("POST", "https://graph.microsoft.com/beta/copilot/admin/catalog/packages/P1/reassign",
                           {"userId": "m1"})
    _ = (GraphError, Resp)


def test_package_reads_use_v1_and_writes_use_beta():
    """List and get are in v1.0; update, block, unblock and reassign are documented only in beta."""
    from absg.core import GraphClient

    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kw):
            self.calls.append((method, url))

            class R:
                status_code, headers, text = 200, {}, ""

                def json(self):
                    return {"value": []}
            return R()
    s = Session()
    g = GraphClient(Config(tenant_id="t", client_id="c", client_secret="x"), session=s, token_provider=lambda: "tok")
    list(g.list_agent_builder_packages())
    g.get_package("P1")
    g.update_package("P1", {"availableTo": "some"})
    g.block("P1")
    g.unblock("P1")
    g.reassign("P1", "u2")
    v1, beta = "https://graph.microsoft.com/v1.0/copilot/admin/catalog/packages", \
        "https://graph.microsoft.com/beta/copilot/admin/catalog/packages"
    assert s.calls[0][1].startswith(v1 + "?$filter=")
    assert s.calls[1:] == [("GET", f"{v1}/P1"), ("PATCH", f"{beta}/P1"), ("POST", f"{beta}/P1/block"),
                           ("POST", f"{beta}/P1/unblock"), ("POST", f"{beta}/P1/reassign")]
    # A national or test cloud can point both bases elsewhere.
    g = GraphClient(Config(tenant_id="t", client_id="c", client_secret="x",
                           graph_beta_base="https://graph.example.test/beta/"), session=s, token_provider=lambda: "t")
    g.block("P2")
    assert s.calls[-1] == ("POST", "https://graph.example.test/beta/copilot/admin/catalog/packages/P2/block")


# ---- lifting a lifecycle block never unblocks a shared, unapproved agent -----------
def test_ownerless_block_lifted_while_shared_stays_blocked_for_sharing(env):
    guard, tenant, audit, _ = env([agent("a")], ownerless_action="block")
    tenant.status[OWNER] = "disabled"
    guard.run_cycle()
    tenant.packages["a"]["sharedWithUsersAndGroups"] = SHARE        # shared while blocked
    tenant.packages["a"]["owners"] = [CO]                           # admin assigns an active owner
    guard.run_cycle()
    assert ("unblock", "a") not in tenant.calls
    (rec,) = records(audit, "block_reason_changed")
    assert rec["previousBlockType"] == "ownerless" and rec["blockType"] == "sharing"
    assert guard.state.data["a"]["blockType"] == "sharing" and guard.state.data["a"]["caseId"] == rec["caseId"]
    notice = [m for m in tenant.mails_to("noah@contoso.com") if "blocked" in m["subject"]]
    assert len(notice) == 1
    tenant.packages["a"]["sharedWithUsersAndGroups"] = []           # sharing removed: released
    guard.run_cycle()
    assert ("unblock", "a") in tenant.calls


def test_reactivating_a_shared_retired_agent_keeps_it_blocked(env):
    guard, tenant, audit, acks = env([agent("a", last_used=ago(70))], inactivity_days=90)
    guard.run_cycle()
    shift(guard, "a", 31)
    guard.run_cycle()
    assert guard.state.data["a"]["blockType"] == "retired"
    retired = [m for m in tenant.mails_to("olivia@contoso.com") if m["subject"].endswith("has been retired")][0]
    tenant.packages["a"]["sharedWithUsersAndGroups"] = SHARE        # shared while retired
    claims = AckTokenSigner(SECRET).verify(ack_token_from(retired))
    acks.submit({"caseId": claims.case_id, "packageId": "a", "ownerId": OWNER, "tokenId": claims.token_id})
    guard.run_cycle()
    assert ("unblock", "a") not in tenant.calls
    entry = guard.state.data["a"]
    assert entry["blockType"] == "sharing" and "archiveOn" not in entry and entry["caseId"] != claims.case_id
    assert records(audit, "reactivation_requested") and records(audit, "block_reason_changed")
    assert "reactivatedAt" in guard.state.lifecycle["a"]
    share_notice = [m for m in tenant.mails_to("olivia@contoso.com")
                    if "blocked" in m["subject"] and not m["subject"].endswith("has been retired")]
    assert share_notice
    # The new notice's link removes the sharing on the owner's behalf, then unblocks.
    claims2 = AckTokenSigner(SECRET).verify(ack_token_from(share_notice[-1]))
    assert claims2.case_id == entry["caseId"]
    acks.submit({"caseId": claims2.case_id, "packageId": "a", "ownerId": OWNER, "tokenId": claims2.token_id})
    guard.run_cycle()
    assert tenant.patches and ("unblock", "a") in tenant.calls


def test_ownerless_block_lifted_on_an_approved_compliant_agent_unblocks_it(env, tmp_path):
    from absg.registry import Registry
    priv, pub = generate_keypair()
    d = agent("a", owners=(OWNER,))
    guard, tenant, audit, _ = env([d], ownerless_action="block")
    tenant.status[OWNER] = "disabled"
    guard.run_cycle()
    assert guard.state.data["a"]["blockType"] == "ownerless"

    tenant.packages["a"]["sharedWithUsersAndGroups"] = SHARE
    entry = sign_entry({**draft_entry(tenant.packages["a"], [OWNER, CO], SHARE),
                        "approval": {"requestId": "REQ-1", "expiresAt": "2099-01-01"}}, priv)
    (tmp_path / "reg.json").write_text(json.dumps({"agents": [entry]}))
    (tmp_path / "pub.pem").write_bytes(pub)
    guard.registry = Registry(str(tmp_path / "reg.json"), str(tmp_path / "pub.pem"))
    tenant.status[OWNER] = "active"
    guard.run_cycle()
    assert ("unblock", "a") in tenant.calls
    assert records(audit, "unblock")[-1]["reason"] == "agent approved in the registry"
