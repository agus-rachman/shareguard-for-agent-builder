# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""End-to-end tests: welcome email, share notice, owner acknowledgement,
on-behalf sharing removal, unblock, and the audit trail that ties them together."""
import json
import urllib.error
import urllib.parse
import urllib.request


import pytest

from absg.core import (AGENT_BUILDER_PLATFORM, AuditLog, Config, GraphError, Guard,
                               StateStore, audit_history, verify_audit_log)
from absg.ack import AckServer, AckStore, AckTokenSigner, TokenError
from absg.mail import Mailer, OwnerResolver

OWNER, OTHER = "owner-1", "user-2"
SECRET = "s" * 40


class Resp:
    def __init__(self, body=None):
        self._b = body or {}

    def json(self):
        return self._b


class FakeTenant:
    """Fake Package Management API + users + sendMail."""

    def __init__(self, packages, clear_on_patch=True):
        self.packages = {p["id"]: p for p in packages}
        self.calls, self.mail, self.patches = [], [], []
        self.clear_on_patch = clear_on_patch
        self.fail_mail = False
        self.users = {OWNER: {"id": OWNER, "displayName": "Olivia Owner", "mail": "olivia@contoso.com"},
                      "owner-2": {"id": "owner-2", "displayName": "Noah New", "mail": "noah@contoso.com"}}

    # package API
    def list_agent_builder_packages(self):
        return [p for p in self.packages.values() if p["platform"] == AGENT_BUILDER_PLATFORM]

    def get_package(self, pid):
        return json.loads(json.dumps(self.packages[pid]))

    def block(self, pid):
        self.calls.append(("block", pid)); self.packages[pid]["isBlocked"] = True

    def unblock(self, pid):
        self.calls.append(("unblock", pid)); self.packages[pid]["isBlocked"] = False

    def update_package(self, pid, body):
        self.patches.append((pid, body))
        if self.clear_on_patch:
            self.packages[pid]["sharedWithUsersAndGroups"] = []
            self.packages[pid]["allowedUsersAndGroups"] = body["allowedUsersAndGroups"]

    # generic Graph
    def request(self, method, url, json=None, **kw):
        if url.startswith("/users/") and url.endswith("/sendMail"):
            if self.fail_mail:
                raise GraphError(403, "mail denied")
            self.mail.append(json)
            return Resp()
        if url.startswith("/users/"):
            uid = url.split("/")[2].split("?")[0]
            if uid not in self.users:
                raise GraphError(404, "no user")
            return Resp(self.users[uid])
        if url.startswith("/groups/"):
            return Resp({"displayName": "Finance Team"})
        raise AssertionError(url)

    def mails_to(self, addr):
        return [m["message"] for m in self.mail
                if m["message"]["toRecipients"][0]["emailAddress"]["address"] == addr]


def agent(pid, owner=OWNER, shared=None, blocked=False):
    return {"id": pid, "displayName": f"Agent {pid}", "platform": AGENT_BUILDER_PLATFORM,
            "isBlocked": blocked, "availableTo": "some",
            "allowedUsersAndGroups": [{"resourceType": "user", "resourceId": owner}],
            "sharedWithUsersAndGroups": shared or []}


SHARE = [{"resourceType": "group", "resourceId": "g-fin"}]


@pytest.fixture
def env(tmp_path):
    def build(packages, delegated=True, clear_on_patch=True, **cfg_over):
        cfg = Config(tenant_id="t", client_id="c", client_secret="x",
                     state_file=str(tmp_path / "state.json"),
                     audit_file=str(tmp_path / "audit.jsonl"),
                     ack_store_file=str(tmp_path / "acks.json"),
                     mail_sender="governance@contoso.com", admin_emails=["it@contoso.com"],
                     ack_enabled=True, ack_base_url="https://guard.contoso.com/ack",
                     ack_secret=SECRET, delegated_username="svc-guard@contoso.com",
                     **cfg_over)
        tenant = FakeTenant(packages, clear_on_patch)
        state = StateStore(cfg.state_file)
        audit = AuditLog(cfg.audit_file, actor={"clientId": "c"})
        signer = AckTokenSigner(SECRET, 1)
        acks = AckStore(cfg.ack_store_file)
        guard = Guard(cfg, tenant, state, audit=audit,
                      mailer=Mailer(tenant, cfg.mail_sender, cfg.admin_emails,
                                    "https://intranet/ai-policy", "the IT service desk",
                                    dry_run=cfg.dry_run),
                      owner_resolver=OwnerResolver([], None, state.package_owners),
                      signer=signer, acks=acks,
                      delegated_graph=tenant if delegated else None)
        return guard, tenant, audit, signer, acks, cfg
    return build


def events(audit):
    return [json.loads(l)["event"] for l in open(audit.path) if l.strip()]


def ack_token_from(mail_msg):
    content = mail_msg["body"]["content"]
    href = content.split('href="https://guard.contoso.com/ack?')[1].split('"')[0]
    return urllib.parse.parse_qs(href.replace("&amp;", "&"))["t"][0]


# ---- Welcome ----------------------------------------------------------
def test_existing_owners_baselined_new_owner_welcomed_once(env):
    guard, tenant, audit, *_ = env([agent("a")])
    guard.run_cycle()
    assert tenant.mail == []                         # first run: baseline, no email
    assert "welcome_baseline" in events(audit)
    tenant.packages["b"] = agent("b", owner="owner-2")
    tenant.packages["c"] = agent("c", owner=OWNER)   # existing owner's 2nd agent
    guard.run_cycle()
    assert len(tenant.mail) == 1
    msg = tenant.mails_to("noah@contoso.com")[0]
    assert "Welcome" in msg["subject"] and "Agent b" in msg["body"]["content"]
    tenant.packages["d"] = agent("d", owner="owner-2")
    guard.run_cycle()
    assert len(tenant.mail) == 1                     # only the first agent triggers it
    w = [json.loads(l) for l in open(audit.path) if '"welcome_email_sent"' in l]
    assert w[0]["ownerId"] == "owner-2" and w[0]["package"]["id"] == "b"


def test_welcome_backfill_emails_existing_owners(env):
    guard, tenant, *_ = env([agent("a")], welcome_backfill=True)
    guard.run_cycle()
    assert len(tenant.mails_to("olivia@contoso.com")) == 1


def test_welcome_failure_retried_then_given_up(env):
    guard, tenant, audit, *_ = env([agent("a")], welcome_max_attempts=2)
    guard.run_cycle()
    tenant.packages["b"] = agent("b", owner="owner-2")
    tenant.fail_mail = True
    guard.run_cycle(); guard.run_cycle(); guard.run_cycle()
    fails = [json.loads(l) for l in open(audit.path) if '"email_failed"' in l]
    assert [f["attempt"] for f in fails] == [1, 2] and fails[-1]["gaveUp"] is True


# ---- Notice + acknowledgement ----------------------------------------------
def test_share_sends_notice_with_signed_ack_link(env):
    guard, tenant, audit, signer, *_ = env([agent("a")])
    guard.run_cycle()
    tenant.packages["a"]["sharedWithUsersAndGroups"] = SHARE
    guard.run_cycle()
    notice = tenant.mails_to("olivia@contoso.com")[0]
    assert "blocked" in notice["subject"] and "Finance Team (group)" in notice["body"]["content"]
    claims = signer.verify(ack_token_from(notice))
    block = [json.loads(l) for l in open(audit.path) if '"event": "block"' in l][0]
    assert claims.case_id == block["caseId"] and claims.owner_id == OWNER
    sent = [json.loads(l) for l in open(audit.path) if '"notice_email_sent"' in l][0]
    assert sent["caseId"] == block["caseId"] and sent["ackTokenId"] == claims.token_id


def _post(url, token, identity=None, confirm="yes"):
    data = urllib.parse.urlencode({"t": token, "confirm": confirm}).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    if identity:
        req.add_header("X-MS-CLIENT-PRINCIPAL-ID", identity)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_end_to_end_ack_over_http_removes_sharing_and_unblocks(env):
    guard, tenant, audit, signer, acks, cfg = env([agent("a")])
    guard.run_cycle()
    tenant.packages["a"]["sharedWithUsersAndGroups"] = SHARE
    guard.run_cycle()
    token = ack_token_from(tenant.mails_to("olivia@contoso.com")[0])

    woke = []
    server = AckServer(signer, acks, lambda e, **f: audit.record(e, source="ack_endpoint", **f),
                       port=0, identity_header="X-MS-CLIENT-PRINCIPAL-ID",
                       require_identity=True, on_ack=lambda: woke.append(1))
    server.start()
    base = f"http://127.0.0.1:{server.port}/ack"
    try:
        # GET only shows the confirmation form; nothing is recorded (link scanners).
        n_before = len(events(audit))
        with urllib.request.urlopen(f"{base}?t={urllib.parse.quote(token)}") as r:
            assert r.status == 200 and "Confirm" in r.read().decode()
        assert len(events(audit)) == n_before and acks.pending() == []

        assert _post(base, token)[0] == 401                     # not signed in
        assert _post(base, token, identity=OTHER)[0] == 403     # not the owner
        assert _post(base, token, identity=OWNER, confirm="")[0] == 400
        status, body = _post(base, token, identity=OWNER)
        assert status == 200 and "received" in body
        assert woke == [1] and len(acks.pending()) == 1
        assert _post(base, "garbage.sig", identity=OWNER)[0] == 400
    finally:
        server.stop()

    guard.run_cycle()
    assert tenant.patches == [("a", {"allowedUsersAndGroups":
                                     [{"resourceType": "user", "resourceId": OWNER}],
                                     "availableTo": "allowedForSome"})]
    assert tenant.calls[-1] == ("unblock", "a")
    assert "unblocked" in tenant.mails_to("olivia@contoso.com")[-1]["subject"]
    assert acks.pending() == [] and acks.is_used(signer.verify(token).case_id)

    # Audit: the whole story under one case ID, chain intact.
    case = [json.loads(l) for l in open(audit.path) if '"event": "block"' in l][0]["caseId"]
    story = [r["event"] for r in audit_history(audit.path, case_id=case)]
    for expected in ["block", "notice_email_sent", "ack_rejected", "ack_received",
                     "sharing_removal", "unblock", "restored_email_sent"]:
        assert expected in story, expected
    removal = [r for r in audit_history(audit.path, case_id=case) if r["event"] == "sharing_removal"][0]
    assert removal["onBehalfOf"] == OWNER and removal["outcome"] == "success"
    assert removal["removedRecipients"] == SHARE and removal["actingIdentity"] == "svc-guard@contoso.com"
    unblock = [r for r in audit_history(audit.path, case_id=case) if r["event"] == "unblock"][0]
    assert unblock["onBehalfOf"] == OWNER and "on owner's behalf" in unblock["reason"]
    received = [r for r in audit_history(audit.path, case_id=case) if r["event"] == "ack_received"][0]
    assert received["signedInUser"] == OWNER and received["identityVerified"] is True
    assert verify_audit_log(audit.path).ok


def test_ack_replay_rejected_after_use(env, tmp_path):
    guard, tenant, audit, signer, acks, _ = env([agent("a")])
    guard.run_cycle()
    tenant.packages["a"]["sharedWithUsersAndGroups"] = SHARE
    guard.run_cycle()
    token = ack_token_from(tenant.mails_to("olivia@contoso.com")[0])
    c = signer.verify(token)
    assert acks.submit({"caseId": c.case_id, "packageId": "a", "ownerId": OWNER})
    guard.run_cycle()
    assert acks.is_used(c.case_id)
    assert not acks.submit({"caseId": c.case_id, "packageId": "a", "ownerId": OWNER})


def _block_and_ack(env, **kw):
    guard, tenant, audit, signer, acks, cfg = env([agent("a")], **kw)
    guard.run_cycle()
    tenant.packages["a"]["sharedWithUsersAndGroups"] = SHARE
    guard.run_cycle()
    c = signer.verify(ack_token_from(tenant.mails_to("olivia@contoso.com")[0]))
    acks.submit({"caseId": c.case_id, "packageId": "a", "ownerId": OWNER, "tokenId": c.token_id})
    return guard, tenant, audit, acks, c


def test_unverified_removal_keeps_block_retries_then_escalates(env):
    guard, tenant, audit, acks, c = _block_and_ack(
        lambda *a, **k: env(*a, clear_on_patch=False, **k), ack_max_attempts=2)
    guard.run_cycle()
    assert tenant.packages["a"]["isBlocked"] and len(acks.pending()) == 1
    guard.run_cycle()
    assert tenant.packages["a"]["isBlocked"] and acks.pending() == []
    ev = events(audit)
    assert ev.count("sharing_removal_unverified") == 2 and "ack_escalated" in ev
    assert any("Could not remove sharing" in m["subject"] for m in tenant.mails_to("it@contoso.com"))


def test_no_delegated_identity_falls_back_to_manual(env):
    guard, tenant, audit, acks, c = _block_and_ack(lambda *a, **k: env(*a, delegated=False, **k))
    guard.run_cycle()
    rec = [json.loads(l) for l in open(audit.path) if '"sharing_removal"' in l][0]
    assert rec["outcome"] == "pending_manual" and rec["caseId"] == c.case_id
    assert any("please remove sharing" in m["subject"] for m in tenant.mails_to("it@contoso.com"))
    tenant.packages["a"]["sharedWithUsersAndGroups"] = []      # admin removes sharing
    guard.run_cycle()
    assert tenant.calls[-1] == ("unblock", "a")


def test_stale_ack_after_reblock_is_ignored(env):
    guard, tenant, audit, acks, c = _block_and_ack(env)
    guard.state.data["a"]["caseId"] = "newer-case"            # simulate a re-block
    guard.run_cycle()
    assert tenant.patches == [] and "ack_stale" in events(audit)


def test_owner_unknown_alerts_admins(env):
    a = agent("a", shared=SHARE)
    a["allowedUsersAndGroups"] = []
    guard, tenant, audit, *_ = env([a])
    guard.run_cycle()
    assert "owner_unknown" in events(audit)
    assert any("owner unknown" in m["subject"] for m in tenant.mails_to("it@contoso.com"))


def test_notice_mail_failure_audited_and_escalated(env):
    guard, tenant, audit, *_ = env([agent("a")])
    guard.run_cycle()
    tenant.packages["a"]["sharedWithUsersAndGroups"] = SHARE
    tenant.fail_mail = True
    guard.run_cycle()
    assert tenant.packages["a"]["isBlocked"]                  # enforcement still happened
    assert "email_failed" in events(audit)


def test_dry_run_sends_nothing(env):
    guard, tenant, audit, *_ = env([agent("a")], dry_run=True, welcome_backfill=True)
    guard.mailer.dry_run = True
    guard.run_cycle()                                         # learn owner while unshared
    guard.state.package_owners["a"] = OWNER                   # (dry run doesn't persist state)
    tenant.packages["a"]["sharedWithUsersAndGroups"] = SHARE
    guard.run_cycle()
    assert tenant.mail == [] and tenant.calls == []
    assert "welcome_email_sent" in events(audit) and "notice_email_sent" in events(audit)


# ---- Tokens -----------------------------------------------------------
def test_token_tamper_and_expiry():
    s = AckTokenSigner(SECRET, ttl_hours=1)
    tok, claims = s.issue("a", OWNER, "case-1")
    assert s.verify(tok).case_id == "case-1"
    body, sig = tok.split(".")
    with pytest.raises(TokenError, match="signature"):
        s.verify(body[:-2] + "AA." + sig)
    with pytest.raises(TokenError, match="signature"):
        AckTokenSigner("t" * 40).verify(tok)
    s.ttl = -10
    old, _ = s.issue("a", OWNER, "case-2")
    with pytest.raises(TokenError, match="expired"):
        s.verify(old)
    with pytest.raises(ValueError):
        AckTokenSigner("short")


def test_owner_resolver_order(tmp_path):
    m = tmp_path / "owners.json"
    m.write_text(json.dumps({"p1": "mapped"}))
    learned = {}
    r = OwnerResolver(["createdBy.user.id"], str(m), learned)
    assert r.resolve({"id": "p1"}, True) == ("mapped", "owner_map")
    assert r.resolve({"id": "p2", "createdBy": {"user": {"id": "u9"}}}, True)[1] == "field:createdBy.user.id"
    unshared = {"id": "p3", "allowedUsersAndGroups": [{"resourceType": "user", "resourceId": "u3"}]}
    assert r.resolve(unshared, False) == ("u3", "inferred:allowed_list")
    assert r.resolve(unshared, True) == (None, None)          # never infer while shared
    learned["p3"] = "u3"
    assert r.resolve(unshared, True) == ("u3", "learned")
