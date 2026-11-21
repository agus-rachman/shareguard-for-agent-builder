# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""Registry (signed whitelist), continuous validation and drift enforcement."""
import copy
import json
import os


import pytest

from absg.core import (AuditLog, Config, Guard, StateStore, audit_history, main,
                               verify_audit_log)
from absg.ack import AckStore, AckTokenSigner
from absg.mail import Mailer, OwnerResolver
from absg.registry import (Registry, build_profile, draft_entry, evaluate, generate_keypair,
                          sign_entry, verify_entry)
from test_flows import OWNER, SECRET, FakeTenant, agent

SITE = "https://contoso.sharepoint.com/sites/HRPolicies"
GROUP = {"resourceType": "group", "resourceId": "g-hr"}


def definition(caps=None, instructions="Answer HR policy questions.", **extra):
    caps = caps if caps is not None else [
        {"name": "OneDriveAndSharePoint", "items_by_url": [{"url": SITE}]}]
    return json.dumps({"version": "v1.6", "name": "HR helper", "instructions": instructions,
                       "capabilities": caps, **extra})


def hr_agent(pid="hr", caps=None, shared=None, **extra):
    a = agent(pid, shared=shared if shared is not None else [GROUP])
    a["manifestId"] = f"m-{pid}"
    a["elementDetails"] = [{"elementType": "declarativeAgent",
                            "elements": [{"id": "da1", "definition": definition(caps, **extra)}]}]
    return a


@pytest.fixture(scope="module")
def keys():
    return generate_keypair()


def make_entry(detail, keys, mutate=None, sign=True):
    entry = draft_entry(detail, OWNER, [GROUP])
    entry["approval"].update({"requestId": "GOV-1042", "approvedBy": "risk@contoso.com",
                              "expiresAt": "2099-01-01T00:00:00+00:00", "riskRating": "low"})
    entry["governanceContacts"] = ["ai-governance@contoso.com"]
    if mutate:
        mutate(entry)
    return sign_entry(entry, keys[0]) if sign else entry


@pytest.fixture
def env(tmp_path, keys):
    pub = tmp_path / "pub.pem"
    pub.write_bytes(keys[1])
    reg_path = tmp_path / "registry.json"

    def write_registry(entries):
        reg_path.write_text(json.dumps({"agents": entries}))

    def build(packages, entries=(), **over):
        write_registry(list(entries))
        cfg = Config(tenant_id="t", client_id="c", client_secret="x",
                     state_file=str(tmp_path / "state.json"),
                     audit_file=str(tmp_path / "audit.jsonl"),
                     ack_store_file=str(tmp_path / "acks.json"),
                     mail_sender="governance@contoso.com", admin_emails=["it@contoso.com"],
                     ack_enabled=True, ack_base_url="https://guard.contoso.com/ack",
                     ack_secret=SECRET, registry_file=str(reg_path),
                     registry_public_key_file=str(pub), **over)
        tenant = FakeTenant(packages)
        state = StateStore(cfg.state_file)
        state.package_owners.update({p["id"]: OWNER for p in packages})
        state.baseline_done = True
        state.known_owners[OWNER] = {"baselinedAt": "x"}
        audit = AuditLog(cfg.audit_file)
        guard = Guard(cfg, tenant, state, audit=audit,
                      mailer=Mailer(tenant, cfg.mail_sender, cfg.admin_emails),
                      owner_resolver=OwnerResolver([], None, state.package_owners),
                      signer=AckTokenSigner(SECRET, 1), acks=AckStore(cfg.ack_store_file),
                      delegated_graph=tenant,
                      registry=Registry(str(reg_path), str(pub)))
        return guard, tenant, audit
    build.write_registry = write_registry
    return build


def recs(audit, event=None):
    out = [json.loads(l) for l in open(audit.path) if l.strip()]
    return [r for r in out if event is None or r["event"] == event]


def set_caps(tenant, pid, caps, **extra):
    tenant.packages[pid]["elementDetails"][0]["elements"][0]["definition"] = definition(caps, **extra)


# ---- Compliant approved agent ----------------------------------------------
def test_approved_compliant_agent_stays_shared_and_unblocked(env, keys):
    a = hr_agent()
    guard, tenant, audit = env([a], [make_entry(a, keys)])
    r = guard.run_cycle()
    assert tenant.calls == [] and r.approved_compliant == ["hr"]
    added = recs(audit, "registry_entry_added")[0]
    assert added["approval"]["requestId"] == "GOV-1042" and added["criteria"][0]["id"] == "KS-01"
    val = recs(audit, "registry_validation")[0]
    assert val["result"] == "compliant" and val["configHash"] == val["baselineHash"]
    guard.run_cycle()
    assert len(recs(audit, "registry_validation")) == 1        # only audited on change


# ---- Drift: the scenario from the requirement ---------------------------------
def test_embedded_files_added_blocks_then_rectified_unblocks(env, keys):
    a = hr_agent()
    guard, tenant, audit = env([a], [make_entry(a, keys)])
    guard.run_cycle()
    set_caps(tenant, "hr", [{"name": "OneDriveAndSharePoint", "items_by_url": [{"url": SITE}]},
                            {"name": "EmbeddedKnowledge", "files": [{"name": "salaries.xlsx"}]}])
    r = guard.run_cycle()
    assert tenant.calls == [("block", "hr")] and r.drift_blocked == ["hr"]
    block = recs(audit, "block")[0]
    assert block["blockType"] == "drift" and block["approvalRef"]["requestId"] == "GOV-1042"
    assert "EMBEDDED-FILES" in {v["rule"] for v in block["violations"]}
    notice = tenant.mails_to("olivia@contoso.com")[-1]
    assert "configuration changed" in notice["subject"]
    assert "EMBEDDED-FILES" in notice["body"]["content"] and "GOV-1042" in notice["body"]["content"]
    assert "Remove sharing and unblock my agent" in notice["body"]["content"]   # option 2
    gov = [m for m in tenant.mail if any(t["emailAddress"]["address"] == "ai-governance@contoso.com"
                                        for t in m["message"]["toRecipients"])]
    assert gov and "configuration drift" in gov[0]["message"]["subject"]

    guard.run_cycle()                                           # still drifted: stays blocked
    assert tenant.calls == [("block", "hr")]

    set_caps(tenant, "hr", None)                                # owner reverts the change
    guard.run_cycle()
    assert tenant.calls[-1] == ("unblock", "hr")
    unblock = recs(audit, "unblock")[0]
    assert "drift rectified" in unblock["reason"] and unblock["caseId"] == block["caseId"]
    assert "matches what was approved" in tenant.mails_to("olivia@contoso.com")[-1]["body"]["content"]
    story = [x["event"] for x in audit_history(audit.path, case_id=block["caseId"])]
    assert story[:2] == ["block", "admin_alert_sent"] and "notice_email_sent" in story
    assert story[-2:] == ["unblock", "restored_email_sent"]
    assert [v["result"] for v in recs(audit, "registry_validation")] == \
        ["compliant", "violation", "compliant"]
    assert verify_audit_log(audit.path).ok


@pytest.mark.parametrize("caps,rule", [
    ([{"name": "OneDriveAndSharePoint",
       "items_by_url": [{"url": SITE}, {"url": "https://contoso.sharepoint.com/sites/Finance"}]}],
     "DRIFT-SCOPE-CHANGED"),
    ([{"name": "OneDriveAndSharePoint"}], "UNSCOPED-KNOWLEDGE"),
    ([{"name": "OneDriveAndSharePoint", "items_by_url": [{"url": SITE}]}, {"name": "WebSearch"}],
     "DRIFT-CAPABILITY-ADDED"),
    ([{"name": "OneDriveAndSharePoint", "items_by_url": [{"url": SITE}]},
      {"name": "GraphConnectors", "connections": [{"connection_id": "servicenow"}]}],
     "DRIFT-CAPABILITY-ADDED"),
])
def test_knowledge_drift_detected(env, keys, caps, rule):
    a = hr_agent()
    guard, tenant, audit = env([a], [make_entry(a, keys)])
    set_caps(tenant, "hr", caps)
    guard.run_cycle()
    assert tenant.calls == [("block", "hr")]
    assert rule in {v["rule"] for v in recs(audit, "block")[0]["violations"]}


def test_actions_added_is_drift(env, keys):
    a = hr_agent()
    guard, tenant, audit = env([a], [make_entry(a, keys)])
    set_caps(tenant, "hr", None, actions=[{"id": "hrWriteback", "file": "p.json"}])
    guard.run_cycle()
    assert "DRIFT-ACTIONS" in {v["rule"] for v in recs(audit, "block")[0]["violations"]}


def test_sensitivity_label_signals_embedded_files(env, keys):
    a = hr_agent()
    guard, tenant, audit = env([a], [make_entry(a, keys)])
    set_caps(tenant, "hr", None, sensitivity_label={"id": "confidential"})
    guard.run_cycle()
    assert "EMBEDDED-FILES" in {v["rule"] for v in recs(audit, "block")[0]["violations"]}


def test_instruction_change_warns_by_default_and_blocks_if_configured(env, keys):
    a = hr_agent()
    guard, tenant, audit = env([a], [make_entry(a, keys)])
    set_caps(tenant, "hr", None, instructions="Be more concise.")
    guard.run_cycle()
    assert tenant.calls == []
    assert recs(audit, "registry_validation")[0]["warnings"][0]["rule"] == "DRIFT-INSTRUCTIONS"

    def strict(e):
        e["policy"]["instructionsChange"] = "block"
    env.write_registry([make_entry(hr_agent(), keys, strict)])
    guard.run_cycle()
    assert tenant.calls == [("block", "hr")]


def test_sharing_beyond_approved_audience_blocks(env, keys):
    a = hr_agent()
    guard, tenant, audit = env([a], [make_entry(a, keys)])
    tenant.packages["hr"]["sharedWithUsersAndGroups"] = [GROUP, {"resourceType": "group",
                                                                "resourceId": "g-all-staff"}]
    guard.run_cycle()
    v = recs(audit, "block")[0]["violations"][0]
    assert v["rule"] == "SHARE-SCOPE" and v["detail"]["unapprovedRecipients"][0]["resourceId"] == "g-all-staff"


def test_unreadable_definition_fails_closed(env, keys):
    a = hr_agent()
    guard, tenant, audit = env([a], [make_entry(a, keys)])
    tenant.packages["hr"]["elementDetails"] = []
    guard.run_cycle()
    assert recs(audit, "block")[0]["violations"][0]["rule"] == "CONFIG-UNREADABLE"


# ---- Registry integrity and lifecycle -----------------------------------------
def test_tampered_entry_is_ignored_and_agent_treated_as_unapproved(env, keys):
    a = hr_agent()
    entry = make_entry(a, keys)
    entry["sharing"]["allowedPrincipals"].append({"resourceType": "group", "resourceId": "g-all"})
    guard, tenant, audit = env([a], [entry])
    guard.run_cycle()
    assert tenant.calls == [("block", "hr")]
    assert recs(audit, "registry_entry_invalid")[0]["reason"] == "signature missing or invalid"
    block = recs(audit, "block")[0]
    assert block["blockType"] == "sharing" and "isn't valid" in block["reason"]


def test_unsigned_entry_rejected(env, keys):
    a = hr_agent()
    guard, tenant, audit = env([a], [make_entry(a, keys, sign=False)])
    guard.run_cycle()
    assert tenant.calls == [("block", "hr")]


@pytest.mark.parametrize("mutate,why", [
    (lambda e: e["approval"].update({"expiresAt": "2020-01-01T00:00:00+00:00"}), "expired"),
    (lambda e: e.update({"status": "suspended"}), "suspended"),
    (lambda e: e.update({"manifestId": "someone-elses-agent"}), "manifestId"),
])
def test_invalid_approvals_fall_back_to_no_sharing_policy(env, keys, mutate, why):
    a = hr_agent()
    guard, tenant, audit = env([a], [make_entry(a, keys, mutate)])
    guard.run_cycle()
    assert tenant.calls == [("block", "hr")]
    assert why in recs(audit, "block")[0]["approvalStatus"]


def test_registry_removal_blocks_and_new_approval_unblocks(env, keys):
    a = hr_agent()
    entry = make_entry(a, keys)
    guard, tenant, audit = env([a], [entry])
    guard.run_cycle()
    env.write_registry([])                                      # approval withdrawn
    guard.run_cycle()
    assert tenant.calls == [("block", "hr")] and recs(audit, "registry_entry_removed")
    env.write_registry([entry])                                 # re-approved
    guard.run_cycle()
    assert tenant.calls[-1] == ("unblock", "hr")
    assert "approved in the registry" in recs(audit, "unblock")[0]["reason"]
    events = [r["event"] for r in recs(audit) if r["event"].startswith("registry_entry")]
    assert events == ["registry_entry_added", "registry_entry_removed", "registry_entry_added"]


def test_drift_blocked_agent_unblocked_when_sharing_removed(env, keys):
    a = hr_agent()
    guard, tenant, audit = env([a], [make_entry(a, keys)])
    set_caps(tenant, "hr", [{"name": "OneDriveAndSharePoint"}])
    guard.run_cycle()
    tenant.packages["hr"]["sharedWithUsersAndGroups"] = []
    guard.run_cycle()
    assert tenant.calls[-1] == ("unblock", "hr") and recs(audit, "unblock")[0]["reason"] == "sharing removed"


def test_violation_changes_while_blocked_are_audited(env, keys):
    a = hr_agent()
    guard, tenant, audit = env([a], [make_entry(a, keys)])
    set_caps(tenant, "hr", [{"name": "OneDriveAndSharePoint"}])
    guard.run_cycle()
    set_caps(tenant, "hr", [{"name": "OneDriveAndSharePoint"}, {"name": "WebSearch"}])
    guard.run_cycle()
    upd = recs(audit, "violation_updated")
    assert upd and "DRIFT-CAPABILITY-ADDED" in {v["rule"] for v in upd[0]["violations"]}


def test_registry_load_failure_keeps_last_good_copy(env, keys, tmp_path):
    a = hr_agent()
    guard, tenant, audit = env([a], [make_entry(a, keys)])
    guard.run_cycle()
    (tmp_path / "registry.json").write_text("{not json")
    guard.run_cycle()
    assert tenant.calls == [] and recs(audit, "error")[0]["stage"] == "registry_load"
    (tmp_path / "registry.json").unlink()                       # deleted registry
    guard.run_cycle()
    assert tenant.calls == [] and len(recs(audit, "error")) == 2


def test_policy_mode_allows_approved_locations_only(env, keys):
    a = hr_agent()

    def policy(e):
        e["policy"] = {"driftMode": "policy",
                       "allowedCapabilities": ["OneDriveAndSharePoint"],
                       "allowedKnowledgeUrlPrefixes": [SITE]}
    guard, tenant, audit = env([a], [make_entry(a, keys, policy)])
    set_caps(tenant, "hr", [{"name": "OneDriveAndSharePoint",
                             "items_by_url": [{"url": SITE + "/Shared Documents/Leave.docx"}]}])
    guard.run_cycle()
    assert tenant.calls == []                                   # inside approved site: allowed
    set_caps(tenant, "hr", [{"name": "OneDriveAndSharePoint",
                             "items_by_url": [{"url": "https://contoso.sharepoint.com/sites/HRPoliciesSecret"}]}])
    guard.run_cycle()
    assert tenant.calls == [("block", "hr")]
    assert recs(audit, "block")[0]["violations"][0]["rule"] == "POLICY-KNOWLEDGE-SOURCE"


# ---- Governance helpers ---------------------------------------------------
def test_profile_normalisation_is_order_and_case_insensitive():
    a = hr_agent(caps=[{"name": "OneDriveAndSharePoint",
                        "items_by_url": [{"url": SITE.upper() + "/"}, {"url": "https://x/b"}]}])
    b = hr_agent(caps=[{"name": "OneDriveAndSharePoint",
                        "items_by_url": [{"url": "https://x/b"}, {"url": SITE}]}])
    assert build_profile(a) == build_profile(b)


def test_sign_verify_roundtrip(keys):
    entry = make_entry(hr_agent(), keys)
    assert verify_entry(entry, keys[1])
    bad = copy.deepcopy(entry)
    bad["approval"]["riskRating"] = "low-ish"
    assert not verify_entry(bad, keys[1])
    assert not verify_entry(entry, generate_keypair()[1])


def test_cli_keygen_and_sign(tmp_path, capsys):
    assert main(["--registry-keygen", str(tmp_path / "k")]) == 0
    capsys.readouterr()
    draft = draft_entry(hr_agent(), OWNER, [GROUP])
    path = tmp_path / "draft.json"
    path.write_text(json.dumps(draft))
    key = str(tmp_path / "k" / "absg_registry_signing_key.pem")
    assert main(["--registry-sign", str(path), "--key", key]) == 1   # placeholders left
    assert "Complete these approval fields" in capsys.readouterr().out
    draft["approval"].update({"requestId": "GOV-1", "approvedBy": "a@b", "expiresAt": "2099-01-01",
                              "riskRating": "low"})
    path.write_text(json.dumps(draft))
    assert main(["--registry-sign", str(path), "--key", key]) == 0
    signed = json.loads(capsys.readouterr().out)
    pub = (tmp_path / "k" / "absg_registry_public_key.pem").read_bytes()
    assert verify_entry(signed, pub)
    assert oct(os.stat(key).st_mode & 0o777) == "0o600"


def test_evaluate_reports_compliance_directly(keys):
    a = hr_agent()
    entry = make_entry(a, keys)
    assert evaluate(a, entry, [GROUP]).compliant


def test_rs256_keygen_and_jwk_export_cli(tmp_path, capsys):
    """RS256 key pair, exported as JWK, round-trips sign/verify."""
    import json as _json

    from absg.core import main
    from absg.registry import draft_entry, sign_entry, verify_entry

    assert main(["--registry-keygen", str(tmp_path), "--algorithm", "rs256"]) == 0
    capsys.readouterr()
    priv = (tmp_path / "absg_registry_signing_key.pem").read_bytes()
    assert main(["--registry-export-jwk", str(tmp_path / "absg_registry_public_key.pem")]) == 0
    pub_jwk = _json.loads(capsys.readouterr().out)
    assert pub_jwk["kty"] == "RSA" and pub_jwk["alg"] == "RS256" and "d" not in pub_jwk
    assert main(["--registry-export-jwk", str(tmp_path / "absg_registry_signing_key.pem")]) == 0
    assert "d" in _json.loads(capsys.readouterr().out)
    detail = {"id": "p1", "displayName": "A", "elementDetails": []}
    entry = sign_entry(draft_entry(detail, "owner-1", []), priv)
    assert verify_entry(entry, pub_jwk)


# ---- Registry unavailable on a cold start (Azure Functions) ---------------------
def test_cold_start_registry_failure_uses_snapshot_from_state(env, keys, tmp_path):
    a = hr_agent()
    guard, tenant, _ = env([a], [make_entry(a, keys)])
    assert guard.run_cycle().approved_compliant == ["hr"]

    # New process (fresh Registry, state reloaded from disk); the registry source fails.
    guard, tenant, audit = env([a], [make_entry(a, keys)])
    os.remove(tmp_path / "registry.json")
    r = guard.run_cycle()
    assert r.approved_compliant == ["hr"] and r.blocked == []
    assert not tenant.packages["hr"].get("isBlocked")
    assert any("copy saved in the state" in e.get("reason", "") for e in recs(audit, "error"))


def test_snapshot_entries_are_reverified(env, keys, tmp_path):
    a = hr_agent()
    guard, tenant, _ = env([a], [make_entry(a, keys)])
    guard.run_cycle()
    state = json.loads((tmp_path / "state.json").read_text())
    state["registry_snapshot"]["agents"][0]["sharing"]["allowedPrincipals"].append(
        {"resourceType": "group", "resourceId": "everyone"})      # tampered snapshot
    (tmp_path / "state.json").write_text(json.dumps(state))

    guard, tenant, audit = env([a], [make_entry(a, keys)])
    os.remove(tmp_path / "registry.json")
    r = guard.run_cycle()
    assert r.approved_compliant == [] and r.blocked == ["hr"]


def test_cold_start_without_any_registry_copy_defers_instead_of_mass_blocking(env, keys, tmp_path):
    a = hr_agent()
    guard, tenant, audit = env([a], [make_entry(a, keys)])
    os.remove(tmp_path / "registry.json")
    r = guard.run_cycle()
    assert r.blocked == [] and not tenant.packages["hr"].get("isBlocked")
    assert [x["package"]["id"] for x in recs(audit, "decision_deferred")] == ["hr"]


# ---- Rollback: an earlier signed entry put back -----------------------------------
def test_restoring_an_approval_after_revocation_is_rejected(env, keys):
    a = hr_agent()
    approved = make_entry(a, keys)
    guard, tenant, audit = env([a], [approved])
    assert guard.run_cycle().approved_compliant == ["hr"]

    revoked = make_entry(a, keys, mutate=lambda e: e.update(status="revoked"))
    env.write_registry([revoked])
    assert guard.run_cycle().blocked == ["hr"]

    env.write_registry([approved])                 # someone restores the earlier version
    r = guard.run_cycle()
    assert r.approved_compliant == [] and tenant.packages["hr"]["isBlocked"]
    (rec,) = recs(audit, "registry_rollback_rejected")
    assert rec["package"]["id"] == "hr" and "earlier entry was put back" in rec["reason"]
    assert any("put back" in x.get("subject", "") for x in recs(audit, "admin_alert_sent"))


def test_rollback_is_rejected_by_a_new_process_too(env, keys):
    a = hr_agent()
    approved = make_entry(a, keys)
    revoked = make_entry(a, keys, mutate=lambda e: e.update(status="revoked"))
    guard, tenant, _ = env([a], [revoked])
    guard.run_cycle()

    assert tenant.packages["hr"]["isBlocked"]
    guard, tenant, _ = env([a], [approved])        # fresh Registry, state reloaded from disk
    r = guard.run_cycle()
    assert r.approved_compliant == [] and r.unblocked == [] and tenant.packages["hr"]["isBlocked"]
    assert "older than one already seen" in guard.registry.lookup(a).reason


def test_entry_without_signed_at_is_rejected_once_a_dated_one_was_seen(env, keys):
    a = hr_agent()
    guard, tenant, _ = env([a], [make_entry(a, keys)])
    guard.run_cycle()
    legacy = make_entry(a, keys)
    legacy.pop("signedAt")
    legacy = sign_entry(legacy, keys[0])
    legacy.pop("signedAt")                         # an entry signed before signedAt existed
    env.write_registry([legacy])
    assert guard.run_cycle().blocked == ["hr"]


def test_newer_entry_replaces_older_one(env, keys):
    a = hr_agent()
    guard, tenant, _ = env([a], [make_entry(a, keys)])
    guard.run_cycle()
    renewed = make_entry(a, keys, mutate=lambda e: e["approval"].update(requestId="GOV-2001"))
    env.write_registry([renewed])
    assert guard.run_cycle().approved_compliant == ["hr"]
    assert guard.state.registry_newest["hr"] == renewed["signedAt"]
