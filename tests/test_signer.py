# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""Registry signer (Key Vault ES256) and the Azure Functions entry point."""
import importlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from absg.cloud import KeyVault
from absg.core import AuditLog, Config, GraphError
from absg.registry import Registry, build_profile, sha256, verify_entry
from absg.sharepoint import SharePointRegistrySource, SharePointSite
from absg.signer import RegistrySigner
from test_azure import DownloadSession, FakeGraph, FakeVault, Resp

ROOT = Path(__file__).resolve().parent.parent


HR_DEFINITION = {"name": "HR helper", "instructions": "Answer HR policy questions.",
                 "capabilities": [{"name": "OneDriveAndSharePoint",
                                   "items_by_url": [{"url": "https://contoso.sharepoint.com/sites/HR"}]}]}
P1 = {"id": "p1", "displayName": "HR helper", "manifestId": "m1", "sharedWithUsersAndGroups": [],
      "elementDetails": [{"elementType": "declarativeAgent",
                          "elements": [{"id": "e1", "definition": json.dumps(HR_DEFINITION)}]}]}


def config_hash(package=P1):
    return sha256(build_profile(package))


class SignerGraph(FakeGraph):
    def __init__(self):
        super().__init__()
        self.packages = {"p1": json.loads(json.dumps(P1))}
        self.directory = {"olivia@contoso.com": {"id": "owner-1", "userPrincipalName": "olivia@contoso.com",
                                                 "accountEnabled": True},
                          "noah@contoso.com": {"id": "owner-2", "userPrincipalName": "noah@contoso.com",
                                               "accountEnabled": True},
                          "gone@contoso.com": {"id": "owner-3", "userPrincipalName": "gone@contoso.com",
                                               "accountEnabled": False}}
        self.versions = {}       # item id -> versions, newest first

    def get_package(self, pid):
        if pid not in self.packages:
            raise GraphError(404, "not found")
        return json.loads(json.dumps(self.packages[pid]))

    def request(self, method, url, headers=None, json=None, data=None, **kw):
        if url.endswith("/versions"):
            item_id = url.split("/items/")[1].split("/")[0]
            return Resp({"value": self.versions.get(item_id, [])})
        if url.startswith("/users/") and "accountEnabled" in url:
            ref = url.split("/")[2].split("?")[0]
            if ref not in self.directory:
                raise GraphError(404, "no user")
            return Resp(self.directory[ref])
        if "$filter" in url and "lists/" in url:
            name = url.split("/lists/")[1].split("/")[0].replace("%20", " ")
            items = list(self.lists.get(name, {}).values())
            if "Title%20eq" in url:
                title = url.split("Title%20eq%20%27")[1].split("%27")[0]
                items = [i for i in items if i["fields"].get("Title") == title]
            else:
                items = [i for i in items if i["fields"].get("Status") in
                         ("Approved", "Revoke requested", "Submitted", "In review")]
            return Resp({"value": [dict(i) for i in items]})
        return super().request(method, url, headers=headers, json=json, data=data, **kw)


def request_item(**over):
    fields = {"Title": "HR helper", "PackageId": "p1", "Owners": "olivia@contoso.com; noah@contoso.com",
              "AudienceGroupIds": "g-hr; g-hr-leads", "KS01": "Pass", "KS02": "Pass", "DS01": "Pass",
              "AU01": "N/A", "AC01": "Pass", "Evidence": "https://contoso.sharepoint.com/sites/gov/REQ-7",
              "RiskRating": "Low", "RiskScore": 4, "ApprovedBy": "jane.risk@contoso.com",
              "ExpiresAt": (datetime.now(timezone.utc) + timedelta(days=180)).isoformat(),
              "Conditions": "Re-review on site permission change", "Status": "Approved",
              "GovernanceContacts": "ai-governance@contoso.com",
              "ReviewConfigHash": config_hash(), "ReviewConfigCapturedAt": "2026-11-20T09:00:00+00:00"}
    fields.update(over)
    return {"id": "7", "fields": fields,
            "createdBy": {"user": {"id": "owner-1", "email": "olivia@contoso.com"}}}


@pytest.fixture
def signer_env(tmp_path):
    def build(item, **cfg_over):
        g = SignerGraph()
        g.lists["Agent Sharing Requests"] = {item["id"]: item}
        site = SharePointSite(g, "reg", session=DownloadSession(g))
        fake = FakeVault()
        vault = KeyVault("https://kv-absg.vault.azure.net", lambda: "kv-token", session=fake)
        cfg = Config(tenant_id="t", client_id="mi", use_managed_identity=True, **cfg_over)
        audit = AuditLog(str(tmp_path / "signer-audit.jsonl"), actor={"role": "signer"})
        return RegistrySigner(cfg, g, site, vault, audit), g, site, vault, audit
    return build


def test_approved_request_becomes_signed_entry_the_guard_accepts(signer_env):
    signer, g, site, vault, audit = signer_env(request_item())
    out = signer.run()
    assert out["registered"] == ["p1"]
    (item,) = g.lists["Approved Agents"].values()
    entry = json.loads(item["fields"]["EntryJson"])
    assert entry["signatureAlgorithm"] == "ES256" and entry["owners"] == ["owner-1", "owner-2"]
    assert entry["approval"]["approvedBy"] == "jane.risk@contoso.com" and entry["approval"]["riskRating"] == "low"
    assert [c["result"] for c in entry["approval"]["criteria"]] == ["pass", "pass", "pass", "n/a", "pass"]
    assert entry["sharing"]["allowedPrincipals"] == [{"resourceType": "group", "resourceId": "g-hr"},
                                                    {"resourceType": "group", "resourceId": "g-hr-leads"}]
    assert g.lists["Agent Sharing Requests"]["7"]["fields"]["Status"] == "Registered"
    # the guard verifies it with only the public key
    reg = Registry(source=SharePointRegistrySource(site), public_key=vault.public_jwk("registry-signing-key"))
    reg.load()
    assert reg.lookup({"id": "p1", "manifestId": "m1"}).valid
    rec = [json.loads(line) for line in open(audit.path)][-1]
    assert rec["event"] == "registry_entry_signed" and rec["outcome"] == "success"


@pytest.mark.parametrize("over,problem", [
    ({"DS01": "Fail"}, "DS-01 failed"),
    ({"KS02": None}, "KS-02 not assessed"),
    ({"ApprovedBy": "olivia@contoso.com"}, "the approver can't be the requester or an owner"),
    ({"ApprovedBy": ""}, "ApprovedBy is empty"),
    ({"ExpiresAt": (datetime.now(timezone.utc) + timedelta(days=900)).isoformat()}, "more than 365 days"),
    ({"ExpiresAt": "2020-01-01T00:00:00Z"}, "ExpiresAt is in the past"),
    ({"Owners": "gone@contoso.com"}, "owner gone@contoso.com is disabled"),
    ({"AudienceGroupIds": ""}, "AudienceGroupIds is empty"),
    ({"PackageId": "nope"}, "agent nope not found"),
    ({"PolicyJson": '{"allowEverything": true}'}, "unknown keys"),
    ({"RiskRating": "Spicy"}, "RiskRating must be"),
])
def test_incomplete_requests_are_refused(signer_env, over, problem):
    signer, g, *_ = signer_env(request_item(**over))
    assert signer.run()["needsCriteria"]
    f = g.lists["Agent Sharing Requests"]["7"]["fields"]
    assert f["Status"] == "Needs criteria" and problem in f["SignerComments"]
    assert "Approved Agents" not in g.lists or not g.lists["Approved Agents"]


def test_revocation_resigns_the_entry(signer_env):
    signer, g, site, vault, _ = signer_env(request_item())
    signer.run()
    g.lists["Agent Sharing Requests"]["7"]["fields"].update(
        {"Status": "Revoke requested", "ApprovedBy": "jane.risk@contoso.com", "ReviewerComments": "No longer needed"})
    assert signer.run()["revoked"] == ["p1"]
    entry = json.loads(next(iter(g.lists["Approved Agents"].values()))["fields"]["EntryJson"])
    assert entry["status"] == "revoked" and verify_entry(entry, vault.public_jwk("registry-signing-key"))
    reg = Registry(source=SharePointRegistrySource(site), public_key=vault.public_jwk("registry-signing-key"))
    reg.load()
    assert reg.lookup({"id": "p1"}).reason == "registry status is 'revoked'"


def test_dry_run_signs_but_writes_nothing(signer_env):
    signer, g, *_ = signer_env(request_item(), dry_run=True)
    signer.run()
    assert "Approved Agents" not in g.lists
    assert g.lists["Agent Sharing Requests"]["7"]["fields"]["Status"] == "Approved"


# ---------------------------------------------------------------- Functions entry point
@pytest.mark.parametrize("role,names", [("guard", {"guard_cycle", "verify_audit_chain"}),
                                        ("signer", {"registry_signer"})])
def test_function_app_registers_timers_per_role(monkeypatch, role, names):
    pytest.importorskip("azure.functions")
    monkeypatch.setenv("ABSG_ROLE", role)
    monkeypatch.syspath_prepend(str(ROOT / "azure" / "functionapp"))
    sys.modules.pop("function_app", None)
    mod = importlib.import_module("function_app")
    fns = {f.get_function_name(): f for f in mod.app.get_functions()}
    assert set(fns) == names
    for f in fns.values():
        trigger = f.get_trigger()
        assert trigger.type == "timerTrigger" and trigger.schedule.startswith("%ABSG_")
    sys.modules.pop("function_app", None)


def test_function_app_rejects_unknown_role(monkeypatch):
    pytest.importorskip("azure.functions")
    monkeypatch.setenv("ABSG_ROLE", "admin")
    monkeypatch.syspath_prepend(str(ROOT / "azure" / "functionapp"))
    sys.modules.pop("function_app", None)
    with pytest.raises(RuntimeError):
        importlib.import_module("function_app")
    sys.modules.pop("function_app", None)


def test_criteria_come_from_the_config():
    from absg.core import Config
    from absg.signer import CRITERIA, criteria_from_config
    assert criteria_from_config(Config(tenant_id="t", client_id="c")) == CRITERIA
    cfg = Config(tenant_id="t", client_id="c", approval_criteria=[
        {"column": "PRIV01", "id": "PRIV-01", "description": "Privacy impact assessed"}])
    assert criteria_from_config(cfg) == [("PRIV01", "PRIV-01", "Privacy impact assessed")]


# ---- Who changed the request ---------------------------------------------------
FLOW = {"user": {"id": "flow-1", "email": "svc-absg-flow@contoso.com"}}
REQUESTER = {"user": {"id": "owner-1", "email": "olivia@contoso.com"}}
SIGNER_APP = {"application": {"id": "mi", "displayName": "absg-signer"}}


def versions(*editors):
    """Newest first; the last one is the submission."""
    return [{"id": f"{len(editors) - i}.0", "lastModifiedBy": e} for i, e in enumerate(editors)]


def test_request_approved_by_the_flow_is_registered(signer_env):
    signer, g, *_ = signer_env(request_item(), signer_trusted_editors=["svc-absg-flow@contoso.com"])
    g.versions["7"] = versions(FLOW, SIGNER_APP, FLOW, REQUESTER)
    assert signer.run()["registered"] == ["p1"]


def test_requester_editing_their_own_request_is_refused(signer_env):
    # The requester set Status = Approved, ApprovedBy and the criteria themselves.
    signer, g, *_ = signer_env(request_item(), signer_trusted_editors=["svc-absg-flow@contoso.com"])
    g.versions["7"] = versions(REQUESTER, FLOW, REQUESTER)
    out = signer.run()
    assert out["needsCriteria"] == ["p1"] and "Approved Agents" not in g.lists
    reason = g.lists["Agent Sharing Requests"]["7"]["fields"]["SignerComments"]
    assert "edited by olivia@contoso.com" in reason


def test_missing_version_history_is_refused(signer_env):
    signer, g, *_ = signer_env(request_item(), signer_trusted_editors=["flow-1"])
    assert signer.run()["needsCriteria"] == ["p1"]


def test_registered_request_cannot_be_approved_again(signer_env):
    signer, g, *_ = signer_env(request_item(RegisteredEntryHash="abc"))
    assert signer.run()["needsCriteria"] == ["p1"]
    assert "already registered" in g.lists["Agent Sharing Requests"]["7"]["fields"]["SignerComments"]


def test_requested_by_counts_as_the_requester(signer_env):
    signer, g, *_ = signer_env(request_item(RequestedBy="jane.risk@contoso.com"))
    assert signer.run()["needsCriteria"] == ["p1"]
    assert "can't be the requester" in g.lists["Agent Sharing Requests"]["7"]["fields"]["SignerComments"]


def test_signed_entries_carry_signed_at_and_revocation_is_newer(signer_env):
    signer, g, site, vault, audit = signer_env(request_item())
    signer.run()
    (item,) = g.lists["Approved Agents"].values()
    approved = json.loads(item["fields"]["EntryJson"])
    g.lists["Agent Sharing Requests"]["7"]["fields"].update(Status="Revoke requested")
    assert signer.run()["revoked"] == ["p1"]
    revoked = json.loads(item["fields"]["EntryJson"])
    assert approved["signedAt"] < revoked["signedAt"]
    assert verify_entry(revoked, vault.public_jwk("registry-signing-key"))


# ---- The baseline is what reviewers saw ------------------------------------------
EMBEDDED = {"name": "EmbeddedKnowledge", "files": [{"name": "salaries.xlsx"}]}


def add_capability(g, cap, pid="p1"):
    el = g.packages[pid]["elementDetails"][0]["elements"][0]
    d = json.loads(el["definition"])
    d["capabilities"].append(cap)
    el["definition"] = json.dumps(d)


def test_request_in_review_gets_a_configuration_snapshot_once(signer_env):
    item = request_item(Status="In review", ReviewConfigHash=None, ReviewConfigCapturedAt=None)
    signer, g, *_ = signer_env(item)
    assert signer.run()["reviewSnapshots"] == ["p1"]
    f = g.lists["Agent Sharing Requests"]["7"]["fields"]
    assert f["ReviewConfigHash"] == config_hash() and f["Status"] == "In review"
    assert "OneDriveAndSharePoint: https://contoso.sharepoint.com/sites/hr" in f["ReviewConfigSummary"]
    assert "Embedded files: none" in f["ReviewConfigSummary"]
    captured = f["ReviewConfigCapturedAt"]
    add_capability(g, EMBEDDED)                     # a change during review doesn't move the snapshot
    assert signer.run()["reviewSnapshots"] == []
    assert f["ReviewConfigCapturedAt"] == captured and f["ReviewConfigHash"] == config_hash()


def test_agent_changed_after_review_is_refused_and_resnapshotted(signer_env):
    signer, g, *_ = signer_env(request_item(KS02="N/A"))
    add_capability(g, EMBEDDED)                      # owner uploads a file after the review
    assert signer.run()["needsCriteria"] == ["p1"]
    f = g.lists["Agent Sharing Requests"]["7"]["fields"]
    assert "changed after the review started" in f["SignerComments"]
    assert f["ReviewConfigHash"] == config_hash(g.packages["p1"])
    assert "salaries.xlsx" in f["ReviewConfigSummary"]
    f["Status"] = "Approved"                         # reviewers approve the new configuration
    assert signer.run()["registered"] == ["p1"]
    entry = json.loads(next(iter(g.lists["Approved Agents"].values()))["fields"]["EntryJson"])
    assert entry["baseline"]["configHash"] == f["ReviewConfigHash"]
    assert entry["baseline"]["reviewSnapshotAt"] == f["ReviewConfigCapturedAt"]


def test_approval_without_a_review_snapshot_is_refused(signer_env):
    signer, g, *_ = signer_env(request_item(ReviewConfigHash=None, ReviewConfigCapturedAt=None))
    assert signer.run()["needsCriteria"] == ["p1"]
    f = g.lists["Agent Sharing Requests"]["7"]["fields"]
    assert "wasn't recorded while the request was in review" in f["SignerComments"]
    assert f["ReviewConfigHash"] == config_hash() and f["ReviewConfigSummary"]


def test_ks02_pass_with_embedded_files_is_refused(signer_env):
    signer, g, *_ = signer_env(request_item())
    add_capability(g, EMBEDDED)
    g.lists["Agent Sharing Requests"]["7"]["fields"]["ReviewConfigHash"] = config_hash(g.packages["p1"])
    assert signer.run()["needsCriteria"] == ["p1"]
    assert "KS-02 is marked Pass, but the agent has embedded knowledge files: salaries.xlsx" in \
        g.lists["Agent Sharing Requests"]["7"]["fields"]["SignerComments"]


def test_unreadable_definition_is_refused(signer_env):
    signer, g, *_ = signer_env(request_item())
    g.packages["p1"]["elementDetails"] = []
    assert signer.run()["needsCriteria"] == ["p1"]
    assert "definition couldn't be read" in g.lists["Agent Sharing Requests"]["7"]["fields"]["SignerComments"]
