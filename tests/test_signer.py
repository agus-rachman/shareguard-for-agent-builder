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
from absg.registry import Registry, verify_entry
from absg.sharepoint import SharePointRegistrySource, SharePointSite
from absg.signer import RegistrySigner
from test_azure import DownloadSession, FakeGraph, FakeVault, Resp

ROOT = Path(__file__).resolve().parent.parent


class SignerGraph(FakeGraph):
    def __init__(self):
        super().__init__()
        self.packages = {"p1": {"id": "p1", "displayName": "HR helper", "manifestId": "m1",
                                "sharedWithUsersAndGroups": [], "elementDetails": []}}
        self.directory = {"olivia@contoso.com": {"id": "owner-1", "userPrincipalName": "olivia@contoso.com",
                                                 "accountEnabled": True},
                          "noah@contoso.com": {"id": "owner-2", "userPrincipalName": "noah@contoso.com",
                                               "accountEnabled": True},
                          "gone@contoso.com": {"id": "owner-3", "userPrincipalName": "gone@contoso.com",
                                               "accountEnabled": False}}

    def get_package(self, pid):
        if pid not in self.packages:
            raise GraphError(404, "not found")
        return json.loads(json.dumps(self.packages[pid]))

    def request(self, method, url, headers=None, json=None, data=None, **kw):
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
                items = [i for i in items if i["fields"].get("Status") in ("Approved", "Revoke requested")]
            return Resp({"value": [dict(i) for i in items]})
        return super().request(method, url, headers=headers, json=json, data=data, **kw)


def request_item(**over):
    fields = {"Title": "HR helper", "PackageId": "p1", "Owners": "olivia@contoso.com; noah@contoso.com",
              "AudienceGroupIds": "g-hr; g-hr-leads", "KS01": "Pass", "KS02": "Pass", "DS01": "Pass",
              "AU01": "N/A", "AC01": "Pass", "Evidence": "https://contoso.sharepoint.com/sites/gov/REQ-7",
              "RiskRating": "Low", "RiskScore": 4, "ApprovedBy": "jane.risk@contoso.com",
              "ExpiresAt": (datetime.now(timezone.utc) + timedelta(days=180)).isoformat(),
              "Conditions": "Re-review on site permission change", "Status": "Approved",
              "GovernanceContacts": "ai-governance@contoso.com"}
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
