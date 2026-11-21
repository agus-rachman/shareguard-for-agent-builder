# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""Registry signer for the Azure deployment of ShareGuard for Agent Builder.

Runs as its own Function app with its own managed identity. It turns sharing
requests that governance has approved into signed registry entries:

1. Reviewers assess a request in the *Agent Sharing Requests* list (criteria,
   evidence, risk rating, expiry, conditions) and an approval sets ``Status`` to
   ``Approved`` with ``ApprovedBy``.
2. The signer re-checks the request (every criterion pass or n/a, an approver who
   isn't the requester or an owner, an expiry within policy, active named owners),
   reads the live agent, captures its configuration as the baseline, signs the
   entry with the Key Vault HSM key (ES256) and writes it to *Approved Agents*.
3. ``Status`` = ``Revoke requested`` re-signs the existing entry as ``revoked``.

The signer can sign and write the registry, but can't block, unblock or email.
The guard can read the registry and verify signatures, but can't sign or write it.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from .core import Config, GraphError, sharing_recipients
from .registry import (attach_signature, draft_entry, entry_owners, sha256, signing_payload,
                       verify_entry)

log = logging.getLogger("absg.signer")

CRITERIA = [("KS01", "KS-01", "Knowledge sources limited to approved SharePoint sites"),
            ("KS02", "KS-02", "No embedded knowledge files"),
            ("DS01", "DS-01", "Content sensitivity reviewed; highest label in scope"),
            ("AU01", "AU-01", "Audience appropriate for the content"),
            ("AC01", "AC-01", "No actions or plugins that write data")]
POLICY_KEYS = {"driftMode", "instructionsChange", "allowEmbeddedFiles", "allowUnscoped",
               "allowedCapabilities", "allowedKnowledgeUrlPrefixes", "allowActions",
               "requireRegisteredOwners", "requireActiveOwner"}


def criteria_from_config(cfg: Config) -> list[tuple[str, str, str]]:
    """The organisation's sharing criteria: approval_criteria in the config, each
    {"column": "KS01", "id": "KS-01", "description": "..."}, or the defaults above.
    Each column is a Pass / Fail / N/A choice column in the requests list."""
    if not cfg.approval_criteria:
        return list(CRITERIA)
    return [(c["column"], c.get("id") or c["column"], c.get("description") or "")
            for c in cfg.approval_criteria]


def _split(text: Any) -> list[str]:
    return [p.strip() for p in str(text or "").replace(",", ";").replace("\n", ";").split(";") if p.strip()]


class RequestProblem(ValueError):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


class RegistrySigner:
    def __init__(self, cfg: Config, graph: Any, site: Any, vault: Any, audit: Any = None,
                 max_approval_days: int = 365):
        self.cfg, self.graph, self.site, self.vault, self.audit = cfg, graph, site, vault, audit
        self.max_approval_days = max_approval_days
        self.criteria = criteria_from_config(cfg)
        self._public: dict | None = None

    # -- helpers ---------------------------------------------------------------
    def _record(self, event: str, **fields: Any) -> None:
        if self.audit:
            self.audit.record(event, **fields)

    def _user(self, ref: str) -> dict | None:
        try:
            return self.graph.request(
                "GET", f"/users/{ref}?$select=id,userPrincipalName,mail,accountEnabled").json()
        except GraphError:
            return None

    def _public_key(self) -> dict:
        if self._public is None:
            self._public = self.vault.public_jwk(self.cfg.registry_key_name)
        return self._public

    def _find(self, list_name: str, title: str) -> dict | None:
        safe = title.replace("'", "''")
        return next(iter(self.site.list_items(list_name, f"fields/Title eq '{safe}'")), None)

    def _sign(self, entry: dict) -> dict:
        entry = {**entry, "signatureAlgorithm": "ES256"}
        entry.pop("signature", None)
        signed = attach_signature(entry, self.vault.sign_es256(self.cfg.registry_key_name,
                                                               signing_payload(entry)), "ES256")
        if not verify_entry(signed, self._public_key()):
            raise RuntimeError("Key Vault signature did not verify with the registry public key")
        return signed

    def _save(self, entry: dict) -> None:
        a = entry.get("approval") or {}
        fields = {"Title": entry["packageId"], "EntryJson": json.dumps(entry, sort_keys=True),
                  "Status": entry.get("status", "approved"), "RequestId": a.get("requestId") or "",
                  "ExpiresAt": a.get("expiresAt") or "", "RiskRating": a.get("riskRating") or "",
                  "DisplayName": entry.get("displayName") or "",
                  "Owners": "; ".join(entry_owners(entry))}
        existing = self._find(self.cfg.sharepoint_registry_list, entry["packageId"])
        if existing:
            self.site.update_fields(self.cfg.sharepoint_registry_list, existing["id"], fields)
        else:
            self.site.create_item(self.cfg.sharepoint_registry_list, fields)

    def _check_history(self, item: dict) -> list[str]:
        """Problems if anyone but a trusted editor changed the request after it was created.

        Item-level permissions let a requester edit their own item, so the fields the
        signer trusts (Status, ApprovedBy, the criteria, PolicyJson, PackageId, ...)
        must be shown to come from the approval flow or a reviewer."""
        trusted = {t.lower() for t in self.cfg.signer_trusted_editors}
        if not trusted:
            log.warning("signer_trusted_editors is not set: request edit history is not checked")
            return []
        trusted.add(str(self.cfg.client_id).lower())          # the signer's own status updates
        versions = self.site.item_versions(self.cfg.sharepoint_requests_list, item["id"])
        if not versions:
            return ["the request's version history is unavailable (turn on list versioning)"]
        problems = []
        for v in versions[:-1]:                                # the oldest version is the submission
            by = v.get("lastModifiedBy") or {}
            who = {str(x.get(k, "")).lower() for x in (by.get("user") or {}, by.get("application") or {})
                   for k in ("id", "email") if x.get(k)}
            if not who & trusted:
                name = (by.get("user") or by.get("application") or {})
                problems.append(f"version {v.get('id')} was edited by "
                                f"{name.get('email') or name.get('displayName') or name.get('id') or 'unknown'}, "
                                "who isn't a reviewer or the approval flow")
        return problems

    def _mark(self, item: dict, status: str, **fields: Any) -> None:
        self.site.update_fields(self.cfg.sharepoint_requests_list, item["id"], {"Status": status, **fields})

    # -- request -> entry ---------------------------------------------------------
    def build_entry(self, item: dict) -> dict:
        f = item.get("fields") or {}
        problems: list[str] = []
        pid = (f.get("PackageId") or "").strip()
        if not pid:
            raise RequestProblem(["PackageId is empty"])
        if f.get("RegisteredEntryHash"):
            # Re-approving a registered request would re-sign it with a fresh expiry and a
            # baseline taken from the agent as it is now, wiping out any drift.
            raise RequestProblem(["this request is already registered; submit a new request "
                                  "to change or renew the approval"])
        history = self._check_history(item)
        if history:
            raise RequestProblem(history)
        try:
            detail = self.graph.get_package(pid)
        except GraphError as exc:
            raise RequestProblem([f"agent {pid} not found ({exc.status})"]) from None

        requester = ((item.get("createdBy") or {}).get("user") or {})
        requester_ids = {str(requester.get(k, "")).lower() for k in ("id", "email") if requester.get(k)}
        # When a flow creates the item for the requester, it records them in RequestedBy.
        requester_ids |= {r.lower() for r in _split(f.get("RequestedBy"))}
        owner_refs = _split(f.get("Owners")) or ([requester.get("email") or requester.get("id")]
                                                if requester else [])
        owners, owner_upns = [], []
        for ref in owner_refs:
            u = self._user(ref)
            if not u:
                problems.append(f"owner {ref} not found")
            elif u.get("accountEnabled") is False:
                problems.append(f"owner {ref} is disabled")
            else:
                owners.append(u["id"])
                owner_upns.append(str(u.get("userPrincipalName") or "").lower())
        if not owners and not problems:
            problems.append("no named owner")

        approver = (f.get("ApprovedBy") or "").strip()
        if not approver:
            problems.append("ApprovedBy is empty")
        elif approver.lower() in requester_ids or approver.lower() in owner_upns:
            problems.append("the approver can't be the requester or an owner")

        criteria = []
        for col, cid, desc in self.criteria:
            raw = str(f.get(col) or "").strip().lower()
            result = {"pass": "pass", "fail": "fail", "n/a": "n/a", "na": "n/a"}.get(raw)
            if result is None:
                problems.append(f"{cid} not assessed")
            elif result == "fail":
                problems.append(f"{cid} failed")
            criteria.append({"id": cid, "description": desc, "result": result or "",
                             "evidence": f.get("Evidence") or ""})

        rating = str(f.get("RiskRating") or "").strip().lower()
        if rating not in ("low", "medium", "high"):
            problems.append("RiskRating must be Low, Medium or High")

        expires = str(f.get("ExpiresAt") or "").strip()
        now = datetime.now(timezone.utc)
        try:
            exp = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            exp = exp if exp.tzinfo else exp.replace(tzinfo=timezone.utc)
            if exp <= now:
                problems.append("ExpiresAt is in the past")
            elif exp > now + timedelta(days=self.max_approval_days):
                problems.append(f"ExpiresAt is more than {self.max_approval_days} days away")
        except ValueError:
            problems.append("ExpiresAt is missing or not a date")

        audience = [{"resourceType": "group", "resourceId": g} for g in _split(f.get("AudienceGroupIds"))]
        if not audience:
            problems.append("AudienceGroupIds is empty: name the groups the agent may be shared with")

        policy_overrides: dict = {}
        if f.get("PolicyJson"):
            try:
                policy_overrides = json.loads(f["PolicyJson"])
                unknown = set(policy_overrides) - POLICY_KEYS
                if unknown:
                    problems.append(f"PolicyJson has unknown keys: {', '.join(sorted(unknown))}")
            except json.JSONDecodeError:
                problems.append("PolicyJson is not valid JSON")
        if problems:
            raise RequestProblem(problems)

        entry = draft_entry(detail, owners, audience, self.cfg.embedded_capability_names)
        entry["approval"] = {
            "requestId": f"REQ-{item['id']}",
            "approvedBy": approver,
            "approvedAt": now.isoformat(),
            "expiresAt": exp.isoformat(),
            "riskRating": rating,
            "riskScore": f.get("RiskScore"),
            "criteria": criteria,
            "conditions": _split(f.get("Conditions")),
            "notes": f.get("ReviewerComments") or "",
            "requestedBy": (f.get("RequestedBy") or "").strip() or requester.get("email") or requester.get("id"),
            "justification": f.get("Justification") or "",
        }
        entry["policy"].update(policy_overrides)
        entry["governanceContacts"] = _split(f.get("GovernanceContacts"))
        live = sharing_recipients(detail, self.cfg)
        entry["baseline"]["sharedWithAtApproval"] = live
        return entry

    # -- cycle --------------------------------------------------------------------
    def run(self) -> dict:
        done = {"registered": [], "revoked": [], "needsCriteria": [], "failed": []}
        flt = "fields/Status eq 'Approved' or fields/Status eq 'Revoke requested'"
        for item in list(self.site.list_items(self.cfg.sharepoint_requests_list, flt)):
            f = item.get("fields") or {}
            pid = f.get("PackageId")
            try:
                if f.get("Status") == "Revoke requested":
                    self._revoke(item)
                    done["revoked"].append(pid)
                    continue
                entry = self.build_entry(item)
                signed = self._sign(entry)
                if self.cfg.dry_run:
                    self._record("registry_entry_signed", package={"id": pid}, requestId=f"REQ-{item['id']}",
                                 entryHash=sha256(signed), outcome="simulated")
                    continue
                self._save(signed)
                self._mark(item, "Registered", RegisteredEntryHash=sha256(signed), ReviewerComments=f.get(
                    "ReviewerComments") or "")
                self._record("registry_entry_signed", package={"id": pid, "displayName": signed.get("displayName")},
                             requestId=signed["approval"]["requestId"], approvedBy=signed["approval"]["approvedBy"],
                             owners=signed["owners"], riskRating=signed["approval"]["riskRating"],
                             expiresAt=signed["approval"]["expiresAt"],
                             allowedPrincipals=signed["sharing"]["allowedPrincipals"],
                             baselineHash=signed["baseline"]["configHash"], entryHash=sha256(signed),
                             signatureAlgorithm="ES256", outcome="success")
                done["registered"].append(pid)
            except RequestProblem as exc:
                if not self.cfg.dry_run:
                    self._mark(item, "Needs criteria", SignerComments="Not registered: " + "; ".join(exc.problems))
                self._record("registry_request_refused", package={"id": pid}, requestId=f"REQ-{item['id']}",
                             problems=exc.problems)
                done["needsCriteria"].append(pid)
            except Exception as exc:   # signing or SharePoint failure: retried on the next run
                log.exception("Signing request %s failed", item.get("id"))
                if not self.cfg.dry_run:
                    self._mark(item, "Signing failed", SignerComments=str(exc)[:250])
                self._record("error", stage="sign", package={"id": pid}, error=str(exc))
                done["failed"].append(pid)
        return done

    def _revoke(self, item: dict) -> None:
        f = item.get("fields") or {}
        pid = f.get("PackageId")
        existing = self._find(self.cfg.sharepoint_registry_list, pid or "")
        if not existing:
            raise RequestProblem([f"no registry entry for {pid}"])
        entry = json.loads((existing.get("fields") or {}).get("EntryJson") or "{}")
        if not verify_entry(entry, self._public_key()):
            raise RequestProblem(["the current entry's signature doesn't verify; investigate before revoking"])
        # No edit-history check here: revoking only removes access, and a requester's edit
        # must not be able to block it.
        approver = (f.get("ApprovedBy") or "").strip()
        if not approver:
            raise RequestProblem(["ApprovedBy is empty"])
        entry["status"] = "revoked"
        entry["approval"] = {**(entry.get("approval") or {}), "revokedBy": approver,
                             "revokedAt": datetime.now(timezone.utc).isoformat(),
                             "revocationReason": f.get("ReviewerComments") or ""}
        signed = self._sign(entry)
        if self.cfg.dry_run:
            self._record("registry_entry_revoked", package={"id": pid}, outcome="simulated")
            return
        self._save(signed)
        self._mark(item, "Revoked", RegisteredEntryHash=sha256(signed))
        self._record("registry_entry_revoked", package={"id": pid}, revokedBy=approver,
                     entryHash=sha256(signed), outcome="success")


def run_signer(cfg: Config | None = None) -> dict:
    """One signer run (the Azure Functions timer calls this)."""
    from .core import GraphClient
    from .runtime import audit_log, key_vault
    from .sharepoint import SharePointSite

    cfg = cfg or Config.load(None)
    if not (cfg.sharepoint_registry_site_id and cfg.key_vault_url):
        raise ValueError("the signer needs sharepoint_registry_site_id and key_vault_url")
    graph = GraphClient(cfg)
    site = SharePointSite(graph, cfg.sharepoint_registry_site_id)
    audit_cfg = Config(**{**cfg.__dict__, "sharepoint_operations_site_id": cfg.sharepoint_registry_site_id,
                          "sharepoint_audit_library": cfg.signer_audit_library})
    audit = audit_log(audit_cfg, "signer", site, prefix="absg-signer-audit-")
    try:
        return RegistrySigner(cfg, graph, site, key_vault(cfg), audit,
                              max_approval_days=cfg.max_approval_days).run()
    finally:
        audit.flush()
