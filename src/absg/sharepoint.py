# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""SharePoint Online stores for ShareGuard for Agent Builder, through Microsoft Graph.

Used by the Azure deployment so that all of the guard's data stays in Microsoft 365:

* ``SharePointJsonDocument``   - the state file (``state.json``) in a document library,
                                 written with an eTag check so two writers can't
                                 silently overwrite each other.
* ``SharePointAuditBackend``   - the hash-chained audit trail as one JSON Lines file
                                 per UTC day; the chain carries on across files, and
                                 closed days can be given a retention (record) label.
* ``SharePointRegistrySource`` - signed registry entries from the *Approved Agents* list.
* ``SharePointLockReleases``   - governance releases of agents locked after repeated
                                 violations, from a list only governance can write.
* ``SharePointAckStore``       - owner acknowledgements written to a list by a
                                 Microsoft Forms + Power Automate flow; the guard
                                 checks each one before acting on it.

Permissions (application, through the managed identities): ``Sites.Selected``, granted
on the ABSG sites only (azure/scripts/Grant-AbsgSiteAccess.ps1).
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Iterator
from urllib.parse import quote

import requests

log = logging.getLogger("absg.sharepoint")

SIMPLE_UPLOAD_LIMIT = 4 * 1024 * 1024
UPLOAD_CHUNK = 5 * 320 * 1024          # a multiple of 320 KiB, as Graph requires


class ConflictError(RuntimeError):
    """The file changed since it was read (HTTP 412): another writer is active."""


def _path(p: str) -> str:
    return quote(p.strip("/"), safe="/")


class SharePointSite:
    """Graph helpers for one site: document library files and list items."""

    def __init__(self, graph: Any, site_id: str, session: requests.Session | None = None):
        self.graph = graph
        self.site_id = site_id
        self.session = session or requests.Session()
        self._drives: dict[str, str] = {}

    # -- libraries ------------------------------------------------------------
    def drive_id(self, library: str) -> str:
        if library not in self._drives:
            drives = self.graph.request("GET", f"/sites/{self.site_id}/drives?$select=id,name").json()
            for d in drives.get("value", []):
                self._drives[d["name"]] = d["id"]
            if library not in self._drives:
                raise LookupError(f"document library '{library}' not found on site {self.site_id}")
        return self._drives[library]

    def item(self, library: str, path: str) -> dict | None:
        from .core import GraphError
        try:
            return self.graph.request("GET", f"/drives/{self.drive_id(library)}/root:/{_path(path)}").json()
        except GraphError as exc:
            if exc.status == 404:
                return None
            raise

    def download(self, library: str, path: str) -> tuple[bytes | None, str | None]:
        """File content and eTag, or (None, None) when the file doesn't exist."""
        meta = self.item(library, path)
        if meta is None:
            return None, None
        url = meta.get("@microsoft.graph.downloadUrl")
        if url:   # pre-authenticated, short-lived URL: no bearer token
            resp = self.session.get(url, timeout=60)
            resp.raise_for_status()
            content = resp.content
        else:
            content = self.graph.request(
                "GET", f"/drives/{self.drive_id(library)}/root:/{_path(path)}:/content").content
        return content, meta.get("eTag")

    def upload(self, library: str, path: str, data: bytes, etag: str | None) -> str:
        """Write the file. ``etag`` = the version read (If-Match); None = it must not exist yet."""
        from .core import GraphError
        drive = self.drive_id(library)
        cond = {"If-Match": etag} if etag else {"If-None-Match": "*"}
        try:
            if len(data) <= SIMPLE_UPLOAD_LIMIT:
                resp = self.graph.request("PUT", f"/drives/{drive}/root:/{_path(path)}:/content",
                                          headers={**cond, "Content-Type": "application/octet-stream"},
                                          data=data)
                return resp.json().get("eTag")
            session = self.graph.request(
                "POST", f"/drives/{drive}/root:/{_path(path)}:/createUploadSession", headers=cond,
                json={"item": {"@microsoft.graph.conflictBehavior": "replace"}}).json()
        except GraphError as exc:
            if exc.status in (409, 412):
                raise ConflictError(f"{library}/{path} changed since it was read") from exc
            raise
        url, last = session["uploadUrl"], {}
        for start in range(0, len(data), UPLOAD_CHUNK):
            chunk = data[start:start + UPLOAD_CHUNK]
            end = start + len(chunk) - 1
            resp = self.session.put(url, data=chunk, timeout=120, headers={
                "Content-Length": str(len(chunk)), "Content-Range": f"bytes {start}-{end}/{len(data)}"})
            if resp.status_code >= 400:
                raise ConflictError(f"upload of {library}/{path} failed: {resp.status_code} {resp.text[:200]}")
            last = resp.json() if resp.content else {}
        return last.get("eTag")

    def children(self, library: str, folder: str) -> list[dict]:
        drive = self.drive_id(library)
        base = f"/drives/{drive}/root:/{_path(folder)}:/children" if folder.strip("/") else \
            f"/drives/{drive}/root/children"
        return list(self.graph.get_paged(base + "?$select=id,name,eTag&$top=999"))

    def set_retention_label(self, library: str, item_id: str, label: str) -> None:
        self.graph.request("PATCH", f"/drives/{self.drive_id(library)}/items/{item_id}/retentionLabel",
                           json={"name": label})

    # -- lists -----------------------------------------------------------------
    def list_items(self, list_name: str, filter_: str | None = None) -> Iterator[dict]:
        url = f"/sites/{self.site_id}/lists/{quote(list_name)}/items?$expand=fields&$top=999"
        headers = None
        if filter_:
            url += "&$filter=" + quote(filter_)
            headers = {"Prefer": "HonorNonIndexedQueriesWarningMayFailRandomly"}
        while url:
            data = self.graph.request("GET", url, headers=headers).json()
            yield from data.get("value", [])
            url = data.get("@odata.nextLink")

    def item_versions(self, list_name: str, item_id: str) -> list[dict]:
        """Every version of a list item, newest first (each with ``lastModifiedBy``)."""
        return list(self.graph.get_paged(
            f"/sites/{self.site_id}/lists/{quote(list_name)}/items/{quote(str(item_id))}/versions"))

    def update_fields(self, list_name: str, item_id: str, fields: dict) -> None:
        self.graph.request("PATCH", f"/sites/{self.site_id}/lists/{quote(list_name)}/items/{item_id}/fields",
                           json=fields)

    def create_item(self, list_name: str, fields: dict) -> dict:
        return self.graph.request("POST", f"/sites/{self.site_id}/lists/{quote(list_name)}/items",
                                  json={"fields": fields}).json()


# ------------------------------------------------------------------------------ state
class SharePointJsonDocument:
    """A JSON document (the guard's state) in a document library, eTag-checked."""

    def __init__(self, site: SharePointSite, library: str, path: str):
        self.site, self.library, self.path = site, library, path
        self.etag: str | None = None

    def load(self) -> dict | None:
        content, self.etag = self.site.download(self.library, self.path)
        return json.loads(content) if content else None

    def save(self, data: dict) -> None:
        body = json.dumps(data, indent=2, sort_keys=True).encode()
        self.etag = self.site.upload(self.library, self.path, body, self.etag)


# ------------------------------------------------------------------------------ audit
def _rechain(records: list[dict], seq: int, prev: str) -> list[dict]:
    from .core import _record_hash
    out = []
    for rec in records:
        seq += 1
        rec = {**rec, "seq": seq, "prevHash": prev}
        rec["hash"] = _record_hash(rec)
        prev = rec["hash"]
        out.append(rec)
    return out


class SharePointAuditBackend:
    """Hash-chained audit records in daily JSON Lines files (``<prefix>YYYY-MM-DD.jsonl``).

    SharePoint has no append, so records are buffered and each flush rewrites the
    day's file with an eTag check. Records that can't be written stay buffered and
    are retried at the next flush. When ``retention_label`` is set, files for days
    that have ended get that label (for example a Purview *record* label), after
    which they can't be edited or deleted.
    """

    def __init__(self, site: SharePointSite, library: str, folder: str = "",
                 prefix: str = "absg-audit-", retention_label: str | None = None,
                 pending: list[dict] | None = None):
        self.site, self.library, self.folder = site, library, folder.strip("/")
        self.prefix, self.retention_label = prefix, retention_label
        # ``pending``: records an earlier process couldn't write (kept in the guard's state).
        self.buffer: list[dict] = [dict(r) for r in pending or []]
        self._labelled: set[str] = set()

    def _name(self, day: str) -> str:
        return f"{self.prefix}{day}.jsonl"

    def _path(self, name: str) -> str:
        return f"{self.folder}/{name}" if self.folder else name

    def files(self) -> list[dict]:
        out = [c for c in self.site.children(self.library, self.folder)
               if c.get("name", "").startswith(self.prefix) and c["name"].endswith(".jsonl")]
        return sorted(out, key=lambda c: c["name"])

    def _stored_tail(self) -> tuple[int, str]:
        from .core import GENESIS_HASH
        for f in reversed(self.files()):
            content, _ = self.site.download(self.library, self._path(f["name"]))
            lines = [ln for ln in (content or b"").decode().splitlines() if ln.strip()]
            if lines:
                rec = json.loads(lines[-1])
                return int(rec["seq"]), rec["hash"]
        return 0, GENESIS_HASH

    def resume(self) -> tuple[int, str]:
        seq, last = self._stored_tail()
        if not self.buffer:
            return seq, last
        # Drop records that were written after all (a lost response, or another process
        # flushed the same pending copy): look for them in their days' files.
        stored: set[str] = {last}
        existing = {f["name"] for f in self.files()}
        for day in sorted({str(r.get("timestamp", ""))[:10] for r in self.buffer}):
            if self._name(day) in existing:
                content, _ = self.site.download(self.library, self._path(self._name(day)))
                for ln in (content or b"").decode().splitlines():
                    if ln.strip():
                        stored.add(json.loads(ln).get("hash"))
        self.buffer = [r for r in self.buffer if r.get("hash") not in stored]
        if self.buffer and (self.buffer[0].get("prevHash") != last or self.buffer[0].get("seq") != seq + 1):
            # Something else wrote to the chain meanwhile. These records were never
            # published, so chain them onto what is actually stored.
            log.warning("Re-chaining %d unwritten audit records onto seq %d", len(self.buffer), seq)
            self.buffer = _rechain(self.buffer, seq, last)
        if self.buffer:
            return int(self.buffer[-1]["seq"]), self.buffer[-1]["hash"]
        return seq, last

    def append(self, rec: dict) -> None:
        self.buffer.append(rec)

    def flush(self) -> None:
        if not self.buffer:
            self._label_closed_days()
            return
        by_day: dict[str, list[dict]] = {}
        for rec in self.buffer:
            by_day.setdefault(str(rec.get("timestamp", ""))[:10], []).append(rec)
        written: list[dict] = []
        try:
            for day in sorted(by_day):
                path = self._path(self._name(day))
                content, etag = self.site.download(self.library, path)
                text = (content or b"").decode()
                if text and not text.endswith("\n"):
                    text += "\n"
                text += "".join(json.dumps(r, sort_keys=True, default=str) + "\n" for r in by_day[day])
                self.site.upload(self.library, path, text.encode(), etag)
                written += by_day[day]
        finally:
            done = {id(r) for r in written}
            self.buffer = [r for r in self.buffer if id(r) not in done]
        self._label_closed_days()

    def _label_closed_days(self) -> None:
        if not self.retention_label:
            return
        today = datetime.now(timezone.utc).date().isoformat()
        try:
            for f in self.files():
                day = f["name"][len(self.prefix):-len(".jsonl")]
                if day < today and f["name"] not in self._labelled:
                    try:
                        self.site.set_retention_label(self.library, f["id"], self.retention_label)
                    except Exception as exc:   # already labelled, or label not published to the site
                        log.debug("retention label on %s: %s", f["name"], exc)
                    self._labelled.add(f["name"])
        except Exception as exc:
            log.warning("Could not apply retention labels: %s", exc)

    def iter_lines(self) -> Iterator[str]:
        """Every record, oldest first, across all daily files (for verification)."""
        for f in self.files():
            content, _ = self.site.download(self.library, self._path(f["name"]))
            yield from (content or b"").decode().splitlines()


# ------------------------------------------------------------------------------ registry
class SharePointRegistrySource:
    """Registry entries from a list: one item per agent, the signed entry in ``EntryJson``."""

    def __init__(self, site: SharePointSite, list_name: str = "Approved Agents",
                 field: str = "EntryJson"):
        self.site, self.list_name, self.field = site, list_name, field

    def fetch(self) -> tuple[list[Any], str]:
        agents: list[Any] = []
        raw: list[str] = []
        for item in self.site.list_items(self.list_name):
            fields = item.get("fields") or {}
            text = fields.get(self.field)
            if not text:
                continue
            raw.append(text)
            try:
                agents.append(json.loads(text))
            except json.JSONDecodeError:
                agents.append((fields.get("Title") or f"item-{item.get('id')}", None))
        digest = hashlib.sha256("\n".join(sorted(raw)).encode()).hexdigest()
        return agents, digest


# ------------------------------------------------------------------------------ lock releases
class SharePointLockReleases:
    """Releases of locked agents from the *Agent Lock Releases* list on the operations site.

    Governance adds an item: ``Title`` = the package id, ``Reason``. SharePoint records who
    created it, which the guard audits as ``releasedBy`` (an agent's own owner is refused).
    The guard marks each item it uses ``Applied`` or ``Rejected``."""

    def __init__(self, site: SharePointSite, list_name: str = "Agent Lock Releases"):
        self.site, self.list_name = site, list_name

    def fetch(self) -> list[dict]:
        out = []
        for item in self.site.list_items(self.list_name, "fields/Status eq 'New'"):
            f = item.get("fields") or {}
            by = (item.get("createdBy") or {}).get("user") or {}
            out.append({"packageId": (f.get("Title") or "").strip(),
                        "releasedBy": by.get("email") or by.get("displayName") or "",
                        "releasedById": by.get("id"), "reason": f.get("Reason") or "",
                        "requestedAt": item.get("createdDateTime") or f.get("Created"), "ref": item.get("id")})
        return out

    def mark(self, release: dict, status: str, note: str = "") -> None:
        self.site.update_fields(self.list_name, release["ref"], {"Status": status, "StatusReason": note})


# ------------------------------------------------------------------------------ acknowledgements
class SharePointAckStore:
    """Owner acknowledgements from the *Agent Acknowledgements* list.

    A Microsoft Forms + Power Automate flow adds an item per response with
    ``Token`` (the signed token from the notice email, pre-filled in the form),
    ``ResponderUpn`` (recorded by Forms) and ``Status`` = ``New``. Each cycle,
    ``refresh`` checks every new item: the token's signature and expiry, that the
    case hasn't been acknowledged already, and that the responder is the owner the
    link was sent to. Accepted items are then processed like endpoint
    acknowledgements; rejected ones are marked with the reason.
    """

    OPEN = ("New", "Accepted")

    def __init__(self, site: SharePointSite, signer: Any, resolve_user: Callable[[str], str | None],
                 list_name: str = "Agent Acknowledgements"):
        self.site, self.signer, self.resolve_user = site, signer, resolve_user
        self.list_name = list_name
        self._accepted: dict[str, dict] = {}
        self._used: set[str] = set()

    def refresh(self, audit: Callable[..., None] | None = None) -> None:
        from .ack import TokenError
        audit = audit or (lambda *a, **k: None)
        items = list(self.site.list_items(self.list_name))
        accepted: dict[str, dict] = {}
        used = {(i.get("fields") or {}).get("CaseId") for i in items
                if (i.get("fields") or {}).get("Status") in ("Accepted", "Closed")}
        for item in sorted(items, key=lambda i: int(i.get("id", 0))):
            f = item.get("fields") or {}
            status = f.get("Status") or "New"
            if status == "Accepted":
                accepted[f.get("CaseId")] = self._ack(item)
                continue
            if status != "New":
                continue
            reason = None
            claims = None
            try:
                claims = self.signer.verify((f.get("Token") or "").strip())
            except TokenError as exc:
                reason = f"token {exc}"
            if claims and claims.case_id in used:
                reason = "case already acknowledged"
            responder = None
            if claims and not reason:
                upn = (f.get("ResponderUpn") or "").strip()
                responder = self.resolve_user(upn) if upn else None
                if not responder:
                    reason = "responder could not be identified"
                elif responder.lower() != claims.owner_id.lower():
                    reason = "responder is not the owner the link was sent to"
            if reason:
                self.site.update_fields(self.list_name, item["id"],
                                        {"Status": "Rejected", "StatusReason": reason})
                audit("ack_rejected", claims.package_id if claims else None,
                      caseId=claims.case_id if claims else None, reason=reason, source="forms",
                      responderUpn=f.get("ResponderUpn"), listItemId=item["id"])
                continue
            fields = {"Status": "Accepted", "CaseId": claims.case_id, "PackageId": claims.package_id,
                      "OwnerId": claims.owner_id, "TokenId": claims.token_id, "StatusReason": ""}
            self.site.update_fields(self.list_name, item["id"], fields)
            used.add(claims.case_id)
            item["fields"] = {**f, **fields}
            accepted[claims.case_id] = self._ack(item)
            audit("ack_received", claims.package_id, caseId=claims.case_id, ownerId=claims.owner_id,
                  ackTokenId=claims.token_id, responderUpn=f.get("ResponderUpn"),
                  identityVerified=True, source="forms", listItemId=item["id"])
        self._accepted, self._used = accepted, used

    @staticmethod
    def _ack(item: dict) -> dict:
        f = item.get("fields") or {}
        return {"caseId": f.get("CaseId"), "packageId": f.get("PackageId"), "ownerId": f.get("OwnerId"),
                "tokenId": f.get("TokenId"), "receivedAt": item.get("createdDateTime") or f.get("Created"),
                "attempts": int(f.get("Attempts") or 0), "itemId": item.get("id")}

    # -- the interface the guard uses (same as ack.AckStore) ----------------------
    def pending(self) -> list[dict]:
        return [dict(a) for a in self._accepted.values()]

    def pending_for_package(self, package_id: str) -> list[dict]:
        return [a for a in self.pending() if a["packageId"] == package_id]

    def bump_attempt(self, case_id: str) -> int:
        ack = self._accepted.get(case_id)
        if not ack:
            return 0
        ack["attempts"] += 1
        self.site.update_fields(self.list_name, ack["itemId"], {"Attempts": ack["attempts"]})
        return ack["attempts"]

    def close(self, case_id: str) -> None:
        ack = self._accepted.pop(case_id, None)
        if ack:
            self.site.update_fields(self.list_name, ack["itemId"], {"Status": "Closed"})
        self._used.add(case_id)

    def is_used(self, case_id: str) -> bool:
        return case_id in self._used
