# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""Archive of retired Agent Builder agents, kept before they're deleted.

Each archived agent gets its own folder, ``<yyyy>/<packageId>/``, holding:

* ``agent.json``    - the package detail exactly as the Package Management API
                      returned it, including the declarative agent definition
                      (instructions, knowledge sources, capabilities, actions);
* ``manifest.json`` - who owned it, when it was last used, retired and archived, the
                      case ID linking it to the audit trail, any registry approval and
                      the SHA-256 of ``agent.json``;
* ``status-<event>.json`` - added later (``deleted``, ``reactivated``). Files are never
                      rewritten, so a record retention label can lock them.

Embedded files (uploaded knowledge) live in the agent's SharePoint Embedded
container and are **not** copied; the manifest lists them when the definition
names them. Keep them with a Purview retention policy if you need them.

Two stores: ``FileArchiveStore`` (local folder, for the standalone daemon) and
``SharePointArchiveStore`` (a document library on a restricted site, with an
optional retention label on each file).
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any

from .registry import sha256


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:120] or "agent"


def archive_files(detail: dict, manifest: dict) -> dict[str, bytes]:
    agent = json.dumps(detail, indent=2, sort_keys=True, default=str).encode()
    manifest = {**manifest, "agentJsonSha256": sha256(detail)}
    return {"agent.json": agent,
            "manifest.json": json.dumps(manifest, indent=2, sort_keys=True, default=str).encode()}


def folder_for(package_id: str, when: datetime | None = None) -> str:
    when = when or datetime.now(timezone.utc)
    return f"{when:%Y}/{_safe(package_id)}"


class FileArchiveStore:
    def __init__(self, root: str):
        self.root = root

    def save(self, package_id: str, files: dict[str, bytes]) -> dict:
        folder = folder_for(package_id)
        path = os.path.join(self.root, folder)
        os.makedirs(path, exist_ok=True)
        for name, data in files.items():
            with open(os.path.join(path, name), "wb") as fh:
                fh.write(data)
        return {"store": "file", "reference": folder, "location": os.path.abspath(path)}

    def record_status(self, reference: str, event: str, details: dict) -> None:
        with open(os.path.join(self.root, reference, f"status-{_safe(event)}.json"), "w", encoding="utf-8") as fh:
            json.dump(details, fh, indent=2, sort_keys=True, default=str)


class SharePointArchiveStore:
    def __init__(self, site: Any, library: str = "Retired Agents", retention_label: str | None = None):
        self.site, self.library, self.retention_label = site, library, retention_label

    def _put(self, path: str, data: bytes) -> dict | None:
        from .sharepoint import ConflictError
        try:
            self.site.upload(self.library, path, data, None)
        except ConflictError:          # left over from an earlier, interrupted attempt
            _, etag = self.site.download(self.library, path)
            self.site.upload(self.library, path, data, etag)
        return self.site.item(self.library, path)

    def save(self, package_id: str, files: dict[str, bytes]) -> dict:
        folder = folder_for(package_id)
        web_url = None
        for name, data in files.items():
            meta = self._put(f"{folder}/{name}", data) or {}
            if self.retention_label and meta.get("id"):
                self.site.set_retention_label(self.library, meta["id"], self.retention_label)
            if name == "manifest.json":
                web_url = meta.get("webUrl")
        return {"store": "sharepoint", "reference": folder, "library": self.library,
                "location": web_url or f"{self.library}/{folder}"}

    def record_status(self, reference: str, event: str, details: dict) -> None:
        meta = self._put(f"{reference}/status-{_safe(event)}.json",
                         json.dumps(details, indent=2, sort_keys=True, default=str).encode()) or {}
        if self.retention_label and meta.get("id"):
            self.site.set_retention_label(self.library, meta["id"], self.retention_label)
