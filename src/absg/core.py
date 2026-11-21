# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""
ShareGuard for Agent Builder (ABSG)
===================================

Daemon that enforces a "no sharing" policy for Microsoft 365 Copilot
Agent Builder agents.

Policy
------
* Users may create Agent Builder agents for their own use.
* If an Agent Builder agent is shared with any other user or group, the
  daemon blocks it (tenant-wide) through the Package Management API.
* Once the owner removes all sharing, the daemon unblocks it.
* The daemon only ever unblocks agents that it blocked itself. Agents that
  an admin blocked for other reasons are never touched.
* A user's first Agent Builder agent triggers a welcome email.
* A block triggers a notice email to the owner with a signed link. When the
  owner confirms, the daemon removes sharing on their behalf (delegated
  identity), checks that sharing is gone, unblocks the agent and emails the owner.
* Approved agents in the signed registry may be shared within their approved
  audience. Each cycle their live configuration is checked for drift against
  the approved baseline. Drift blocks the agent until it is rectified.
* Everything is recorded in the hash-chained audit trail under a caseId.

Microsoft APIs used (Microsoft Graph)
-------------------------------------
  GET   /copilot/admin/catalog/packages?$filter=platform eq '...Agent Builder'
  GET   /copilot/admin/catalog/packages/{id}
  POST  /copilot/admin/catalog/packages/{id}/block | /unblock   (application)
  PATCH /copilot/admin/catalog/packages/{id}                    (delegated only)
  GET   /users/{id}, /directoryObjects/{id}
  POST  /users/{sender}/sendMail

Requires a Microsoft Agent 365 licence. See README for the permissions.

Run:
  absg --config config.json            # daemon
  absg --config config.json --once     # one pass
  absg --config config.json --dry-run  # report only
"""
from __future__ import annotations

import argparse
import hashlib
import json
import uuid
import logging
import os
import signal
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Iterator

import requests

log = logging.getLogger("absg")

AGENT_BUILDER_PLATFORM = "Microsoft 365 Copilot Agent Builder"
GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
@dataclass
class Config:
    tenant_id: str
    client_id: str
    client_secret: str | None = None          # or use a certificate
    cert_path: str | None = None              # PEM with private key
    cert_thumbprint: str | None = None
    graph_base: str = "https://graph.microsoft.com/v1.0"
    # Authenticate as an Azure managed identity (client_id = the user-assigned
    # identity's client ID) instead of a client secret or certificate.
    use_managed_identity: bool = False
    poll_interval_seconds: int = 300
    state_file: str = "absg_state.json"
    # Append-only, hash-chained audit trail (JSON Lines).
    audit_file: str = "absg_audit.jsonl"
    # Also record "no action" evaluations for every agent scanned
    # (verbose; useful to prove an agent was checked at a point in time).
    audit_no_action: bool = False
    dry_run: bool = False
    # Package IDs or manifest IDs that are allowed to be shared
    # (approved exceptions, e.g. a pilot agent).
    exempt_ids: list[str] = field(default_factory=list)
    # Principal IDs to ignore when deciding whether an agent is shared
    # (e.g. a governance service account that is auto-added).
    ignore_principal_ids: list[str] = field(default_factory=list)
    # Treat availableTo == "all" as shared even when the share list is empty.
    treat_available_to_all_as_shared: bool = True
    # Circuit breaker: stop blocking after this many new blocks in one pass.
    # Protects against an API behaviour change causing a mass block.
    max_blocks_per_cycle: int = 25
    # Optional webhook (e.g. Teams Workflows / Logic App HTTP trigger).
    notify_webhook_url: str | None = None
    request_timeout_seconds: int = 30

    # --- Email (Graph sendMail, app permission Mail.Send) -----------------
    mail_sender: str | None = None            # e.g. shareguard@contoso.com
    admin_emails: list[str] = field(default_factory=list)
    policy_url: str | None = None
    helpdesk_contact: str | None = None
    welcome_emails_enabled: bool = True
    # On the first run, existing agent owners are recorded as "known"
    # without being emailed. Set true to welcome them too.
    welcome_backfill: bool = False
    welcome_max_attempts: int = 3

    # --- Owner lookup ------------------------------------------------------
    owner_fields: list[str] = field(default_factory=list)  # e.g. ["ownerId"]
    owner_map_file: str | None = None
    infer_owner_from_allowed_list: bool = True

    # --- Owner acknowledgement -------------------------------------------
    ack_enabled: bool = False
    ack_base_url: str | None = None           # public URL of the endpoint, e.g. https://guard.contoso.com/ack
    # Pre-filled Microsoft Forms link instead of the endpoint; "{token}" is replaced,
    # e.g. https://forms.office.com/r/AbC123?r1a2b3c4d={token}
    ack_form_url: str | None = None
    ack_secret: str | None = None             # HMAC key; set via ABSG_ACK_SECRET
    ack_token_ttl_hours: int = 168
    # Loopback by default; set "0.0.0.0" explicitly when running in a container
    # behind an authenticating proxy.
    ack_listen_host: str = "127.0.0.1"
    ack_listen_port: int = 8080
    ack_path: str = "/ack"
    ack_identity_header: str | None = "X-MS-CLIENT-PRINCIPAL-ID"
    ack_require_identity: bool = True
    ack_store_file: str = "absg_acks.json"
    ack_max_attempts: int = 3

    # --- Delegated identity used to remove sharing (PATCH is delegated-only)
    delegated_client_id: str | None = None    # public client app registration
    delegated_token_cache: str = "absg_delegated_cache.json"  # noqa: S105 - a file path, not a secret
    delegated_username: str | None = None     # service account UPN
    removal_available_to_value: str = "allowedForSome"

    # --- Approved-agent registry and drift detection --------------------
    registry_file: str | None = None          # signed whitelist maintained by governance
    registry_public_key_file: str | None = None  # Ed25519 public key; unsigned entries ignored
    require_registry_signatures: bool = True
    # Capability names that represent embedded (uploaded) knowledge files.
    embedded_capability_names: list[str] = field(default_factory=lambda: ["EmbeddedKnowledge"])
    # If an approved agent's definition can't be read, treat it as a violation.
    drift_fail_closed: bool = True

    # --- Azure deployment: SharePoint stores and Key Vault -----------------
    # "file" (local files, the default) or "sharepoint" (the Azure deployment).
    storage_backend: str = "file"
    sharepoint_operations_site_id: str | None = None   # hostname,siteCollectionId,webId
    sharepoint_registry_site_id: str | None = None
    sharepoint_state_library: str = "ABSG State"
    sharepoint_state_path: str = "state.json"
    sharepoint_owner_map_path: str | None = None       # e.g. "owner-map.json" in the state library
    sharepoint_audit_library: str = "ABSG Audit"
    sharepoint_audit_folder: str = ""
    audit_retention_label: str | None = None           # Purview label applied to closed days
    sharepoint_registry_list: str = "Approved Agents"
    sharepoint_requests_list: str = "Agent Sharing Requests"
    sharepoint_acks_list: str = "Agent Acknowledgements"
    key_vault_url: str | None = None                   # https://kv-absg-prod.vault.azure.net
    ack_secret_name: str = "ack-token-hmac-key"  # noqa: S105 - a secret's name, not a secret
    delegated_cache_secret_name: str = "delegated-token-cache"  # noqa: S105
    registry_key_name: str = "registry-signing-key"
    # The registry public key inline (PEM or JWK), e.g. from an app setting.
    registry_public_key: str | None = None
    # Also write every audit record to the log (Application Insights).
    audit_to_log: bool = False
    # Registry signer (its own Function app): its audit chain lives in this library
    # on the registry site, and approvals may last at most this many days.
    signer_audit_library: str = "ABSG Signer Audit"
    max_approval_days: int = 365
    # The sharing criteria reviewers score, each {"column", "id", "description"}; each
    # column is a Pass / Fail / N/A choice column in the requests list. None = the
    # defaults in absg.signer.CRITERIA (KS01, KS02, DS01, AU01, AC01).
    approval_criteria: list[dict] | None = None
    # Who may change a sharing request after it's submitted: the approval flow's account
    # and the reviewers (Entra object ids or UPNs; app ids for applications). When set,
    # the signer refuses a request whose version history shows an edit by anyone else,
    # for example the requester changing Status, ApprovedBy or the criteria themselves.
    signer_trusted_editors: list[str] = field(default_factory=list)

    # --- Ownership and lifecycle ------------------------------------------
    # Check owners' Entra accounts (deleted or disabled = inactive). Needs User.Read.All.
    owner_status_checks: bool = True
    # What to do when none of an agent's owners has an active account:
    # "report" (audit + admin alert), "reassign_to_manager" (reassign to a disabled
    # owner's manager), or "block".
    ownerless_action: str = "report"
    # An agent not used for this many days is inactive and is retired (blocked).
    # None = lifecycle retirement off.
    inactivity_days: int | None = None
    # Owners are told this many days before the agent becomes inactive that it's bound
    # for retirement. Retirement is never sooner than this after the notice.
    inactivity_notice_days: int = 30
    # A reminder this many days before the retirement date (0 = no reminder).
    inactivity_reminder_days: int = 7
    # Apply inactivity retirement to agents approved in the registry too.
    inactivity_applies_to_approved: bool = True
    # Days a retired agent stays blocked (owners can still reactivate it) before it is
    # archived. None = never archive (it stays blocked).
    archive_after_days: int | None = 30
    # Where archives go: a local folder (storage_backend "file"), or a document library
    # on a restricted SharePoint site (storage_backend "sharepoint"; defaults to the
    # operations site if no archive site is set).
    archive_dir: str = "absg_archive"
    sharepoint_archive_site_id: str | None = None
    sharepoint_archive_library: str = "Retired Agents"
    archive_retention_label: str | None = None
    # Tell the owners when their agent is archived.
    archive_notify_owners: bool = True
    # After archiving: "manual" (admins delete it in the Microsoft 365 admin centre; the
    # guard asks, reminds and verifies), "api" (experimental: an undocumented DELETE
    # call, verified; falls back to manual), or "none" (archive only, stays blocked).
    deletion_mode: str = "manual"
    deletion_reminder_days: int = 7
    deletion_api_path: str = "/copilot/admin/catalog/packages/{id}"

    # --- Email ----------------------------------------------------------------
    # Name shown in emails, an optional subject prefix (for example "[IT]"), footer text
    # that replaces "Need help? Contact ...", and the button colour.
    email_brand_name: str = "ShareGuard for Agent Builder"
    email_subject_prefix: str = ""
    email_footer: str | None = None
    email_button_colour: str = "#0f6cbd"
    # Customised templates: a local folder, or a folder in the state library on the
    # operations site (storage_backend "sharepoint"). See absg.mail.
    email_templates_dir: str | None = None
    sharepoint_templates_folder: str | None = None

    @classmethod
    def load(cls, path: str | None) -> Config:
        data: dict[str, Any] = {}
        if path:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        elif os.environ.get("ABSG_CONFIG_JSON"):
            # Azure Functions: the (non-secret) configuration as one app setting.
            data = json.loads(os.environ["ABSG_CONFIG_JSON"])
        # Environment variables override file values (keeps secrets out of files).
        env_map = {
            "tenant_id": "ABSG_TENANT_ID",
            "client_id": "ABSG_CLIENT_ID",
            "client_secret": "ABSG_CLIENT_SECRET",
            "cert_path": "ABSG_CERT_PATH",
            "cert_thumbprint": "ABSG_CERT_THUMBPRINT",
            "notify_webhook_url": "ABSG_NOTIFY_WEBHOOK_URL",
            "state_file": "ABSG_STATE_FILE",
            "audit_file": "ABSG_AUDIT_FILE",
            "ack_secret": "ABSG_ACK_SECRET",
            "mail_sender": "ABSG_MAIL_SENDER",
            "registry_public_key": "ABSG_REGISTRY_PUBLIC_KEY",
        }
        for key, env in env_map.items():
            if os.environ.get(env):
                data[key] = os.environ[env]
        for flag, env in (("dry_run", "ABSG_DRY_RUN"), ("use_managed_identity", "ABSG_USE_MANAGED_IDENTITY")):
            if os.environ.get(env, "").lower() in ("1", "true", "yes"):
                data[flag] = True
        missing = [k for k in ("tenant_id", "client_id") if not data.get(k)]
        if missing:
            raise ValueError(f"Missing required config: {', '.join(missing)}")
        if not data.get("client_secret") and not data.get("cert_path") \
                and not data.get("use_managed_identity"):
            raise ValueError("Provide client_secret, cert_path/cert_thumbprint, or use_managed_identity")
        if "inactivity_warning_days" in data and "inactivity_notice_days" not in data:
            data["inactivity_notice_days"] = data.pop("inactivity_warning_days")   # older name
        known = cls.__dataclass_fields__.keys()
        cfg = cls(**{k: v for k, v in data.items() if k in known})
        if cfg.ack_enabled:
            if not (cfg.ack_base_url or cfg.ack_form_url) or not (cfg.ack_secret or cfg.key_vault_url):
                raise ValueError("ack_enabled needs ack_base_url or ack_form_url, and ack_secret (ABSG_ACK_SECRET)")
            if not cfg.mail_sender:
                raise ValueError("ack_enabled needs mail_sender: the link is delivered by email")
        if cfg.ownerless_action not in ("report", "reassign_to_manager", "block"):
            raise ValueError("ownerless_action must be report, reassign_to_manager or block")
        if cfg.inactivity_days is not None and cfg.inactivity_days <= cfg.inactivity_notice_days:
            raise ValueError("inactivity_days must be greater than inactivity_notice_days")
        if not 0 <= cfg.inactivity_reminder_days < max(cfg.inactivity_notice_days, 1):
            raise ValueError("inactivity_reminder_days must be 0 or less than inactivity_notice_days")
        if cfg.archive_after_days is not None and cfg.archive_after_days < 0:
            raise ValueError("archive_after_days must be 0 or more (or null to never archive)")
        if cfg.deletion_mode not in ("manual", "api", "none"):
            raise ValueError("deletion_mode must be manual, api or none")
        for c in cfg.approval_criteria or []:
            if not isinstance(c, dict) or not str(c.get("column", "")).isalnum():
                raise ValueError("each approval_criteria item needs a letters-and-digits 'column'")
        if "{id}" not in cfg.deletion_api_path:
            raise ValueError("deletion_api_path must contain {id}")
        if cfg.storage_backend not in ("file", "sharepoint"):
            raise ValueError("storage_backend must be file or sharepoint")
        if cfg.storage_backend == "sharepoint" and not cfg.sharepoint_operations_site_id:
            raise ValueError("storage_backend sharepoint needs sharepoint_operations_site_id")
        has_registry = cfg.registry_file or (cfg.storage_backend == "sharepoint"
                                             and cfg.sharepoint_registry_site_id)
        has_key = cfg.registry_public_key_file or cfg.registry_public_key or cfg.key_vault_url
        if has_registry and cfg.require_registry_signatures and not has_key:
            raise ValueError("the registry needs a public key: registry_public_key_file, "
                             "registry_public_key or key_vault_url (or set require_registry_signatures "
                             "to false; not recommended)")
        return cfg


# --------------------------------------------------------------------------
# Graph client
# --------------------------------------------------------------------------
class GraphError(RuntimeError):
    def __init__(self, status: int, body: str):
        super().__init__(f"Graph error {status}: {body[:500]}")
        self.status = status


class GraphClient:
    """Minimal Graph client: app-only auth, retries, paging."""

    def __init__(self, cfg: Config, session: requests.Session | None = None,
                 token_provider: Callable[[], str] | None = None):
        self.cfg = cfg
        self.session = session or requests.Session()
        self._token_provider = token_provider or self._build_msal_provider()

    def _build_msal_provider(self) -> Callable[[], str]:
        if self.cfg.use_managed_identity:
            from .cloud import GRAPH_RESOURCE, managed_identity_provider
            return managed_identity_provider(GRAPH_RESOURCE, self.cfg.client_id or None)
        import msal  # imported lazily so tests don't need it

        if self.cfg.cert_path:
            with open(self.cfg.cert_path, encoding="utf-8") as fh:
                credential: Any = {
                    "private_key": fh.read(),
                    "thumbprint": self.cfg.cert_thumbprint,
                }
        else:
            credential = self.cfg.client_secret
        app = msal.ConfidentialClientApplication(
            client_id=self.cfg.client_id,
            client_credential=credential,
            authority=f"https://login.microsoftonline.com/{self.cfg.tenant_id}",
        )

        def provider() -> str:
            result = app.acquire_token_for_client(scopes=GRAPH_SCOPE)  # cached by MSAL
            if "access_token" not in result:
                raise RuntimeError(f"Token acquisition failed: {result.get('error_description')}")
            return result["access_token"]

        return provider

    def request(self, method: str, url: str, headers: dict | None = None,
                **kwargs: Any) -> requests.Response:
        if not url.startswith("http"):
            url = self.cfg.graph_base.rstrip("/") + url
        for attempt in range(6):
            merged = {"Authorization": f"Bearer {self._token_provider()}",
                      "Accept": "application/json", **(headers or {})}
            resp = self.session.request(method, url, headers=merged,
                                        timeout=self.cfg.request_timeout_seconds, **kwargs)
            if resp.status_code in (429, 500, 502, 503, 504):
                retry_after = resp.headers.get("Retry-After")
                delay = float(retry_after) if retry_after and retry_after.isdigit() else 2 ** attempt
                log.warning("Graph %s on %s %s; retrying in %.0fs", resp.status_code, method, url, delay)
                time.sleep(min(delay, 120))
                continue
            if resp.status_code >= 400:
                raise GraphError(resp.status_code, resp.text)
            return resp
        raise GraphError(resp.status_code, resp.text)

    def get_paged(self, url: str) -> Iterator[dict]:
        next_url: str | None = url
        while next_url:
            data = self.request("GET", next_url).json()
            yield from data.get("value", [])
            next_url = data.get("@odata.nextLink")  # use verbatim, per Graph guidance

    # Package Management API -------------------------------------------------
    def list_agent_builder_packages(self) -> Iterator[dict]:
        flt = f"platform eq '{AGENT_BUILDER_PLATFORM}'"
        return self.get_paged(f"/copilot/admin/catalog/packages?$filter={requests.utils.quote(flt)}")

    def get_package(self, package_id: str) -> dict:
        return self.request("GET", f"/copilot/admin/catalog/packages/{package_id}").json()

    def block(self, package_id: str) -> None:
        self.request("POST", f"/copilot/admin/catalog/packages/{package_id}/block")

    def unblock(self, package_id: str) -> None:
        self.request("POST", f"/copilot/admin/catalog/packages/{package_id}/unblock")

    def reassign(self, package_id: str, user_id: str) -> None:
        self.request("POST", f"/copilot/admin/catalog/packages/{package_id}/reassign",
                     json={"userId": user_id})

    def user_status(self, user_id: str) -> str:
        """"active", "disabled", "deleted", or "unknown" (lookup failed for another reason)."""
        try:
            user = self.request("GET", f"/users/{user_id}?$select=id,accountEnabled").json()
        except GraphError as exc:
            return "deleted" if exc.status == 404 else "unknown"
        return "disabled" if user.get("accountEnabled") is False else "active"

    def manager_of(self, user_id: str) -> str | None:
        try:
            return self.request("GET", f"/users/{user_id}/manager?$select=id").json().get("id")
        except GraphError:
            return None

    def update_package(self, package_id: str, body: dict) -> None:
        # Delegated permission only (CopilotPackages.ReadWrite.All); call this on
        # a GraphClient built with a delegated token provider.
        self.request("PATCH", f"/copilot/admin/catalog/packages/{package_id}", json=body)


# --------------------------------------------------------------------------
# State store: records which packages *this daemon* blocked
# --------------------------------------------------------------------------
class FileJsonDocument:
    """A JSON document in a local file, replaced atomically on save."""

    def __init__(self, path: str):
        self.path = path

    def load(self) -> dict | None:
        if not os.path.exists(self.path):
            return None
        with open(self.path, encoding="utf-8") as fh:
            return json.load(fh)

    def save(self, data: dict) -> None:
        directory = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".state-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
        os.replace(tmp, self.path)  # atomic


class StateStore:
    def __init__(self, path: str | None = None, backend: Any = None):
        self.path = path
        self.backend = backend or FileJsonDocument(path or "absg_state.json")
        self.data: dict[str, dict] = {}
        # ownerId -> {"firstAgentId", "welcomedAt" | "baselinedAt", ...}
        self.known_owners: dict[str, dict] = {}
        # packageId -> ownerId (learned while the agent was unshared)
        self.package_owners: dict[str, str] = {}
        # ownerId -> failed welcome attempts
        self.welcome_failures: dict[str, int] = {}
        self.baseline_done = False
        # packageId -> fingerprint of the last registry validation result
        self.validations: dict[str, str] = {}
        # packageId -> hash of the registry entry last seen (to audit changes)
        self.registry_hashes: dict[str, str] = {}
        self.registry_invalid: dict[str, str] = {}
        # packageId -> signedAt of the newest registry entry seen (rejects rollbacks).
        # Never pruned: an old entry must stay rejected even after a long absence.
        self.registry_newest: dict[str, str] = {}
        # packageId -> lifecycle record (inactivity warnings, reactivation, ownerless reports)
        self.lifecycle: dict[str, dict] = {}
        # Last registry copy that loaded ({"agents": [...], "hash": ...}): entries are
        # re-verified on use, so a cold start can fall back on it when the source fails.
        self.registry_snapshot: dict | None = None
        # Audit records a remote backend couldn't write; written first next time.
        self.pending_audit: list[dict] = []
        raw = self.backend.load()
        if raw is not None:
            self.data = raw.get("blocked_by_guard", {})
            self.known_owners = raw.get("known_owners", {})
            self.package_owners = raw.get("package_owners", {})
            self.welcome_failures = raw.get("welcome_failures", {})
            self.baseline_done = raw.get("baseline_done", False)
            self.validations = raw.get("validations", {})
            self.registry_hashes = raw.get("registry_hashes", {})
            self.registry_invalid = raw.get("registry_invalid", {})
            self.registry_newest = raw.get("registry_newest", {})
            self.lifecycle = raw.get("lifecycle", {})
            self.registry_snapshot = raw.get("registry_snapshot")
            self.pending_audit = raw.get("pending_audit", [])

    def is_ours(self, package_id: str) -> bool:
        return package_id in self.data

    def record_block(self, package_id: str, info: dict) -> None:
        self.data[package_id] = info

    def forget(self, package_id: str) -> None:
        self.data.pop(package_id, None)

    def ids(self) -> set[str]:
        return set(self.data)

    def save(self) -> None:
        self.backend.save({"blocked_by_guard": self.data,
                       "known_owners": self.known_owners,
                       "package_owners": self.package_owners,
                       "welcome_failures": self.welcome_failures,
                       "baseline_done": self.baseline_done,
                       "validations": self.validations,
                       "registry_hashes": self.registry_hashes,
                       "registry_invalid": self.registry_invalid,
                       "registry_newest": self.registry_newest,
                       "lifecycle": self.lifecycle,
                       "registry_snapshot": self.registry_snapshot,
                       "pending_audit": self.pending_audit})


# --------------------------------------------------------------------------
# Audit trail
# --------------------------------------------------------------------------
GENESIS_HASH = "0" * 64


def _canonical(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str).encode()


def _record_hash(record: dict) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(_canonical(body)).hexdigest()


class AuditLog:
    """Append-only, hash-chained audit trail in JSON Lines format.

    Every record carries ``seq``, ``prevHash`` and ``hash`` (SHA-256 over the
    canonical JSON of the record minus ``hash``). Editing, deleting or
    reordering any line breaks the chain, which ``verify_audit_log`` detects.

    Each record answers who / what / when / why / outcome:
      actor      - app (client) ID, host and process that acted
      event      - block | unblock | reblock | exempt_skip | state_forget |
                   circuit_breaker | error | no_action | cycle_start | cycle_end
      package    - id, displayName, manifestId
      before / after - isBlocked and shared state around the action
      reason     - policy rule that triggered the action
      recipients - who the agent was shared with (evidence)
      outcome    - success | failed | simulated (dry run)

    For long-term retention, ship the file to a SIEM / Log Analytics (e.g. the
    Azure Monitor Agent custom-text-log collector) or immutable blob storage.
    The hash chain lets you prove the shipped copy matches the original.
    """

    def __init__(self, path: str | None = None, actor: dict | None = None,
                 sink: Callable[[dict], None] | None = None, backend: Any = None):
        self.path = path
        self.backend = backend or FileAuditBackend(path or "absg_audit.jsonl")
        self.actor = actor or {}
        self.sink = sink
        self._lock = threading.Lock()
        self._seq, self._last_hash = self.backend.resume()

    def record(self, event: str, **fields: Any) -> dict:
        with self._lock:
            rec = {
                "seq": self._seq + 1,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": event,
                "actor": self.actor,
                **{k: v for k, v in fields.items() if v is not None},
                "prevHash": self._last_hash,
            }
            # Round-trip so the hashed form is exactly what is written and re-read.
            rec = json.loads(json.dumps(rec, default=str))
            rec["hash"] = _record_hash(rec)
            self.backend.append(rec)
            self._seq, self._last_hash = rec["seq"], rec["hash"]
        if self.sink:
            try:
                self.sink(rec)
            except Exception as exc:  # a sink failure must not stop enforcement
                log.error("Audit sink failed: %s", exc)
        return rec

    def flush(self) -> None:
        """Write buffered records (remote backends); a no-op for the local file."""
        with self._lock:
            self.backend.flush()

    def unflushed(self) -> list[dict]:
        """Records the backend still holds unwritten (remote backends only)."""
        with self._lock:
            return [dict(r) for r in getattr(self.backend, "buffer", [])]


class FileAuditBackend:
    """JSON Lines file; every record is fsynced as it's written."""

    def __init__(self, path: str):
        self.path = path

    def resume(self) -> tuple[int, str]:
        if not os.path.exists(self.path):
            return 0, GENESIS_HASH
        last = None
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        if last is None:
            return 0, GENESIS_HASH
        rec = json.loads(last)
        return int(rec["seq"]), rec["hash"]

    def append(self, rec: dict) -> None:
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True, default=str) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def flush(self) -> None:
        return None

    def iter_lines(self) -> Iterator[str]:
        with open(self.path, encoding="utf-8") as fh:
            yield from fh


@dataclass
class AuditVerification:
    ok: bool
    records: int
    first_bad_seq: int | None = None
    problem: str | None = None


def verify_audit_log(path: str) -> AuditVerification:
    """Recompute the hash chain of an audit file and report the first break, if any."""
    with open(path, encoding="utf-8") as fh:
        return verify_audit_lines(fh)


def verify_audit_lines(lines: Iterable[str]) -> AuditVerification:
    """Recompute the hash chain over audit lines (one file, or several days in order)."""
    prev, expected_seq, count = GENESIS_HASH, 1, 0
    for lineno, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return AuditVerification(False, count, expected_seq, f"line {lineno}: not valid JSON")
        seq = rec.get("seq")
        if seq != expected_seq:
            return AuditVerification(False, count, expected_seq,
                                     f"line {lineno}: expected seq {expected_seq}, found {seq} "
                                     "(record missing or reordered)")
        if rec.get("prevHash") != prev:
            return AuditVerification(False, count, seq, f"seq {seq}: prevHash does not match")
        if _record_hash(rec) != rec.get("hash"):
            return AuditVerification(False, count, seq, f"seq {seq}: content altered (hash mismatch)")
        prev, expected_seq, count = rec["hash"], expected_seq + 1, count + 1
    return AuditVerification(True, count)


def audit_history(path: str, package_id: str | None = None,
                  event: str | None = None, since: str | None = None,
                  case_id: str | None = None) -> list[dict]:
    """Return audit records filtered by package, event type and ISO start time."""
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            rec = json.loads(line)
            if package_id and rec.get("package", {}).get("id") != package_id:
                continue
            if event and rec.get("event") != event:
                continue
            if case_id and rec.get("caseId") != case_id:
                continue
            if since and rec.get("timestamp", "") < since:
                continue
            out.append(rec)
    return out


# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------
def sharing_recipients(detail: dict, cfg: Config) -> list[dict]:
    """Return the principals (other than ignored ones) the agent is shared with."""
    ignored = set(cfg.ignore_principal_ids)
    recipients = [
        e for e in (detail.get("sharedWithUsersAndGroups") or [])
        if e.get("resourceId") not in ignored
    ]
    if not recipients and cfg.treat_available_to_all_as_shared \
            and str(detail.get("availableTo", "")).lower() == "all":
        recipients = [{"resourceType": "tenant", "resourceId": "all"}]
    return recipients


def is_exempt(detail: dict, cfg: Config) -> bool:
    exempt = set(cfg.exempt_ids)
    return detail.get("id") in exempt or detail.get("manifestId") in exempt


# --------------------------------------------------------------------------
# Reconciler
# --------------------------------------------------------------------------
@dataclass
class CycleResult:
    scanned: int = 0
    blocked: list[str] = field(default_factory=list)
    unblocked: list[str] = field(default_factory=list)
    reblocked: list[str] = field(default_factory=list)
    skipped_exempt: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    circuit_breaker_tripped: bool = False
    welcomed: list[str] = field(default_factory=list)
    removed_on_behalf: list[str] = field(default_factory=list)
    approved_compliant: list[str] = field(default_factory=list)
    drift_blocked: list[str] = field(default_factory=list)
    retired: list[str] = field(default_factory=list)
    reactivated: list[str] = field(default_factory=list)
    inactivity_warned: list[str] = field(default_factory=list)
    archived: list[str] = field(default_factory=list)
    deletion_requested: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    ownerless: list[str] = field(default_factory=list)
    reassigned: list[str] = field(default_factory=list)


class Guard:
    """Applies the no-sharing policy, runs the owner email flows and handles
    owner acknowledgements.

    Case model: every block (or re-block) opens a *case* (``caseId``). The
    notice email, the acknowledgement link, the acknowledgement itself,
    the sharing removal and the unblock all carry the same ``caseId`` in
    the audit trail, so one query rebuilds the whole story.
    """

    def __init__(self, cfg: Config, graph: GraphClient, state: StateStore,
                 notifier: Callable[[str, dict], None] | None = None,
                 audit: AuditLog | None = None,
                 mailer: Any = None,
                 owner_resolver: Any = None,
                 signer: Any = None,
                 acks: Any = None,
                 delegated_graph: GraphClient | None = None,
                 registry: Any = None,
                 archive: Any = None):
        self.cfg = cfg
        self.graph = graph
        self.state = state
        self.notify = notifier or (lambda event, payload: None)
        self.audit = audit
        self.mailer = mailer
        self.owners = owner_resolver
        self.signer = signer
        self.acks = acks
        self.delegated = delegated_graph
        self.registry = registry
        if archive is None and self._archiving:
            from .archive import FileArchiveStore
            archive = FileArchiveStore(cfg.archive_dir)
        self.archive = archive
        self._registry_file_hash: str | None = None
        self._cycle_id: str | None = None
        self._baselined = 0
        self._status_cache: dict[str, str] = {}
        # packageId -> new case ID, for a reactivated agent kept blocked because it's shared
        self._held: dict[str, str] = {}

    # -- audit helper -------------------------------------------------------
    def _audit(self, event: str, d: dict | None = None, **fields: Any) -> None:
        if not self.audit:
            return
        package = None
        if d is not None:
            package = {"id": d.get("id"), "displayName": d.get("displayName"),
                       "manifestId": d.get("manifestId")}
        self.audit.record(event, cycleId=self._cycle_id, dryRun=self.cfg.dry_run,
                          package=package, **fields)

    def _audit_ack(self, event: str, package_id: str | None = None, **fields: Any) -> None:
        self._audit(event, {"id": package_id} if package_id else None, **fields)

    @staticmethod
    def _snapshot(blocked: bool, recipients: list[dict]) -> dict:
        return {"isBlocked": blocked, "shared": bool(recipients),
                "recipientCount": len(recipients)}

    @property
    def _archiving(self) -> bool:
        return bool(self.cfg.inactivity_days) and self.cfg.archive_after_days is not None

    @property
    def _mail_on(self) -> bool:
        return bool(self.mailer and self.mailer.enabled)

    # -- cycle --------------------------------------------------------------
    def run_cycle(self) -> CycleResult:
        result = CycleResult()
        seen: set[str] = set()
        new_blocks = 0
        self._baselined = 0
        self._status_cache = {}
        self._cycle_id = uuid.uuid4().hex
        try:
            return self._run_cycle(result, seen, new_blocks)
        finally:
            # Always runs, even when the cycle aborts part-way: blocks already issued must
            # stay recorded as ours, or they'd look like admin blocks and never be released.
            if self.audit:
                try:
                    self.audit.flush()
                except Exception:
                    log.exception("Audit flush failed; unwritten records are kept in the state")
                self.state.pending_audit = self.audit.unflushed()
            # Raise a save failure (e.g. a second writer) unless another error is already on its way out.
            self._save_state(raise_errors=sys.exc_info()[0] is None)

    def _save_state(self, raise_errors: bool = False) -> None:
        if self.cfg.dry_run:
            return
        try:
            self.state.save()
        except Exception:
            if raise_errors:
                raise
            log.exception("State save failed")

    def _run_cycle(self, result: CycleResult, seen: set[str], new_blocks: int) -> CycleResult:
        self._sync_registry()
        if self.acks is not None and hasattr(self.acks, "refresh"):
            try:
                self.acks.refresh(self._audit_ack)
            except Exception as exc:
                self._audit("error", stage="ack_refresh", error=str(exc))
        self._audit("cycle_start", registryFileHash=self._registry_file_hash,
                    approvedAgents=len(self.registry.entries) if self.registry else 0, policy={
            "maxBlocksPerCycle": self.cfg.max_blocks_per_cycle,
            "exemptIds": self.cfg.exempt_ids,
            "ignorePrincipalIds": self.cfg.ignore_principal_ids,
            "treatAvailableToAllAsShared": self.cfg.treat_available_to_all_as_shared,
        })

        try:
            for summary in self.graph.list_agent_builder_packages():
                pid = summary["id"]
                seen.add(pid)
                result.scanned += 1
                try:
                    detail = self.graph.get_package(pid)
                    new_blocks += self._reconcile(detail, result, new_blocks)
                except Exception as exc:   # one bad package must not abort the cycle
                    log.error("Failed on package %s: %s", pid, exc,
                              exc_info=not isinstance(exc, GraphError))
                    result.errors.append(pid)
                    self._audit("error", summary, stage="evaluate", error=str(exc))
        except GraphError as exc:
            # Listing failed: skip state pruning, since "unseen" means nothing.
            self._audit("error", stage="list", error=str(exc))
            self._audit("cycle_end", summary=self._summary(result), completed=False)
            raise

        # Packages we blocked that no longer exist (deleted by owner/admin).
        for pid in self.state.ids() - seen:
            log.info("Package %s no longer in catalog; forgetting", pid)
            entry = self.state.data.get(pid, {})
            if entry.get("archivedAt"):
                self._record_deleted(pid, entry, result)
            else:
                self._audit("state_forget", {"id": pid, **entry}, caseId=entry.get("caseId"),
                            reason="package no longer in catalog", outcome="success")
            self.state.forget(pid)
        for pid in set(self.state.package_owners) - seen:
            self.state.package_owners.pop(pid, None)
        for pid in set(self.state.validations) - seen:
            self.state.validations.pop(pid, None)
        for pid in set(self.state.lifecycle) - seen:
            self.state.lifecycle.pop(pid, None)
        if self.acks:
            for ack in self.acks.pending():
                if ack["packageId"] not in seen:
                    self._audit("ack_closed", {"id": ack["packageId"]}, caseId=ack["caseId"],
                                reason="package no longer in catalog")
                    self.acks.close(ack["caseId"])

        if not self.state.baseline_done:
            self.state.baseline_done = True
            self._audit("welcome_baseline", ownersBaselined=self._baselined,
                        reason="first run: existing owners recorded without a welcome email")

        log.info("Cycle done: scanned=%d blocked=%d unblocked=%d reblocked=%d errors=%d",
                 result.scanned, len(result.blocked), len(result.unblocked),
                 len(result.reblocked), len(result.errors))
        self._audit("cycle_end", summary=self._summary(result), completed=True)
        return result

    @staticmethod
    def _summary(r: CycleResult) -> dict:
        return {"scanned": r.scanned, "blocked": r.blocked, "unblocked": r.unblocked,
                "reblocked": r.reblocked, "skippedExempt": r.skipped_exempt,
                "errors": r.errors, "circuitBreakerTripped": r.circuit_breaker_tripped,
                "welcomed": r.welcomed, "removedOnBehalf": r.removed_on_behalf,
                "approvedCompliant": r.approved_compliant, "driftBlocked": r.drift_blocked,
                "retired": r.retired, "reactivated": r.reactivated,
                "inactivityWarned": r.inactivity_warned, "ownerless": r.ownerless,
                "archived": r.archived, "deletionRequested": r.deletion_requested, "deleted": r.deleted,
                "reassigned": r.reassigned}

    # -- owner + welcome ----------------------------------------------------
    def _owners(self, d: dict, shared: bool) -> tuple[list[str], str | None]:
        """All known owners of the agent (primary first) and the primary's source."""
        if not self.owners:
            return [], None
        if hasattr(self.owners, "resolve_all"):
            owners, source = self.owners.resolve_all(d, shared)
        else:
            owner, source = self.owners.resolve(d, shared)
            owners = [owner] if owner else []
        if owners and self.state.package_owners.get(d["id"]) != owners[0]:
            self.state.package_owners[d["id"]] = owners[0]
            self._audit("owner_resolved", d, ownerId=owners[0], ownerIds=owners, source=source)
        return owners, source

    def _owner(self, d: dict, shared: bool) -> tuple[str | None, str | None]:
        owners, source = self._owners(d, shared)
        return (owners[0] if owners else None), source

    def _status(self, user_id: str) -> str:
        if user_id not in self._status_cache:
            fn = getattr(self.graph, "user_status", None)
            self._status_cache[user_id] = fn(user_id) if fn else "unknown"
        return self._status_cache[user_id]

    def _inactive(self, owners: list[str]) -> list[str]:
        if not self.cfg.owner_status_checks:
            return []
        return [o for o in owners if self._status(o) in ("disabled", "deleted")]

    def _maybe_welcome(self, d: dict, owner: str | None, result: CycleResult) -> None:
        if not owner or owner in self.state.known_owners:
            return
        if self.state.baseline_done and self._inactive([owner]):
            return          # no welcome for an account that is deleted or disabled
        now = datetime.now(timezone.utc).isoformat()
        if not self.state.baseline_done and not self.cfg.welcome_backfill:
            self.state.known_owners[owner] = {"firstAgentId": d["id"], "baselinedAt": now}
            self._baselined += 1
            return
        if not (self.cfg.welcome_emails_enabled and self._mail_on):
            self.state.known_owners[owner] = {"firstAgentId": d["id"], "firstSeenAt": now,
                                              "welcomed": False}
            return
        try:
            user = self.mailer.get_user(owner)
            meta = self.mailer.send_welcome(user, d)
        except Exception as exc:
            fails = self.state.welcome_failures.get(owner, 0) + 1
            self.state.welcome_failures[owner] = fails
            give_up = fails >= self.cfg.welcome_max_attempts
            self._audit("email_failed", d, template="welcome", ownerId=owner, attempt=fails,
                        gaveUp=give_up, error=str(exc), outcome="failed")
            if give_up:
                self.state.known_owners[owner] = {"firstAgentId": d["id"], "firstSeenAt": now,
                                                  "welcomed": False}
            return
        self.state.welcome_failures.pop(owner, None)
        self.state.known_owners[owner] = {"firstAgentId": d["id"], "welcomedAt": now}
        result.welcomed.append(owner)
        self._audit("welcome_email_sent", d, ownerId=owner, email=meta,
                    outcome="simulated" if meta.get("simulated") else "success")

    # -- policy -------------------------------------------------------------
    def _reconcile(self, d: dict, result: CycleResult, new_blocks: int) -> int:
        """Apply policy to one package. Returns 1 if a new block was issued."""
        pid = d["id"]
        blocked = bool(d.get("isBlocked"))
        ours = self.state.is_ours(pid)
        recipients = sharing_recipients(d, self.cfg)
        shared = bool(recipients)
        before = self._snapshot(blocked, recipients)

        owners, owner_source = self._owners(d, shared)
        for o in owners:
            self._maybe_welcome(d, o, result)

        if shared and is_exempt(d, self.cfg):
            result.skipped_exempt.append(pid)
            self._audit("exempt_skip", d, before=before, recipients=recipients,
                        reason="package is on the exemption list")
            if blocked and ours:  # exemption granted after we blocked it
                self._unblock(d, result, recipients, reason="exemption granted")
            return 0

        lifecycle_block = self.state.data.get(pid, {}).get("blockType") if ours else None
        if blocked and lifecycle_block in ("retired", "ownerless"):
            held = self._reconcile_lifecycle_block(d, lifecycle_block, owners, recipients, result)
            if held is None:
                return 0
            # The lifecycle reason is gone, but the agent is shared: the normal policy
            # decides now (an approved, compliant agent is unblocked; otherwise it stays
            # blocked and the owners get the notice for the new case).
            issued = self._reconcile_sharing(d, result, new_blocks, recipients, before, blocked, ours,
                                             owners, owner_source)
            self._notify_if_still_held(d, held, owners, recipients)
            return issued

        return self._reconcile_sharing(d, result, new_blocks, recipients, before, blocked, ours,
                                       owners, owner_source)

    def _reconcile_sharing(self, d: dict, result: CycleResult, new_blocks: int, recipients: list[dict],
                           before: dict, blocked: bool, ours: bool, owners: list[str],
                           owner_source: str | None) -> int:
        pid = d["id"]
        shared = bool(recipients)
        owner = owners[0] if owners else None
        if shared and self.registry is not None and not self.registry.loaded:
            # Without any copy of the registry, approved agents can't be told apart from
            # unapproved ones: blocking them all would be a mass block. Decide next cycle.
            self._audit("decision_deferred", d, before=before, recipients=recipients,
                        reason="registry unavailable and no earlier copy exists", outcome="deferred")
            return 0

        approval = self.registry.lookup(d) if (self.registry and shared) else None
        if shared and approval is not None and approval.valid:
            return self._reconcile_approved(d, approval, recipients, owners, owner_source,
                                            before, blocked, ours, result, new_blocks)

        if shared and not blocked:
            if ours:
                reason = "still shared after a manual unblock"
            elif approval is not None:
                reason = f"shared, but the registry approval isn't valid: {approval.reason}"
            else:
                reason = "shared with other users or groups"
            return self._block(d, result, recipients, owner, owner_source, before, new_blocks,
                               block_type="sharing", reason=reason,
                               approval_status=approval.reason if approval else None,
                               owners=owners)

        if shared and blocked and ours:
            self._process_acks(d, recipients, result)
            return 0

        if not shared and blocked and ours:
            case_id = self.state.data.get(pid, {}).get("caseId")
            self._unblock(d, result, recipients, reason="sharing removed", case_id=case_id)
            self._close_acks(d, reason="sharing was removed before the acknowledgement was processed")
            return 0

        if not blocked and ours and not shared:
            # Someone unblocked it manually and it is no longer shared.
            entry = self.state.data.get(pid, {})
            self._audit("state_forget", d, before=before, caseId=entry.get("caseId"),
                        reason="unblocked outside the guard and no longer shared",
                        outcome="success")
            self.state.forget(pid)
            self._close_acks(d, reason="agent unblocked outside the guard")
            return 0

        if not shared and not blocked:
            issued = self._lifecycle(d, owners, recipients, before, result, new_blocks)
            if issued is not None:
                return issued

        # shared & blocked & not ours: admin block, leave alone.
        # not shared & blocked & not ours: admin block, leave alone.
        if self.cfg.audit_no_action:
            why = ("compliant: not shared" if not shared and not blocked
                   else "blocked by admin; not managed by guard")
            self._audit("no_action", d, before=before, reason=why)
        return 0

    # -- approved (registry) agents -----------------------------------------
    def _reconcile_approved(self, d: dict, approval: Any, recipients: list[dict],
                            owners: list[str], owner_source: str | None, before: dict,
                            blocked: bool, ours: bool, result: CycleResult,
                            new_blocks: int) -> int:
        from .registry import entry_owners, evaluate

        pid = d["id"]
        named = entry_owners(approval.entry)
        # Notices go to every named owner as well as the owners we know of.
        owners = list(dict.fromkeys(owners + named))
        owner = owners[0] if owners else None
        ownership = None
        if self.owners is not None or named:
            reported = self.owners.reported(d) if hasattr(self.owners, "reported") else None
            ownership = {"reported": reported, "inactive": self._inactive(named)}
        ev = evaluate(d, approval.entry, recipients, self.cfg.embedded_capability_names,
                      self.cfg.drift_fail_closed, ownership=ownership)
        self._record_validation(d, approval.entry, ev)
        state_entry = self.state.data.get(pid, {})

        if ev.compliant:
            result.approved_compliant.append(pid)
            if blocked and ours:
                reason = ("configuration drift rectified: matches the approved configuration"
                          if state_entry.get("blockType") == "drift"
                          else "agent approved in the registry")
                self._unblock(d, result, recipients, reason=reason)
                self._close_acks(d, reason=reason)
            elif not blocked and self.cfg.inactivity_applies_to_approved and self.cfg.inactivity_days:
                return self._inactivity(d, owners, recipients, before, result, new_blocks) or 0
            return 0

        violations = [f.as_dict() for f in ev.violations]
        if not blocked:
            return self._block(d, result, recipients, owner, owner_source, before, new_blocks,
                               block_type="drift",
                               reason="approved agent violates its registry approval",
                               violations=violations, approval_entry=approval.entry,
                               evaluation=ev, owners=owners)
        if ours:
            if state_entry.get("violationsFingerprint") != ev.fingerprint():
                state_entry.update({"blockType": "drift", "violations": violations,
                                    "violationsFingerprint": ev.fingerprint()})
                self._audit("violation_updated", d, caseId=state_entry.get("caseId"),
                            violations=violations, configHash=ev.config_hash,
                            reason="violations changed while blocked")
            self._process_acks(d, recipients, result)
        return 0

    def _record_validation(self, d: dict, entry: dict, ev: Any) -> None:
        """Audit continuous validation results when they change (or every
        cycle when audit_no_action is on)."""
        fp = ev.fingerprint()
        changed = self.state.validations.get(d["id"]) != fp
        if not (changed or self.cfg.audit_no_action):
            return
        self.state.validations[d["id"]] = fp
        approval = entry.get("approval") or {}
        self._audit("registry_validation", d,
                    result="compliant" if ev.compliant else "violation",
                    violations=[f.as_dict() for f in ev.violations],
                    warnings=[f.as_dict() for f in ev.warnings],
                    configHash=ev.config_hash,
                    baselineHash=(entry.get("baseline") or {}).get("configHash"),
                    approvalRef={"requestId": approval.get("requestId"),
                                 "riskRating": approval.get("riskRating"),
                                 "approvedBy": approval.get("approvedBy"),
                                 "expiresAt": approval.get("expiresAt")},
                    changed=changed)

    def _sync_registry(self) -> None:
        """Reload the registry and audit additions, changes, removals and
        entries rejected for a bad signature."""
        if not self.registry:
            return
        try:
            self.registry.load()
        except Exception as exc:  # keep the last good copy
            if self.registry.loaded:
                self._audit("error", stage="registry_load", error=str(exc),
                            reason="registry could not be loaded; using the last good copy")
                return
            snap = self.state.registry_snapshot
            if snap and isinstance(snap.get("agents"), list):
                # A fresh process (an Azure Functions invocation) has no copy in memory:
                # fall back on the one saved in the state. Entries are re-verified.
                self.registry.apply(snap["agents"], snap.get("hash"))
                self._reject_rollbacks()
                self.state.registry_invalid = dict(self.registry.invalid)
                self._audit("error", stage="registry_load", error=str(exc),
                            reason="registry could not be loaded; using the copy saved in the state",
                            registryFileHash=snap.get("hash"))
                self._registry_file_hash = self.registry.file_hash
                return
            self._audit("error", stage="registry_load", error=str(exc),
                        reason="registry could not be loaded and no earlier copy exists; "
                               "decisions on shared agents are deferred this cycle")
            return
        self._reject_rollbacks()
        self.state.registry_snapshot = {"agents": self.registry.raw_agents,
                                        "hash": self.registry.file_hash}
        current = self.registry.entry_hashes()
        previous = self.state.registry_hashes
        for pid in sorted(set(current) | set(previous)):
            if current.get(pid) == previous.get(pid):
                continue
            entry = self.registry.entries.get(pid, {})
            approval = entry.get("approval") or {}
            event = ("registry_entry_added" if pid not in previous else
                     "registry_entry_removed" if pid not in current else
                     "registry_entry_updated")
            self._audit(event, {"id": pid, "displayName": entry.get("displayName"),
                                "manifestId": entry.get("manifestId")},
                        entryHash=current.get(pid), previousEntryHash=previous.get(pid),
                        status=entry.get("status"),
                        approval={k: approval.get(k) for k in
                                  ("requestId", "approvedBy", "approvedAt", "expiresAt",
                                   "riskRating", "riskScore")} if entry else None,
                        criteria=approval.get("criteria") if entry else None,
                        allowedPrincipals=(entry.get("sharing") or {}).get("allowedPrincipals"),
                        baselineHash=(entry.get("baseline") or {}).get("configHash"))
        for pid, why in self.registry.invalid.items():
            if self.state.registry_invalid.get(pid) != why:
                self._audit("registry_entry_invalid", {"id": pid}, reason=why)
        self.state.registry_invalid = dict(self.registry.invalid)
        self.state.registry_hashes = current
        self._registry_file_hash = self.registry.file_hash

    def _reject_rollbacks(self) -> None:
        for pid in self.registry.reject_rollbacks(self.state.registry_newest):
            if self.state.registry_invalid.get(pid) == self.registry.invalid[pid]:
                continue                     # already reported
            self._audit("registry_rollback_rejected", {"id": pid}, reason=self.registry.invalid[pid],
                        newestSignedAt=self.state.registry_newest.get(pid))
            self.notify("registry_rollback_rejected", {"packageId": pid, "reason": self.registry.invalid[pid]})
            self._admin_alert({"id": pid}, None, "Registry entry rejected: an earlier entry was put back", {
                "Problem": self.registry.invalid[pid],
                "Next step": "Find who restored the entry (list version history); the agent is treated "
                             "as unapproved until the signer writes a current entry"})

    # -- block --------------------------------------------------------------
    def _block(self, d: dict, result: CycleResult, recipients: list[dict], owner: str | None,
               owner_source: str | None, before: dict, new_blocks: int, block_type: str,
               reason: str, violations: list[dict] | None = None,
               approval_entry: dict | None = None, evaluation: Any = None,
               approval_status: str | None = None, owners: list[str] | None = None,
               extra: dict | None = None, state_extra: dict | None = None) -> int:
        pid, name = d["id"], d.get("displayName", "")
        owners = owners if owners is not None else ([owner] if owner else [])
        ours = self.state.is_ours(pid)
        if result.circuit_breaker_tripped or new_blocks >= self.cfg.max_blocks_per_cycle:
            if not result.circuit_breaker_tripped:
                log.critical("Circuit breaker: %d blocks this cycle; halting further blocks",
                             new_blocks)
                self.notify("circuit_breaker", {"blocks_this_cycle": new_blocks})
                self._audit("circuit_breaker", blocksThisCycle=new_blocks,
                            reason="max_blocks_per_cycle reached")
            result.circuit_breaker_tripped = True
            self._audit("block_deferred", d, before=before, recipients=recipients,
                        blockType=block_type, violations=violations,
                        reason="circuit breaker tripped", outcome="deferred")
            return 0
        event = "reblock" if ours else "block"
        case_id = uuid.uuid4().hex
        approval_ref = None
        if approval_entry:
            a = approval_entry.get("approval") or {}
            approval_ref = {"requestId": a.get("requestId"), "riskRating": a.get("riskRating"),
                            "approvedBy": a.get("approvedBy")}
        log.warning("%s %s (%s) [%s]: %s", event.upper(), pid, name, block_type, reason)
        if not self.cfg.dry_run:
            try:
                self.graph.block(pid)
            except GraphError as exc:
                log.error("Block failed for %s: %s", pid, exc)
                self._audit(event, d, before=before, after=before, recipients=recipients,
                            blockType=block_type, violations=violations, reason=reason,
                            caseId=case_id, outcome="failed", error=str(exc))
                result.errors.append(pid)
                return 0
            self.state.record_block(pid, {
                "displayName": name,
                "blockedAt": datetime.now(timezone.utc).isoformat(),
                "sharedWith": recipients,
                "caseId": case_id,
                "ownerId": owner,
                "ownerIds": owners,
                "ownerSource": owner_source,
                "blockType": block_type,
                "violations": violations,
                "violationsFingerprint": evaluation.fingerprint() if evaluation else None,
                "approvalRef": approval_ref,
                **(state_extra or {}),
            })
            self._save_state()      # record it now: a later crash mustn't orphan the block
        self._audit(event, d, before=before,
                    after=self._snapshot(not self.cfg.dry_run, recipients),
                    recipients=recipients, reason=reason, caseId=case_id, ownerId=owner,
                    ownerIds=owners if len(owners) > 1 else None,
                    blockType=block_type, violations=violations, approvalRef=approval_ref,
                    approvalStatus=approval_status,
                    configHash=evaluation.config_hash if evaluation else None,
                    outcome="simulated" if self.cfg.dry_run else "success", **(extra or {}))
        (result.reblocked if ours else result.blocked).append(pid)
        if block_type == "drift":
            result.drift_blocked.append(pid)
        elif block_type == "retired":
            result.retired.append(pid)
        self.notify("blocked", {"packageId": pid, "displayName": name,
                                "sharedWith": recipients, "reblock": ours,
                                "blockType": block_type, "violations": violations,
                                "caseId": case_id, "dryRun": self.cfg.dry_run})
        self._send_notice(d, owners, recipients, case_id, block_type, violations, approval_entry)
        return 1

    # -- notice email -------------------------------------------------------
    def _send_notice(self, d: dict, owners: list[str] | str | None, recipients: list[dict],
                     case_id: str, block_type: str = "sharing",
                     violations: list[dict] | None = None,
                     approval_entry: dict | None = None) -> None:
        if not self._mail_on:
            return
        if isinstance(owners, str) or owners is None:
            owners = [owners] if owners else []
        extra_admins = (approval_entry or {}).get("governanceContacts") or []
        if block_type == "drift":
            self._admin_alert(d, case_id, "Approved agent blocked: configuration drift", {
                "Owners": ", ".join(owners) or "unknown",
                "Approval": ((approval_entry or {}).get("approval") or {}).get("requestId"),
                "Violations": "; ".join(v["message"] for v in violations or [])},
                extra=extra_admins)
        if block_type == "ownerless":
            self._admin_alert(d, case_id, "Agent blocked: no owner has an active account", {
                "Owners": ", ".join(owners) or "unknown", "Recipients": len(recipients),
                "Next step": "Assign an active owner (Agent 365 registry > Reassign), or delete "
                             "the agent; the guard unblocks it once an owner is active"},
                extra=extra_admins)
            return
        if not owners:
            self._audit("owner_unknown", d, caseId=case_id,
                        reason="no owner could be resolved; notice sent to admins instead")
            self._admin_alert(d, case_id, "Agent blocked, owner unknown", {
                "Block type": block_type, "Recipients": len(recipients),
                "Action": "Identify the owner and add them to the owner map, or remove sharing manually"},
                extra=extra_admins)
            return
        template = {"drift": "drift_notice", "retired": "retired_notice"}.get(block_type, "share_notice")
        failures = 0
        for owner in owners:
            ack_url = expires_at = token_id = None
            if self.cfg.ack_enabled and self.signer and (self.cfg.ack_base_url or self.cfg.ack_form_url):
                from .ack import ack_link
                token, claims = self.signer.issue(d["id"], owner, case_id)
                ack_url = ack_link(self.cfg.ack_form_url or self.cfg.ack_base_url or "", token)
                token_id = claims.token_id
                expires_at = datetime.fromtimestamp(claims.expires, timezone.utc).strftime(
                    "%d %b %Y %H:%M UTC")
            try:
                user = self.mailer.get_user(owner)
                if block_type == "drift":
                    meta = self.mailer.send_drift_notice(user, d, violations or [],
                                                         approval_entry or {}, ack_url, expires_at)
                elif block_type == "retired":
                    archive_on = self._parse_time(self.state.data.get(d["id"], {}).get("archiveOn"))
                    meta = self.mailer.send_retired_notice(
                        user, d, self.cfg.inactivity_days or 0, ack_url, expires_at,
                        archive_on=archive_on.strftime("%d %b %Y") if archive_on else None,
                        archive_after_days=self.cfg.archive_after_days if self._archiving else None,
                        deletion_mode=self.cfg.deletion_mode)
                else:
                    meta = self.mailer.send_share_notice(user, d, recipients, ack_url, expires_at)
            except Exception as exc:
                failures += 1
                self._audit("email_failed", d, template=template, caseId=case_id,
                            ownerId=owner, error=str(exc), outcome="failed")
                continue
            if self.state.is_ours(d["id"]):
                self.state.data[d["id"]].update({"noticeSentAt": meta["sentAt"],
                                                 "ackTokenId": token_id})
            self._audit("notice_email_sent", d, caseId=case_id, ownerId=owner, email=meta,
                        blockType=block_type, ackLinkIssued=bool(ack_url), ackTokenId=token_id,
                        ackExpiresAt=expires_at,
                        outcome="simulated" if meta.get("simulated") else "success")
        if failures == len(owners):
            self._admin_alert(d, case_id, "Could not email the owner of a blocked agent",
                              {"Owners": ", ".join(owners)}, extra=extra_admins)

    def _admin_alert(self, d: dict, case_id: str | None, subject: str, lines: dict,
                     extra: list[str] | None = None) -> None:
        if not self._mail_on or not (self.mailer.admin_emails or extra):
            return
        try:
            meta = self.mailer.send_admin_alert(subject, {
                "Agent": d.get("displayName"), "Package ID": d.get("id"),
                "Case ID": case_id, **lines}, extra_recipients=extra)
            self._audit("admin_alert_sent", d, caseId=case_id, subject=subject, email=meta)
        except Exception as exc:
            self._audit("email_failed", d, template="admin_alert", caseId=case_id,
                        error=str(exc), outcome="failed")

    # -- acknowledgements ---------------------------------------------------
    def _close_acks(self, d: dict, reason: str) -> None:
        if not self.acks:
            return
        for ack in self.acks.pending_for_package(d["id"]):
            self._audit("ack_closed", d, caseId=ack["caseId"], reason=reason)
            self.acks.close(ack["caseId"])

    def _process_acks(self, d: dict, recipients: list[dict], result: CycleResult) -> None:
        if not self.acks:
            return
        pid = d["id"]
        entry = self.state.data.get(pid, {})
        for ack in self.acks.pending_for_package(pid):
            case_id = ack["caseId"]
            if case_id != entry.get("caseId"):
                self._audit("ack_stale", d, caseId=case_id, currentCaseId=entry.get("caseId"),
                            reason="acknowledgement is for an earlier block")
                self.acks.close(case_id)
                continue
            allowed = set(entry.get("ownerIds") or []) | ({entry["ownerId"]} if entry.get("ownerId") else set())
            if allowed and ack["ownerId"] not in allowed:
                self._audit("ack_rejected", d, caseId=case_id, reason="owner mismatch",
                            ackOwnerId=ack["ownerId"], ownerId=entry.get("ownerId"),
                            ownerIds=sorted(allowed))
                self.acks.close(case_id)
                continue
            if entry.get("blockType") == "retired":
                self._reactivate(d, ack, recipients, result)
                continue
            self._remove_sharing_on_behalf(d, ack, recipients, result)

    def _remove_sharing_on_behalf(self, d: dict, ack: dict, recipients: list[dict],
                                  result: CycleResult) -> None:
        pid, case_id, owner = d["id"], ack["caseId"], ack["ownerId"]
        common = {"caseId": case_id, "onBehalfOf": owner, "ackTokenId": ack.get("tokenId"),
                  "ackReceivedAt": ack.get("receivedAt"), "removedRecipients": recipients}

        if self.cfg.dry_run:
            self._audit("sharing_removal", d, outcome="simulated", **common)
            return

        if not self.delegated:
            self._audit("sharing_removal", d, outcome="pending_manual",
                        reason="no delegated identity configured; admins asked to remove sharing",
                        **common)
            self._admin_alert(d, case_id, "Owner acknowledged: please remove sharing", {
                "Owner": owner, "Acknowledged at": ack.get("receivedAt"),
                "Recipients": len(recipients),
                "Next step": "Remove sharing; the guard will unblock automatically"})
            self.acks.close(case_id)
            return

        attempt = self.acks.bump_attempt(case_id)
        body = {"allowedUsersAndGroups": [{"resourceType": "user", "resourceId": owner}],
                "availableTo": self.cfg.removal_available_to_value}
        try:
            self.delegated.update_package(pid, body)
        except GraphError as exc:
            self._audit("sharing_removal", d, outcome="failed", attempt=attempt,
                        error=str(exc), request=body, **common)
            self._escalate_if_exhausted(d, ack, attempt, f"Sharing removal failed: {exc}")
            return
        self._audit("sharing_removal", d, outcome="success", attempt=attempt,
                    request=body, actingIdentity=self.cfg.delegated_username, **common)

        # Verify by reading back: unblock only once sharing is really gone.
        fresh = self.graph.get_package(pid)
        remaining = sharing_recipients(fresh, self.cfg)
        if remaining:
            self._audit("sharing_removal_unverified", d, attempt=attempt,
                        remainingRecipients=remaining, caseId=case_id,
                        reason="agent still reports sharing after removal; will retry")
            self._escalate_if_exhausted(d, ack, attempt,
                                        "Sharing still present after removal")
            return
        self._unblock(fresh, result, [], case_id=case_id, on_behalf_of=owner,
                      reason="owner acknowledged; sharing removed by guard on owner's behalf")
        result.removed_on_behalf.append(pid)
        self.acks.close(case_id)

    def _escalate_if_exhausted(self, d: dict, ack: dict, attempt: int, problem: str) -> None:
        if attempt < self.cfg.ack_max_attempts:
            return
        self._audit("ack_escalated", d, caseId=ack["caseId"], attempts=attempt,
                    reason=problem)
        self._admin_alert(d, ack["caseId"], "Could not remove sharing on the owner's behalf", {
            "Owner": ack["ownerId"], "Attempts": attempt, "Problem": problem,
            "Next step": "Remove sharing manually; the guard will unblock automatically"})
        self.acks.close(ack["caseId"])

    # -- lifecycle: ownerless agents and inactivity --------------------------
    def _lifecycle(self, d: dict, owners: list[str], recipients: list[dict], before: dict,
                   result: CycleResult, new_blocks: int) -> int | None:
        """Ownership and inactivity checks for an agent that is otherwise allowed.
        Returns 1 when a block was issued, 0 when handled, None to carry on."""
        if owners and self.cfg.owner_status_checks:
            inactive = self._inactive(owners)
            if len(inactive) == len(owners):
                issued = self._ownerless(d, owners, recipients, before, result, new_blocks)
                if issued is not None:
                    return issued
        if self.cfg.inactivity_days:
            return self._inactivity(d, owners, recipients, before, result, new_blocks)
        return None

    def _ownerless(self, d: dict, owners: list[str], recipients: list[dict], before: dict,
                   result: CycleResult, new_blocks: int) -> int | None:
        pid = d["id"]
        statuses = {o: self._status(o) for o in owners}
        lc = self.state.lifecycle.setdefault(pid, {})
        fingerprint = hashlib.sha256(_canonical(statuses)).hexdigest()
        action = self.cfg.ownerless_action
        if action == "block":
            result.ownerless.append(pid)
            return self._block(d, result, recipients, owners[0], "lifecycle", before, new_blocks,
                               block_type="ownerless", reason="no owner has an active account",
                               owners=owners, extra={"ownerStatus": statuses})
        if action == "reassign_to_manager":
            for o in owners:
                manager = self.graph.manager_of(o) if statuses[o] == "disabled" else None
                if not manager or self._status(manager) != "active":
                    continue
                outcome = "simulated"
                if not self.cfg.dry_run:
                    try:
                        self.graph.reassign(pid, manager)
                        outcome = "success"
                    except GraphError as exc:
                        self._audit("ownership_reassigned", d, previousOwners=owners, newOwner=manager,
                                    ownerStatus=statuses, outcome="failed", error=str(exc),
                                    reason="no owner has an active account")
                        break
                    self.state.package_owners[pid] = manager
                self._audit("ownership_reassigned", d, previousOwners=owners, newOwner=manager,
                            ownerStatus=statuses, outcome=outcome,
                            reason="no owner has an active account; reassigned to a former owner's manager")
                result.reassigned.append(pid)
                lc.pop("ownerlessReported", None)
                if self._mail_on and outcome == "success":
                    try:
                        meta = self.mailer.send_ownership_transferred(self.mailer.get_user(manager), d, o)
                        self._audit("ownership_email_sent", d, ownerId=manager, email=meta,
                                    outcome="simulated" if meta.get("simulated") else "success")
                    except Exception as exc:
                        self._audit("email_failed", d, template="ownership_transferred",
                                    ownerId=manager, error=str(exc), outcome="failed")
                return 0
        # "report", or no manager could take over
        if lc.get("ownerlessReported") != fingerprint:
            lc["ownerlessReported"] = fingerprint
            result.ownerless.append(pid)
            self._audit("ownerless_detected", d, ownerStatus=statuses, action=action,
                        reason="no owner has an active account")
            self._admin_alert(d, None, "Agent has no active owner", {
                "Owners": ", ".join(f"{o} ({st})" for o, st in statuses.items()),
                "Policy": action,
                "Next step": "Reassign the agent to an active owner, or delete it"})
        return None

    @staticmethod
    def _parse_time(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value or value.startswith("0001-"):
            return None
        try:
            ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)

    def _last_activity(self, d: dict) -> datetime | None:
        lc = self.state.lifecycle.get(d["id"], {})
        stamps = [self._parse_time(d.get(k)) for k in ("lastUsedDateTime", "lastModifiedDateTime",
                                                         "createdDateTime")]
        stamps.append(self._parse_time(lc.get("reactivatedAt")))
        stamps = [t for t in stamps if t]
        return max(stamps) if stamps else None

    _NOTICE_KEYS = ("noticeAt", "noticeForActivity", "retireOn", "reminderAt")

    def _inactivity(self, d: dict, owners: list[str], recipients: list[dict], before: dict,
                    result: CycleResult, new_blocks: int) -> int | None:
        """Notice -> (reminder) -> retirement for an agent nobody uses.

        The agent becomes inactive ``inactivity_days`` after its last activity. Owners
        are told ``inactivity_notice_days`` before that, and retirement (a block) is
        never sooner than that notice period, even when the policy is first switched
        on. Any use in between cancels it."""
        days = self.cfg.inactivity_days or 0
        notice_days, remind_days = self.cfg.inactivity_notice_days, self.cfg.inactivity_reminder_days
        last = self._last_activity(d)
        if not days or last is None:
            return None
        now = datetime.now(timezone.utc)
        idle = (now - last).days
        pid = d["id"]
        lc = self.state.lifecycle.setdefault(pid, {})
        last_iso = last.isoformat()
        if lc.get("noticeAt") and lc.get("noticeForActivity") != last_iso:
            self._audit("inactivity_cleared", d, lastActivity=last_iso,
                        reason="agent was used after the retirement notice")
            for k in self._NOTICE_KEYS:
                lc.pop(k, None)
        inactive_on = last + timedelta(days=days)
        retire_on = self._parse_time(lc.get("retireOn"))
        if lc.get("noticeAt") and retire_on:
            if now >= retire_on:
                archive_on = (now + timedelta(days=self.cfg.archive_after_days)
                              if self._archiving else None)
                issued = self._block(
                    d, result, recipients, owners[0] if owners else None, "lifecycle", before, new_blocks,
                    block_type="retired", reason=f"not used for {idle} days (policy: {days} days)",
                    owners=owners, extra={"lastActivity": last_iso, "idleDays": idle,
                                          "inactiveSince": inactive_on.isoformat(),
                                          "archiveOn": archive_on.isoformat() if archive_on else None},
                    state_extra={"lastActivity": last_iso, "retiredAt": now.isoformat(),
                                 "archiveOn": archive_on.isoformat() if archive_on else None})
                if issued:
                    for k in self._NOTICE_KEYS:
                        lc.pop(k, None)
                return issued
            left = (retire_on - now).days + 1
            if remind_days and not lc.get("reminderAt") and left <= remind_days:
                lc["reminderAt"] = now.isoformat()
                emails = self._email_owners(d, owners, "inactivity_reminder", lambda u: self.mailer.send_inactivity_warning(
                    u, d, last.strftime("%d %b %Y"), retire_on.strftime("%d %b %Y"), days,
                    notice_days=notice_days, days_left=left, reminder=True,
                    archive_after_days=self.cfg.archive_after_days if self._archiving else None,
                    deletion_mode=self.cfg.deletion_mode))
                self._audit("inactivity_reminder", d, lastActivity=last_iso, idleDays=idle,
                            retireOn=retire_on.isoformat(), daysLeft=left, ownerIds=owners,
                            emails=emails or None, outcome="simulated" if self.cfg.dry_run else "success")
            return None
        if now >= inactive_on - timedelta(days=notice_days):
            retire_on = max(inactive_on, now + timedelta(days=notice_days))
            lc.update({"noticeAt": now.isoformat(), "noticeForActivity": last_iso,
                       "retireOn": retire_on.isoformat()})
            result.inactivity_warned.append(pid)
            emails = self._email_owners(d, owners, "inactivity_warning", lambda u: self.mailer.send_inactivity_warning(
                u, d, last.strftime("%d %b %Y"), retire_on.strftime("%d %b %Y"), days,
                notice_days=notice_days, days_left=(retire_on - now).days,
                archive_after_days=self.cfg.archive_after_days if self._archiving else None,
                deletion_mode=self.cfg.deletion_mode))
            self._audit("inactivity_warning", d, lastActivity=last_iso, idleDays=idle,
                        inactiveOn=inactive_on.isoformat(), retireOn=retire_on.isoformat(),
                        ownerIds=owners, emails=emails or None,
                        outcome="simulated" if self.cfg.dry_run else "success")
        return None

    def _email_owners(self, d: dict, owners: list[str], template: str,
                      send: Callable[[dict], dict]) -> list[dict]:
        emails: list[dict] = []
        if not self._mail_on:
            return emails
        for o in owners:
            try:
                emails.append(send(self.mailer.get_user(o)))
            except Exception as exc:
                self._audit("email_failed", d, template=template, ownerId=o,
                            error=str(exc), outcome="failed")
        return emails

    # -- retirement: archive, then deletion ---------------------------------
    def _retirement_progress(self, d: dict, entry: dict, owners: list[str], result: CycleResult) -> None:
        if not self._archiving or not self.archive:
            return
        now = datetime.now(timezone.utc)
        if not entry.get("archivedAt"):
            archive_on = self._parse_time(entry.get("archiveOn"))
            if archive_on is None:           # retired before archiving was configured
                retired = self._parse_time(entry.get("retiredAt") or entry.get("blockedAt")) or now
                archive_on = retired + timedelta(days=self.cfg.archive_after_days or 0)
                entry["archiveOn"] = archive_on.isoformat()
            if now >= archive_on:
                self._archive_agent(d, entry, owners, result)
            if not entry.get("archivedAt"):
                return                       # not yet, failed, or a dry run
        mode = self.cfg.deletion_mode
        if mode == "none":
            return
        if mode == "api" and not entry.get("deletionSubmittedAt") and not entry.get("deletionApiFailed"):
            self._delete_via_api(d, entry, result)
            return
        submitted = self._parse_time(entry.get("deletionSubmittedAt"))
        if mode == "api" and submitted and not entry.get("deletionApiFailed"):
            if (now - submitted).days < self.cfg.deletion_reminder_days:
                return                       # give the deletion time to propagate
            entry["deletionApiFailed"] = "still listed after the deletion request"
            self._audit("deletion_unverified", d, caseId=entry.get("caseId"),
                        submittedAt=entry.get("deletionSubmittedAt"),
                        reason="agent still in the catalog; asking admins to delete it")
        self._request_manual_deletion(d, entry, result, now)

    def _archive_agent(self, d: dict, entry: dict, owners: list[str], result: CycleResult) -> None:
        from .archive import archive_files
        from .registry import declarative_definitions
        pid = d["id"]
        people = []
        for o in owners:
            person = {"id": o}
            if self.mailer is not None:
                try:
                    u = self.mailer.get_user(o)
                    person.update({"displayName": u.get("displayName"),
                                   "userPrincipalName": u.get("userPrincipalName") or u.get("mail")})
                except Exception as exc:          # deleted owners can't be looked up
                    person["lookupError"] = str(exc)[:120]
            people.append(person)
        embedded = []
        for definition in declarative_definitions(d):
            for cap in definition.get("capabilities") or []:
                if cap.get("name") in self.cfg.embedded_capability_names:
                    embedded.append({k: v for k, v in cap.items() if k != "name"} or {"capability": cap.get("name")})
        approval = None
        if self.registry is not None:
            try:
                found = self.registry.lookup(d)
                approval = found.entry if found is not None else None
            except Exception:
                approval = None
        now = datetime.now(timezone.utc).isoformat()
        manifest = {"packageId": pid, "displayName": d.get("displayName"), "platform": d.get("platform"),
                    "owners": people, "createdDateTime": d.get("createdDateTime"),
                    "lastActivity": entry.get("lastActivity"), "retiredAt": entry.get("retiredAt")
                    or entry.get("blockedAt"), "archivedAt": now, "caseId": entry.get("caseId"),
                    "inactivityDays": self.cfg.inactivity_days, "deletionMode": self.cfg.deletion_mode,
                    "registryEntry": approval, "embeddedKnowledge": embedded or None,
                    "embeddedFilesCopied": False,
                    "archivedBy": (self.audit.actor if self.audit else None)}
        files = archive_files(d, manifest)
        if self.cfg.dry_run:
            self._audit("agent_archived", d, caseId=entry.get("caseId"), files=sorted(files),
                        outcome="simulated", reason="retired agent reached its archive date")
            return
        try:
            where = self.archive.save(pid, files)
        except Exception as exc:
            log.error("Archive failed for %s: %s", pid, exc)
            self._audit("archive_failed", d, caseId=entry.get("caseId"), error=str(exc), outcome="failed")
            if not entry.get("archiveFailedAt"):
                entry["archiveFailedAt"] = now
                self._admin_alert(d, entry.get("caseId"), "Retired agent could not be archived", {
                    "Error": str(exc)[:300], "Next step": "Check the archive site permissions; "
                    "the guard retries every cycle and won't request deletion until it's archived"})
            return
        entry.pop("archiveFailedAt", None)
        entry.update({"archivedAt": now, "archiveReference": where["reference"],
                      "archiveLocation": where.get("location")})
        result.archived.append(pid)
        self._audit("agent_archived", d, caseId=entry.get("caseId"), archive=where, files=sorted(files),
                    agentJsonSha256=json.loads(files["manifest.json"])["agentJsonSha256"],
                    outcome="success", reason="retired agent reached its archive date")
        self.notify("archived", {"packageId": pid, "displayName": d.get("displayName"), "archive": where})
        if self.cfg.archive_notify_owners:
            emails = self._email_owners(d, owners, "archived_notice", lambda u: self.mailer.send_archived_notice(
                u, d, where["reference"], self.cfg.deletion_mode))
            if emails:
                self._audit("archived_email_sent", d, caseId=entry.get("caseId"), emails=emails,
                            outcome="simulated" if any(e.get("simulated") for e in emails) else "success")

    def _delete_via_api(self, d: dict, entry: dict, result: CycleResult) -> None:
        pid = d["id"]
        url = self.cfg.deletion_api_path.replace("{id}", pid)
        if self.cfg.dry_run:
            self._audit("deletion_submitted", d, caseId=entry.get("caseId"), method="api", outcome="simulated")
            return
        try:
            (self.delegated or self.graph).request("DELETE", url)
        except GraphError as exc:
            entry["deletionApiFailed"] = f"{exc.status}: {str(exc)[:200]}"
            self._audit("deletion_failed", d, caseId=entry.get("caseId"), method="api", error=str(exc),
                        outcome="failed", reason="falling back to deletion by an admin")
            self._request_manual_deletion(d, entry, result, datetime.now(timezone.utc))
            return
        entry["deletionSubmittedAt"] = datetime.now(timezone.utc).isoformat()
        result.deletion_requested.append(pid)
        self._audit("deletion_submitted", d, caseId=entry.get("caseId"), method="api",
                    archiveReference=entry.get("archiveReference"), outcome="success")

    def _request_manual_deletion(self, d: dict, entry: dict, result: CycleResult, now: datetime) -> None:
        last = self._parse_time(entry.get("deletionReminderAt") or entry.get("deletionRequestedAt"))
        first = not entry.get("deletionRequestedAt")
        if not first and (last and (now - last).days < max(self.cfg.deletion_reminder_days, 1)):
            return
        entry["deletionReminderAt" if not first else "deletionRequestedAt"] = now.isoformat()
        result.deletion_requested.append(d["id"])
        self._audit("deletion_requested" if first else "deletion_reminder", d, caseId=entry.get("caseId"),
                    archiveReference=entry.get("archiveReference"), archiveLocation=entry.get("archiveLocation"),
                    outcome="simulated" if self.cfg.dry_run else "success")
        self._admin_alert(d, entry.get("caseId"),
                          "Retired agent archived and ready for deletion" if first
                          else "Reminder: retired agent still waiting for deletion", {
                              "Agent ID": d["id"],
                              "Retired": entry.get("retiredAt") or entry.get("blockedAt"),
                              "Archive": entry.get("archiveLocation") or entry.get("archiveReference"),
                              "Next step": "Microsoft 365 admin center > Agents > All agents > select the agent "
                                           "> Delete agent. ShareGuard confirms the deletion on its next cycle.",
                              "Changed your mind?": "Leave it blocked: an owner can still reactivate it until "
                                                    "it's deleted."})

    def _record_deleted(self, pid: str, entry: dict, result: CycleResult) -> None:
        details = {"packageId": pid, "deletedObservedAt": datetime.now(timezone.utc).isoformat(),
                   "caseId": entry.get("caseId"), "deletionMode": self.cfg.deletion_mode,
                   "deletionRequestedAt": entry.get("deletionRequestedAt"),
                   "deletionSubmittedAt": entry.get("deletionSubmittedAt")}
        outcome = "success"
        if self.archive and entry.get("archiveReference") and not self.cfg.dry_run:
            try:
                self.archive.record_status(entry["archiveReference"], "deleted", details)
            except Exception as exc:
                outcome = "partial"
                details["archiveStatusError"] = str(exc)[:200]
        result.deleted.append(pid)
        self._audit("agent_deleted", {"id": pid, "displayName": entry.get("displayName")},
                    caseId=entry.get("caseId"), archiveReference=entry.get("archiveReference"),
                    archiveLocation=entry.get("archiveLocation"), outcome=outcome,
                    reason="retired agent no longer in the catalog: deleted",
                    **{k: v for k, v in details.items() if k not in ("packageId", "caseId")})
        self.notify("deleted", {"packageId": pid, "displayName": entry.get("displayName"),
                                "archive": entry.get("archiveReference")})

    # State keys that only make sense while an agent is retired.
    _RETIREMENT_KEYS = ("retiredAt", "lastActivity", "archiveOn", "archivedAt", "archiveReference",
                        "archiveLocation", "archiveFailedAt", "deletionRequestedAt", "deletionReminderAt",
                        "deletionSubmittedAt", "deletionApiFailed")

    def _reconcile_lifecycle_block(self, d: dict, block_type: str, owners: list[str],
                                   recipients: list[dict], result: CycleResult) -> str | None:
        """A retired or ownerless agent this guard blocked: release it when that's allowed.

        Returns the new case ID when the lifecycle reason is gone but the agent is still
        shared, so it's now held under the sharing policy instead; otherwise None."""
        entry = self.state.data.get(d["id"], {})
        if block_type == "ownerless":
            active = [o for o in owners if self._status(o) == "active"]
            if active:
                if self.state.is_ours(d["id"]):
                    entry["ownerId"] = active[0]
                reason = "an active owner is assigned again"
                if recipients:
                    return self._hold_for_sharing(d, owners, recipients, reason)
                self._unblock(d, result, recipients, reason=reason)
            return None
        self._process_acks(d, recipients, result)          # reactivation requests
        held = self._held.pop(d["id"], None)
        if held:
            return held
        if self.state.is_ours(d["id"]) and self.state.data[d["id"]].get("blockType") == "retired":
            self._retirement_progress(d, self.state.data[d["id"]], owners, result)
        return None

    def _hold_for_sharing(self, d: dict, owners: list[str], recipients: list[dict], reason: str,
                          on_behalf_of: str | None = None) -> str:
        """Keep a lifecycle-blocked agent blocked because it's shared: the block becomes a
        sharing block with a new case, and the usual policy takes it from here."""
        pid = d["id"]
        entry = self.state.data[pid]
        previous_case, previous_type = entry.get("caseId"), entry.get("blockType")
        case_id = uuid.uuid4().hex
        for k in self._RETIREMENT_KEYS:
            entry.pop(k, None)
        entry.update({"blockType": "sharing", "caseId": case_id, "sharedWith": recipients,
                      "violations": None, "violationsFingerprint": None, "ackTokenId": None,
                      "ownerIds": owners or entry.get("ownerIds"),
                      "ownerId": entry.get("ownerId") or (owners[0] if owners else None)})
        self._audit("block_reason_changed", d, caseId=case_id, previousCaseId=previous_case,
                    previousBlockType=previous_type, blockType="sharing", recipients=recipients,
                    onBehalfOf=on_behalf_of,
                    reason=f"{reason}, but the agent is shared: it stays blocked under the sharing policy")
        return case_id

    def _notify_if_still_held(self, d: dict, case_id: str, owners: list[str], recipients: list[dict]) -> None:
        entry = self.state.data.get(d["id"])
        if not entry or entry.get("caseId") != case_id:
            return                              # released (e.g. approved and compliant)
        approval = self.registry.lookup(d) if self.registry else None
        self._send_notice(d, owners or entry.get("ownerIds") or entry.get("ownerId"), recipients, case_id,
                          entry.get("blockType") or "sharing", entry.get("violations"),
                          approval.entry if approval is not None and approval.valid else None)

    def _reactivate(self, d: dict, ack: dict, recipients: list[dict], result: CycleResult) -> None:
        pid, case_id = d["id"], ack["caseId"]
        entry = dict(self.state.data.get(pid, {}))
        self._audit("reactivation_requested", d, caseId=case_id, ownerId=ack["ownerId"],
                    ackTokenId=ack.get("tokenId"), ackReceivedAt=ack.get("receivedAt"))
        reason = "owner reactivated a retired agent"
        if recipients:
            # Reactivation lifts the retirement, not the no-sharing policy.
            self._held[pid] = self._hold_for_sharing(d, [], recipients, reason, on_behalf_of=ack["ownerId"])
        else:
            self._unblock(d, result, recipients, case_id=case_id, on_behalf_of=ack["ownerId"], reason=reason)
        if not self.cfg.dry_run:
            lc = self.state.lifecycle.setdefault(pid, {})
            lc.update({"reactivatedAt": datetime.now(timezone.utc).isoformat()})
            for k in self._NOTICE_KEYS:
                lc.pop(k, None)
            result.reactivated.append(pid)
            if entry.get("archivedAt"):
                if self.archive and entry.get("archiveReference"):
                    try:
                        self.archive.record_status(entry["archiveReference"], "reactivated", {
                            "packageId": pid, "reactivatedAt": lc["reactivatedAt"], "ownerId": ack["ownerId"]})
                    except Exception:
                        log.exception("Could not record reactivation in the archive")
                self._audit("deletion_cancelled", d, caseId=case_id, ownerId=ack["ownerId"],
                            archiveReference=entry.get("archiveReference"),
                            reason="owner reactivated the agent before it was deleted")
                if entry.get("deletionRequestedAt") or entry.get("deletionSubmittedAt"):
                    self._admin_alert(d, case_id, "Don't delete: retired agent reactivated by its owner", {
                        "Agent ID": pid, "Owner": ack["ownerId"],
                        "Archive": entry.get("archiveLocation") or entry.get("archiveReference")})
        self.acks.close(case_id)

    # -- unblock ------------------------------------------------------------
    def _unblock(self, d: dict, result: CycleResult, recipients: list[dict],
                 reason: str, case_id: str | None = None,
                 on_behalf_of: str | None = None) -> None:
        pid, name = d["id"], d.get("displayName", "")
        entry = self.state.data.get(pid, {})
        case_id = case_id or entry.get("caseId")
        owner = entry.get("ownerId") or self.state.package_owners.get(pid)
        before = self._snapshot(bool(d.get("isBlocked", True)), recipients)
        blocked_at = entry.get("blockedAt")
        log.info("UNBLOCK %s (%s): %s", pid, name, reason)
        if not self.cfg.dry_run:
            try:
                self.graph.unblock(pid)
            except GraphError as exc:
                log.error("Unblock failed for %s: %s", pid, exc)
                self._audit("unblock", d, before=before, after=before, reason=reason,
                            caseId=case_id, onBehalfOf=on_behalf_of,
                            outcome="failed", error=str(exc))
                result.errors.append(pid)
                return
            self.state.forget(pid)
        self._audit("unblock", d, before=before,
                    after=self._snapshot(self.cfg.dry_run, recipients),
                    reason=reason, caseId=case_id, onBehalfOf=on_behalf_of,
                    originallyBlockedAt=blocked_at,
                    outcome="simulated" if self.cfg.dry_run else "success")
        result.unblocked.append(pid)
        self.notify("unblocked", {"packageId": pid, "displayName": name, "caseId": case_id,
                                  "reason": reason, "dryRun": self.cfg.dry_run})
        if self._mail_on and owner and reason != "exemption granted":
            try:
                meta = self.mailer.send_restored(self.mailer.get_user(owner), d, reason=reason)
                self._audit("restored_email_sent", d, caseId=case_id, ownerId=owner, email=meta,
                            outcome="simulated" if meta.get("simulated") else "success")
            except Exception as exc:
                self._audit("email_failed", d, template="restored", caseId=case_id,
                            ownerId=owner, error=str(exc), outcome="failed")


# --------------------------------------------------------------------------
# Notifications
# --------------------------------------------------------------------------
def make_webhook_notifier(url: str | None, timeout: int = 15) -> Callable[[str, dict], None]:
    def notify(event: str, payload: dict) -> None:
        if not url:
            return
        body = {"source": "absg", "event": event,
                "timestamp": datetime.now(timezone.utc).isoformat(), **payload}
        try:
            requests.post(url, json=body, timeout=timeout).raise_for_status()
        except requests.RequestException as exc:  # never let notifications break enforcement
            log.error("Notification failed (%s): %s", event, exc)
    return notify


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
DELEGATED_SCOPES = ["https://graph.microsoft.com/CopilotPackages.ReadWrite.All"]


def _delegated_app(cfg: Config):
    import msal

    cache = msal.SerializableTokenCache()
    if os.path.exists(cfg.delegated_token_cache):
        with open(cfg.delegated_token_cache, encoding="utf-8") as fh:
            cache.deserialize(fh.read())
    app = msal.PublicClientApplication(
        cfg.delegated_client_id, token_cache=cache,
        authority=f"https://login.microsoftonline.com/{cfg.tenant_id}")
    return app, cache


def _persist_cache(cfg: Config, cache: Any) -> None:
    if cache.has_state_changed:
        fd = os.open(cfg.delegated_token_cache, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(cache.serialize())


def build_delegated_provider(cfg: Config, cache_store: Any = None) -> Callable[[], str]:
    """Token provider for the delegated service account (silent refresh only).

    ``cache_store`` (optional, e.g. ``cloud.KeyVaultTokenCache``) keeps the MSAL token
    cache somewhere other than the local ``delegated_token_cache`` file."""
    if cache_store is None:
        app, cache = _delegated_app(cfg)
        persist = lambda: _persist_cache(cfg, cache)  # noqa: E731
    else:
        import msal
        cache = msal.SerializableTokenCache()
        cache_store.load(cache)
        app = msal.PublicClientApplication(
            cfg.delegated_client_id, token_cache=cache,
            authority=f"https://login.microsoftonline.com/{cfg.tenant_id}")
        persist = lambda: cache_store.save(cache)  # noqa: E731
    lock = threading.Lock()

    def provider() -> str:
        with lock:
            accounts = app.get_accounts(username=cfg.delegated_username)
            result = app.acquire_token_silent(DELEGATED_SCOPES, account=accounts[0]) \
                if accounts else None
            persist()
        if not result or "access_token" not in result:
            raise GraphError(401, "Delegated sign-in missing or expired: run --login-delegated")
        return result["access_token"]

    return provider


def login_delegated(cfg: Config) -> int:
    """One-off interactive device-code sign-in for the delegated service account."""
    app, cache = _delegated_app(cfg)
    flow = app.initiate_device_flow(scopes=DELEGATED_SCOPES)
    if "user_code" not in flow:
        print(f"Could not start device flow: {flow.get('error_description')}")
        return 1
    print(flow["message"])
    result = app.acquire_token_by_device_flow(flow)
    _persist_cache(cfg, cache)
    if "access_token" not in result:
        print(f"Sign-in failed: {result.get('error_description')}")
        return 1
    who = result.get("id_token_claims", {}).get("preferred_username")
    print(f"Signed in as {who}. Token cache saved to {cfg.delegated_token_cache}.")
    return 0


def registry_report(cfg: Config, draft_package_id: str | None) -> int:
    """--registry-draft / --registry-validate (read-only)."""
    from .mail import OwnerResolver
    from .registry import Registry, draft_entry, evaluate

    graph = GraphClient(cfg)
    state = StateStore(cfg.state_file)
    if draft_package_id:
        d = graph.get_package(draft_package_id)
        recipients = sharing_recipients(d, cfg)
        owner, _ = OwnerResolver(cfg.owner_fields, cfg.owner_map_file, state.package_owners,
                                 cfg.infer_owner_from_allowed_list).resolve(d, bool(recipients))
        print(json.dumps(draft_entry(d, owner, recipients, cfg.embedded_capability_names),
                         indent=2))
        return 0
    if not cfg.registry_file:
        print("registry_file is not configured")
        return 1
    reg = Registry(cfg.registry_file, cfg.registry_public_key_file
                   if cfg.require_registry_signatures else None)
    reg.load()
    report, failing = [], 0
    for pid, why in reg.invalid.items():
        report.append({"packageId": pid, "result": "invalid_entry", "reason": why})
        failing += 1
    for pid in reg.entries:
        try:
            d = graph.get_package(pid)
        except GraphError as exc:
            report.append({"packageId": pid, "result": "error", "error": str(exc)})
            failing += 1
            continue
        approval = reg.lookup(d)
        recipients = sharing_recipients(d, cfg)
        if not approval.valid:
            report.append({"packageId": pid, "displayName": d.get("displayName"),
                           "result": "approval_not_valid", "reason": approval.reason})
            failing += 1
            continue
        ev = evaluate(d, approval.entry, recipients, cfg.embedded_capability_names,
                      cfg.drift_fail_closed)
        failing += 0 if ev.compliant else 1
        report.append({"packageId": pid, "displayName": d.get("displayName"),
                       "result": "compliant" if ev.compliant else "violation",
                       "isBlocked": d.get("isBlocked"), "configHash": ev.config_hash,
                       "violations": [f.as_dict() for f in ev.violations],
                       "warnings": [f.as_dict() for f in ev.warnings]})
    print(json.dumps({"generatedAt": datetime.now(timezone.utc).isoformat(),
                      "entries": len(report), "failing": failing, "results": report}, indent=2))
    return 0 if failing == 0 else 3


def email_template_command(args: Any) -> int:
    from .mail import Mailer, TemplateError, export_templates, load_template_dir, preview_emails
    if args.export_email_templates:
        for name in export_templates(args.export_email_templates):
            print(name)
        return 0
    folder = args.check_email_templates or args.templates
    try:
        templates = load_template_dir(folder) if folder else {}
    except TemplateError as exc:
        print(f"Template problems: {exc}")
        return 1
    if args.check_email_templates:
        print(f"OK: {len(templates)} customised template(s): {', '.join(sorted(templates)) or 'none'}")
        return 0
    branding: dict[str, Any] = {}
    policy = helpdesk = None
    if args.config:
        with open(args.config, encoding="utf-8") as fh:
            raw = json.load(fh)
        branding = {"brand_name": raw.get("email_brand_name", "ShareGuard for Agent Builder"),
                    "subject_prefix": raw.get("email_subject_prefix", ""),
                    "footer": raw.get("email_footer"),
                    "button_colour": raw.get("email_button_colour", "#0f6cbd")}
        policy, helpdesk = raw.get("policy_url"), raw.get("helpdesk_contact")
        if not folder and raw.get("email_templates_dir"):
            templates = load_template_dir(raw["email_templates_dir"])
    mailer = Mailer(None, "preview@example.com", ["admins@example.com"], policy, helpdesk,
                    templates=templates, **branding)
    for name in preview_emails(mailer, args.preview_emails):
        print(name)
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    from . import __version__
    parser.add_argument("--version", action="version", version=f"absg {__version__}")
    parser.add_argument("--config", help="Path to JSON config file")
    parser.add_argument("--once", action="store_true", help="Run a single cycle and exit")
    parser.add_argument("--dry-run", action="store_true", help="Report only; make no changes")
    parser.add_argument("--log-level", default=os.environ.get("ABSG_LOG_LEVEL", "INFO"))
    parser.add_argument("--login-delegated", action="store_true",
                        help="Sign in the delegated service account (device code) and exit")
    reg = parser.add_argument_group("registry commands (governance process)")
    reg.add_argument("--registry-keygen", metavar="DIR",
                     help="Create an Ed25519 signing key pair in DIR (keep the private key offline)")
    reg.add_argument("--registry-draft", metavar="PACKAGE_ID",
                     help="Print a draft registry entry with a baseline taken from the live agent")
    reg.add_argument("--registry-sign", metavar="ENTRY_FILE",
                     help="Sign a completed registry entry (JSON) and print it")
    reg.add_argument("--key", metavar="PRIVATE_KEY", help="Private key for --registry-sign")
    reg.add_argument("--algorithm", choices=["ed25519", "es256", "rs256"], default="ed25519",
                     help="Key algorithm for --registry-keygen (ed25519 by default; es256 matches Key Vault signing)")
    reg.add_argument("--registry-export-jwk", metavar="PEM",
                     help="Print an RSA key (PEM) as a JWK and exit")
    reg.add_argument("--registry-validate", action="store_true",
                     help="Validate every registry entry against the live agents, print a report, exit")
    audit_cmds = parser.add_argument_group("audit commands (do not contact Graph)")
    audit_cmds.add_argument("--verify-audit", metavar="AUDIT_FILE",
                            help="Verify the audit file's hash chain and exit (1 if broken)")
    audit_cmds.add_argument("--verify-audit-store", action="store_true",
                            help="Verify the audit chain where --config stores it (SharePoint or file)")
    audit_cmds.add_argument("--audit-history", metavar="AUDIT_FILE",
                            help="Print audit records as JSON Lines, filtered by the options below")
    audit_cmds.add_argument("--package", help="Filter history by package ID")
    audit_cmds.add_argument("--case", help="Filter history by case ID")
    audit_cmds.add_argument("--event", help="Filter history by event type, e.g. block")
    audit_cmds.add_argument("--since", help="Filter history from an ISO date/time, e.g. 2026-11-01")
    mail_cmds = parser.add_argument_group("email template commands (do not contact Graph)")
    mail_cmds.add_argument("--export-email-templates", metavar="DIR",
                           help="Write the default email templates to DIR, to customise")
    mail_cmds.add_argument("--check-email-templates", metavar="DIR",
                           help="Check customised templates in DIR (exit 1 on problems)")
    mail_cmds.add_argument("--preview-emails", metavar="OUT_DIR",
                           help="Render every email with sample data into OUT_DIR; uses --templates "
                                "and the branding in --config, if given")
    mail_cmds.add_argument("--templates", metavar="DIR", help="Customised templates for --preview-emails")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.export_email_templates or args.check_email_templates or args.preview_emails:
        return email_template_command(args)

    if args.verify_audit:
        v = verify_audit_log(args.verify_audit)
        print(json.dumps(v.__dict__))
        return 0 if v.ok else 1
    if args.registry_keygen:
        from .registry import generate_keypair
        os.makedirs(args.registry_keygen, exist_ok=True)
        priv, pub = generate_keypair(args.algorithm)
        priv_path = os.path.join(args.registry_keygen, "absg_registry_signing_key.pem")
        pub_path = os.path.join(args.registry_keygen, "absg_registry_public_key.pem")
        fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(priv)
        with open(pub_path, "wb") as fh:
            fh.write(pub)
        print(f"Private key: {priv_path} (governance only; never deploy with the daemon)")
        print(f"Public key:  {pub_path} (set registry_public_key_file to this)")
        return 0
    if args.registry_export_jwk:
        from .registry import rsa_jwk
        with open(args.registry_export_jwk, "rb") as fh:
            print(json.dumps(rsa_jwk(fh.read())))
        return 0
    if args.registry_sign:
        from .registry import sign_entry
        if not args.key:
            print("--registry-sign needs --key PRIVATE_KEY")
            return 1
        with open(args.registry_sign, encoding="utf-8") as fh:
            entry = json.load(fh)
        unfinished = [k for k, v in (entry.get("approval") or {}).items()
                      if isinstance(v, str) and v.startswith("<")]
        if unfinished:
            print(f"Complete these approval fields before signing: {', '.join(unfinished)}")
            return 1
        with open(args.key, "rb") as fh:
            print(json.dumps(sign_entry(entry, fh.read()), indent=2))
        return 0
    if args.audit_history:
        for rec in audit_history(args.audit_history, args.package, args.event, args.since,
                                 case_id=args.case):
            print(json.dumps(rec, sort_keys=True))
        return 0

    logging.basicConfig(level=args.log_level.upper(),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    cfg = Config.load(args.config)
    if args.verify_audit_store:
        from .runtime import verify_audit
        v = verify_audit(cfg)
        print(json.dumps(v))
        return 0 if v["ok"] else 1
    if args.login_delegated:
        if not cfg.delegated_client_id:
            print("Set delegated_client_id in the config first.")
            return 1
        return login_delegated(cfg)
    if args.registry_draft or args.registry_validate:
        return registry_report(cfg, args.registry_draft)
    if args.dry_run:
        cfg.dry_run = True
    if cfg.dry_run:
        log.warning("DRY RUN: no agents will be blocked or unblocked, and no email sent")

    from .ack import AckServer
    from .runtime import build, safe_config

    parts = build(cfg, "guard")
    audit, guard = parts.audit, parts.guard
    if cfg.storage_backend == "file" and os.path.exists(cfg.audit_file):
        v = verify_audit_log(cfg.audit_file)
        if not v.ok:
            log.critical("Audit chain broken at seq %s: %s", v.first_bad_seq, v.problem)
            make_webhook_notifier(cfg.notify_webhook_url)(
                "audit_integrity_failure", {"firstBadSeq": v.first_bad_seq, "problem": v.problem})
            return 2  # refuse to run on a tampered trail
    safe_cfg = safe_config(cfg)
    audit.record("daemon_start", dryRun=cfg.dry_run, config=safe_cfg,
                 configHash=hashlib.sha256(_canonical(safe_cfg)).hexdigest())

    wake = threading.Event()
    server = None
    if cfg.ack_enabled and cfg.ack_base_url and cfg.storage_backend == "file":
        server = AckServer(
            parts.signer, parts.acks,
            audit=lambda event, **f: audit.record(event, source="ack_endpoint", **f),
            host=cfg.ack_listen_host, port=cfg.ack_listen_port, path=cfg.ack_path,
            identity_header=cfg.ack_identity_header,
            require_identity=cfg.ack_require_identity, on_ack=wake.set,
            poll_minutes=max(1, cfg.poll_interval_seconds // 60))
        server.start()

    stop = threading.Event()

    def _stop(*_: Any) -> None:
        stop.set()
        wake.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _stop)

    while not stop.is_set():
        wake.clear()
        try:
            guard.run_cycle()
        except Exception:  # keep the daemon alive; next cycle retries
            log.exception("Cycle failed")
        if args.once:
            break
        # Sleep until the next poll, or wake early when an acknowledgement arrives.
        wake.wait(cfg.poll_interval_seconds)
    if server:
        server.stop()
    audit.record("daemon_stop", dryRun=cfg.dry_run)
    audit.flush()
    log.info("Stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
