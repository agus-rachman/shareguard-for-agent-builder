# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""Builds a ready-to-run guard from the configuration: local files for a
self-hosted daemon, or SharePoint + Key Vault + managed identities for the Azure
deployment (``storage_backend: "sharepoint"``)."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import uuid
from dataclasses import dataclass
from typing import Any

from .core import (AuditLog, Config, GraphClient, Guard, StateStore, _canonical,
                   build_delegated_provider, make_webhook_notifier, verify_audit_lines)

log = logging.getLogger("absg.runtime")
SECRET_KEYS = ("client_secret", "cert_path", "cert_thumbprint", "notify_webhook_url", "ack_secret")


@dataclass
class Components:
    cfg: Config
    graph: GraphClient
    state: StateStore
    audit: AuditLog
    guard: Guard
    vault: Any = None
    acks: Any = None
    signer: Any = None
    ops_site: Any = None


def key_vault(cfg: Config):
    if not cfg.key_vault_url:
        return None
    from .cloud import KEY_VAULT_RESOURCE, KeyVault, managed_identity_provider
    return KeyVault(cfg.key_vault_url,
                    managed_identity_provider(KEY_VAULT_RESOURCE, cfg.client_id if cfg.use_managed_identity else None))


def registry_public_key(cfg: Config, vault: Any) -> Any:
    if cfg.registry_public_key_file:
        with open(cfg.registry_public_key_file, "rb") as fh:
            return fh.read()
    if cfg.registry_public_key:
        return cfg.registry_public_key
    if vault and cfg.registry_key_name:
        return vault.public_jwk(cfg.registry_key_name)   # public part only; signing stays in the HSM
    return None


def actor(cfg: Config, role: str) -> dict:
    return {"clientId": cfg.client_id, "tenantId": cfg.tenant_id, "role": role,
            "host": os.environ.get("WEBSITE_HOSTNAME") or socket.gethostname(),
            "instanceId": os.environ.get("WEBSITE_INSTANCE_ID", uuid.uuid4().hex)[:32]}


def audit_log(cfg: Config, role: str, ops_site: Any = None, prefix: str = "absg-audit-") -> AuditLog:
    sink = None
    if cfg.audit_to_log:
        audit_logger = logging.getLogger("absg.audit")
        sink = lambda rec: audit_logger.info("audit %s", json.dumps(rec, sort_keys=True))  # noqa: E731
    if cfg.storage_backend == "sharepoint":
        from .sharepoint import SharePointAuditBackend
        backend = SharePointAuditBackend(ops_site, cfg.sharepoint_audit_library, cfg.sharepoint_audit_folder,
                                         prefix=prefix, retention_label=cfg.audit_retention_label)
        return AuditLog(actor=actor(cfg, role), sink=sink, backend=backend)
    path = cfg.audit_file if prefix == "absg-audit-" else cfg.audit_file.replace(".jsonl", f".{role}.jsonl")
    return AuditLog(path, actor=actor(cfg, role), sink=sink)


def build(cfg: Config, role: str = "guard") -> Components:
    """Everything the guard needs, from the configuration."""
    from .ack import AckStore, AckTokenSigner
    from .mail import Mailer, OwnerResolver
    from .registry import Registry

    graph = GraphClient(cfg)
    vault = key_vault(cfg)
    ops_site = reg_site = None
    owner_map: dict = {}
    if cfg.storage_backend == "sharepoint":
        from .sharepoint import SharePointJsonDocument, SharePointSite
        ops_site = SharePointSite(graph, cfg.sharepoint_operations_site_id)
        reg_site = SharePointSite(graph, cfg.sharepoint_registry_site_id) if cfg.sharepoint_registry_site_id else None
        state = StateStore(backend=SharePointJsonDocument(ops_site, cfg.sharepoint_state_library,
                                                          cfg.sharepoint_state_path))
        if cfg.sharepoint_owner_map_path:
            owner_map = SharePointJsonDocument(ops_site, cfg.sharepoint_state_library,
                                               cfg.sharepoint_owner_map_path).load() or {}
    else:
        state = StateStore(cfg.state_file)
    audit = audit_log(cfg, role, ops_site)

    mailer = Mailer(graph, cfg.mail_sender, cfg.admin_emails, cfg.policy_url,
                    cfg.helpdesk_contact, dry_run=cfg.dry_run, templates=email_templates(cfg, ops_site),
                    **mail_branding(cfg))
    resolver = OwnerResolver(cfg.owner_fields, cfg.owner_map_file, state.package_owners,
                             cfg.infer_owner_from_allowed_list, owner_map=owner_map)

    signer = acks = None
    if cfg.ack_enabled:
        secret = cfg.ack_secret or (vault.get_secret(cfg.ack_secret_name) if vault else None)
        signer = AckTokenSigner(secret or "", cfg.ack_token_ttl_hours)
        if cfg.storage_backend == "sharepoint":
            from .sharepoint import SharePointAckStore

            def resolve_user(upn: str) -> str | None:
                try:
                    return graph.request("GET", f"/users/{upn}?$select=id").json().get("id")
                except Exception:
                    return None
            acks = SharePointAckStore(ops_site, signer, resolve_user, cfg.sharepoint_acks_list)
        else:
            acks = AckStore(cfg.ack_store_file)

    delegated = None
    if cfg.delegated_client_id:
        cache_store = None
        if vault:
            from .cloud import KeyVaultTokenCache
            cache_store = KeyVaultTokenCache(vault, cfg.delegated_cache_secret_name)
        delegated = GraphClient(cfg, token_provider=build_delegated_provider(cfg, cache_store))

    registry = None
    public_key = registry_public_key(cfg, vault) if cfg.require_registry_signatures else None
    if cfg.storage_backend == "sharepoint" and reg_site:
        from .sharepoint import SharePointRegistrySource
        registry = Registry(source=SharePointRegistrySource(reg_site, cfg.sharepoint_registry_list),
                            public_key=public_key)
    elif cfg.registry_file:
        registry = Registry(cfg.registry_file, public_key=public_key)

    guard = Guard(cfg, graph, state, make_webhook_notifier(cfg.notify_webhook_url),
                  audit=audit, mailer=mailer, owner_resolver=resolver, signer=signer,
                  acks=acks, delegated_graph=delegated, registry=registry,
                  archive=archive_store(cfg, graph, ops_site))
    return Components(cfg, graph, state, audit, guard, vault=vault, acks=acks, signer=signer,
                      ops_site=ops_site)


def mail_branding(cfg: Config) -> dict:
    return {"brand_name": cfg.email_brand_name, "subject_prefix": cfg.email_subject_prefix,
            "footer": cfg.email_footer, "button_colour": cfg.email_button_colour}


def email_templates(cfg: Config, ops_site: Any = None) -> dict:
    """Customised email templates from a local folder or the operations site.

    A broken template stops the guard from starting (raises TemplateError), so a typo
    can't silently send owners a half-empty email."""
    from .mail import load_template_dir, load_templates
    if cfg.email_templates_dir:
        return load_template_dir(cfg.email_templates_dir)
    if cfg.storage_backend == "sharepoint" and cfg.sharepoint_templates_folder and ops_site is not None:
        files = {}
        for child in ops_site.children(cfg.sharepoint_state_library, cfg.sharepoint_templates_folder):
            name = child.get("name", "")
            if name.lower().endswith(".html"):
                content, _ = ops_site.download(cfg.sharepoint_state_library,
                                               f"{cfg.sharepoint_templates_folder.strip('/')}/{name}")
                files[name] = (content or b"").decode("utf-8")
        return load_templates(files)
    return {}


def archive_store(cfg: Config, graph: Any, ops_site: Any = None) -> Any:
    """Where retired agents are archived (None when archiving is off)."""
    if not cfg.inactivity_days or cfg.archive_after_days is None:
        return None
    from .archive import FileArchiveStore, SharePointArchiveStore
    if cfg.storage_backend == "sharepoint":
        from .sharepoint import SharePointSite
        site = (SharePointSite(graph, cfg.sharepoint_archive_site_id) if cfg.sharepoint_archive_site_id
                else ops_site)
        return SharePointArchiveStore(site, cfg.sharepoint_archive_library, cfg.archive_retention_label)
    return FileArchiveStore(cfg.archive_dir)


def safe_config(cfg: Config) -> dict:
    return {k: v for k, v in cfg.__dict__.items() if k not in SECRET_KEYS}


def run_guard_cycle(cfg: Config | None = None) -> dict:
    """One guard cycle (the Azure Functions timer calls this)."""
    cfg = cfg or Config.load(None)
    parts = build(cfg, "guard")
    safe = safe_config(cfg)
    parts.audit.record("invocation_start", dryRun=cfg.dry_run,
                       configHash=hashlib.sha256(_canonical(safe)).hexdigest())
    result = parts.guard.run_cycle()
    return parts.guard._summary(result)


def verify_audit(cfg: Config | None = None, prefix: str = "absg-audit-") -> dict:
    """Verify the whole audit chain where it is stored (file or SharePoint)."""
    cfg = cfg or Config.load(None)
    if cfg.storage_backend == "sharepoint":
        from .sharepoint import SharePointAuditBackend, SharePointSite
        site = SharePointSite(GraphClient(cfg), cfg.sharepoint_operations_site_id)
        lines = SharePointAuditBackend(site, cfg.sharepoint_audit_library, cfg.sharepoint_audit_folder,
                                       prefix=prefix).iter_lines()
    else:
        lines = open(cfg.audit_file, encoding="utf-8")   # noqa: SIM115 - consumed below
    try:
        return verify_audit_lines(lines).__dict__
    finally:
        if hasattr(lines, "close"):
            lines.close()
