# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""
Approved-agent registry and configuration drift detection for ShareGuard for Agent Builder (ABSG).

The registry is owned by the governance process, outside the daemon. An
agent that passes its risk assessment gets a registry entry recording:

  * who approved it, when, the risk rating, and the approval criteria
    assessed (with results and evidence links);
  * the audience it may be shared with;
  * a **baseline**: a normalised snapshot of the agent's configuration
    (knowledge sources, capabilities, actions, embedded files, instructions)
    taken from the live definition at approval time;
  * optional policy constraints and an expiry or review date.

Entries are signed with Ed25519. Governance holds the private key and the
daemon has only the public key, so editing the registry file isn't enough to
approve an agent: unsigned or altered entries are ignored.

Every cycle, the daemon re-reads each shared, approved agent's live definition
and compares it with the baseline. A violation (for example, embedded files
added to an agent approved for SharePoint knowledge only) blocks the agent.
It stays blocked until the configuration matches what was approved again,
or until sharing is removed.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("absg.registry")

DEFAULT_EMBEDDED_CAPABILITY_NAMES = ["EmbeddedKnowledge"]
# Capabilities that grant access to organisational or external content.
KNOWLEDGE_CAPABILITIES = {"OneDriveAndSharePoint", "WebSearch", "GraphConnectors",
                          "TeamsMessages", "Email", "Dataverse", "People", "Meetings"}


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


def sha256(obj: Any) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


# --------------------------------------------------------------------------
# Configuration profile: a normalised view of the agent definition
# --------------------------------------------------------------------------
def _norm_url(u: str) -> str:
    return (u or "").strip().rstrip("/").lower()


def declarative_definitions(detail: dict) -> list[dict]:
    """Parse declarativeAgent element definitions from a package detail."""
    out = []
    for group in detail.get("elementDetails") or []:
        if str(group.get("elementType", "")).lower() not in ("declarativeagent",
                                                             "declarativecopilots"):
            continue
        for element in group.get("elements") or []:
            raw = element.get("definition")
            if not raw:
                continue
            try:
                out.append(json.loads(raw) if isinstance(raw, str) else raw)
            except json.JSONDecodeError:
                log.warning("Unparseable definition in %s", detail.get("id"))
    return out


def build_profile(detail: dict,
                  embedded_names: list[str] | None = None) -> dict | None:
    """Normalise the agent definition into a comparable profile.

    Returns None when no declarative agent definition is available.
    """
    defs = declarative_definitions(detail)
    if not defs:
        return None
    embedded_names = embedded_names or DEFAULT_EMBEDDED_CAPABILITY_NAMES
    d = defs[0]
    caps: dict[str, dict] = {}
    embedded: list[str] = []
    for cap in d.get("capabilities") or []:
        name = cap.get("name", "")
        if name in embedded_names:
            for f in cap.get("files") or cap.get("items") or []:
                embedded.append(str(f.get("name") or f.get("file") or f.get("id") or f)
                                if isinstance(f, dict) else str(f))
            if not embedded:
                embedded.append("<embedded knowledge present>")
            continue
        if name == "OneDriveAndSharePoint":
            urls = sorted(_norm_url(i.get("url")) for i in cap.get("items_by_url") or [])
            ids = sorted(sha256(i) for i in cap.get("items_by_sharepoint_ids") or [])
            caps[name] = {"urls": urls, "itemIds": ids, "unscoped": not urls and not ids}
        elif name == "WebSearch":
            sites = sorted(_norm_url(s.get("url")) for s in cap.get("sites") or [])
            caps[name] = {"sites": sites, "unscoped": not sites}
        elif name == "GraphConnectors":
            conns = sorted(c.get("connection_id", "") for c in cap.get("connections") or [])
            caps[name] = {"connections": conns, "unscoped": not conns}
        elif name == "TeamsMessages":
            urls = sorted(_norm_url(u.get("url")) for u in cap.get("urls") or [])
            caps[name] = {"urls": urls, "unscoped": not urls}
        elif name == "Email":
            folders = sorted(f.get("folder_id", "") for f in cap.get("folders") or [])
            caps[name] = {"folders": folders, "sharedMailbox": cap.get("shared_mailbox"),
                          "unscoped": not folders and not cap.get("shared_mailbox")}
        elif name == "Dataverse":
            caps[name] = {"knowledgeSources": sorted(sha256(k) for k in
                                                     cap.get("knowledge_sources") or [])}
        else:
            # Presence-only capabilities (CodeInterpreter, GraphicArt, People, ...).
            rest = {k: v for k, v in cap.items() if k != "name"}
            caps[name] = {"config": sha256(rest)} if rest else {}
    if d.get("sensitivity_label") and not embedded:
        # Schema: sensitivity_label is only allowed when the agent has embedded files.
        embedded.append("<embedded files indicated by sensitivity_label>")
    return {
        "capabilities": caps,
        "embeddedFiles": sorted(embedded),
        "actions": sorted(a.get("id", "") for a in d.get("actions") or []),
        "workerAgents": sorted(sha256(w) for w in d.get("worker_agents") or []),
        "userOverrides": sha256(d.get("user_overrides")) if d.get("user_overrides") else None,
        "behaviorOverrides": sha256(d.get("behavior_overrides"))
        if d.get("behavior_overrides") else None,
        "instructionsHash": hashlib.sha256((d.get("instructions") or "").encode()).hexdigest(),
    }


# --------------------------------------------------------------------------
# Registry entries and signatures
# --------------------------------------------------------------------------
def _signable(entry: dict) -> dict:
    return {k: v for k, v in entry.items() if k != "signature"}


def _load_private(private_key_pem: bytes):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    return load_pem_private_key(private_key_pem, password=None)


def _sign_bytes(key, data: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(data, padding.PKCS1v15(), hashes.SHA256())   # RS256
    if isinstance(key, ec.EllipticCurvePrivateKey):
        # ES256 as JWS and Azure Key Vault encode it: raw r || s, 32 bytes each
        r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return key.sign(data)                                             # Ed25519


SIGNATURE_ALGORITHMS = {"ed25519": "Ed25519", "rsa": "RS256", "ec": "ES256"}


def _algorithm_name(key) -> str:
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return "RS256"
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return "ES256"
    return "Ed25519"


def signing_payload(entry: dict) -> bytes:
    """The exact bytes a registry signature covers (canonical JSON without ``signature``)."""
    return canonical(_signable(entry))


def attach_signature(entry: dict, signature: bytes, algorithm: str) -> dict:
    """Return a copy of ``entry`` carrying ``signature`` (raw bytes) made over
    ``signing_payload`` of that same entry. Used by remote signers such as Key Vault."""
    signed = copy.deepcopy(entry)
    signed.pop("signature", None)
    if signed.get("signatureAlgorithm") != algorithm:
        raise ValueError("set signatureAlgorithm on the entry before computing the payload")
    signed["signature"] = base64.b64encode(signature).decode()
    return signed


def sign_entry(entry: dict, private_key_pem: bytes) -> dict:
    """Sign a registry entry with an Ed25519, RSA (RS256) or P-256 (ES256) private key in PEM form.

    ``signatureAlgorithm`` is recorded inside the signed content, so it can't be swapped later."""
    key = _load_private(private_key_pem)
    signed = copy.deepcopy(entry)
    signed.pop("signature", None)
    signed["signatureAlgorithm"] = _algorithm_name(key)
    signed["signature"] = base64.b64encode(_sign_bytes(key, signing_payload(signed))).decode()
    return signed


def _load_public(public_key: bytes | str | dict):
    """Accept a PEM public key (Ed25519, RSA or P-256) or an RSA / EC P-256 public JWK
    (dict or JSON text, as Azure Key Vault returns it)."""
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    if isinstance(public_key, (bytes, str)) and public_key.strip().startswith(b"{" if isinstance(public_key, bytes) else "{"):
        public_key = json.loads(public_key)
    if isinstance(public_key, dict):
        kty = public_key.get("kty", "").upper()
        if kty in ("RSA", "RSA-HSM"):
            n = int.from_bytes(_b64url_decode(public_key["n"]), "big")
            e = int.from_bytes(_b64url_decode(public_key["e"]), "big")
            return rsa.RSAPublicNumbers(e, n).public_key()
        if kty in ("EC", "EC-HSM"):
            if public_key.get("crv") != "P-256":
                raise ValueError("only P-256 EC keys are supported")
            x = int.from_bytes(_b64url_decode(public_key["x"]), "big")
            y = int.from_bytes(_b64url_decode(public_key["y"]), "big")
            return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        raise ValueError(f"unsupported JWK key type {kty!r}")
    return load_pem_public_key(public_key if isinstance(public_key, bytes) else public_key.encode())


def verify_entry(entry: dict, public_key_pem: bytes | dict | None) -> bool:
    if public_key_pem is None:
        return True  # signatures not enforced
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    sig = entry.get("signature")
    if not sig:
        return False
    try:
        key = _load_public(public_key_pem)
        declared = entry.get("signatureAlgorithm")
        if declared and declared != _algorithm_name(key):
            return False      # the entry claims a different algorithm than the trusted key
        data, raw = signing_payload(entry), base64.b64decode(sig)
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(raw, data, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(key, ec.EllipticCurvePublicKey):
            if len(raw) != 64:
                return False
            der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
            key.verify(der, data, ec.ECDSA(hashes.SHA256()))
        else:
            key.verify(raw, data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def generate_keypair(algorithm: str = "ed25519") -> tuple[bytes, bytes]:
    """Create a signing key pair: ``ed25519`` (default), ``es256`` (P-256, the
    algorithm the Azure deployment signs with in Key Vault) or ``rs256`` (RSA-3072)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if algorithm.lower() == "rs256":
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    elif algorithm.lower() == "es256":
        key = ec.generate_private_key(ec.SECP256R1())
    elif algorithm.lower() == "ed25519":
        key = Ed25519PrivateKey.generate()
    else:
        raise ValueError("algorithm must be 'ed25519', 'es256' or 'rs256'")
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return private, public


def _b64url(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def rsa_jwk(pem: bytes) -> dict:
    """Export an RSA key (private or public PEM) as a JWK.

    A private key yields a private JWK (keep it secret: it goes only into the
    signer's ABSG Engine connection); a public key yields a public JWK."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

    if b"PRIVATE KEY" in pem:
        key = load_pem_private_key(pem, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("not an RSA key; generate one with --algorithm rs256")
        nums = key.private_numbers()
        pub = nums.public_numbers
        return {"kty": "RSA", "alg": "RS256", "n": _b64url(pub.n), "e": _b64url(pub.e), "d": _b64url(nums.d),
                "p": _b64url(nums.p), "q": _b64url(nums.q), "dp": _b64url(nums.dmp1),
                "dq": _b64url(nums.dmq1), "qi": _b64url(nums.iqmp)}
    key = load_pem_public_key(pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("not an RSA key; generate one with --algorithm rs256")
    pub = key.public_numbers()
    return {"kty": "RSA", "alg": "RS256", "n": _b64url(pub.n), "e": _b64url(pub.e)}


@dataclass
class Approval:
    entry: dict
    valid: bool
    reason: str            # "approved" or why the entry is not usable


class FileRegistrySource:
    """``{"agents": [entry, ...]}`` in a local JSON file."""

    def __init__(self, path: str):
        self.path = path

    def fetch(self) -> tuple[list[Any], str]:
        if not os.path.exists(self.path):
            # A missing file is an error, not "no approvals": keeps the last good copy,
            # so deleting the file can't trigger a mass block of approved agents.
            raise FileNotFoundError(f"registry file not found: {self.path}")
        with open(self.path, "rb") as fh:
            raw = fh.read()
        data = json.loads(raw or b"{}")          # raises on corrupt file
        return data.get("agents", []), hashlib.sha256(raw).hexdigest()


class Registry:
    """Loads the registry each cycle (a file, or a source such as a SharePoint list)
    and checks entry signatures."""

    def __init__(self, path: str | None = None, public_key_file: str | None = None,
                 source: Any = None, public_key: bytes | str | dict | None = None):
        self.path = path
        self.source = source or FileRegistrySource(path or "")
        self.public_key = public_key
        if public_key_file:
            with open(public_key_file, "rb") as fh:
                self.public_key = fh.read()
        self.entries: dict[str, dict] = {}
        self.invalid: dict[str, str] = {}
        self.file_hash: str | None = None

    def load(self) -> None:
        """Parse the registry. On any error the previous (last good) copy is
        kept and the exception is raised for the caller to audit."""
        agents, raw_hash = self.source.fetch()
        entries: dict[str, dict] = {}
        invalid: dict[str, str] = {}
        for entry in agents:
            if isinstance(entry, tuple):          # (key, None): an item that isn't valid JSON
                invalid[entry[0]] = "entry is not valid JSON"
                continue
            pid = entry.get("packageId")
            if not pid:
                continue
            if not verify_entry(entry, self.public_key):
                invalid[pid] = "signature missing or invalid"
                continue
            entries[pid] = entry
        self.entries, self.invalid = entries, invalid
        self.file_hash = raw_hash

    def lookup(self, detail: dict) -> Approval | None:
        pid = detail.get("id")
        if pid in self.invalid:
            return Approval({"packageId": pid}, False, self.invalid[pid])
        entry = self.entries.get(pid)
        if entry is None:
            return None
        if entry.get("manifestId") and detail.get("manifestId") \
                and entry["manifestId"] != detail["manifestId"]:
            return Approval(entry, False, "manifestId does not match the approved agent")
        status = entry.get("status", "approved")
        if status != "approved":
            return Approval(entry, False, f"registry status is '{status}'")
        expires = (entry.get("approval") or {}).get("expiresAt")
        if expires and expires < datetime.now(timezone.utc).isoformat():
            return Approval(entry, False, f"approval expired on {expires}")
        return Approval(entry, True, "approved")

    def entry_hashes(self) -> dict[str, str]:
        return {pid: sha256(e) for pid, e in self.entries.items()}


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------
@dataclass
class Finding:
    rule: str
    severity: str          # "block" or "warn"
    message: str
    detail: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"rule": self.rule, "severity": self.severity, "message": self.message,
                **({"detail": self.detail} if self.detail else {})}


@dataclass
class Evaluation:
    profile: dict | None
    config_hash: str | None
    findings: list[Finding]

    @property
    def violations(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "block"]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "warn"]

    @property
    def compliant(self) -> bool:
        return not self.violations

    def fingerprint(self) -> str:
        return sha256([self.config_hash, sorted(f.rule + f.message for f in self.findings)])


def _principal_key(p: dict) -> tuple[str, str]:
    return str(p.get("resourceType", "")).lower(), str(p.get("resourceId", "")).lower()


def entry_owners(entry: dict) -> list[str]:
    """Named owners of a registry entry (``owners``; older entries carry a single ``ownerId``)."""
    owners = [o for o in (entry.get("owners") or []) if o]
    if not owners and entry.get("ownerId"):
        owners = [entry["ownerId"]]
    return owners


def _ownership_findings(entry: dict, ownership: dict, policy: dict) -> list[Finding]:
    """Owner rules: every owner the platform reports must be a named owner in the
    registry, and at least one named owner must still have an active account."""
    out: list[Finding] = []
    named = {o.lower() for o in entry_owners(entry)}
    reported = ownership.get("reported")
    if reported is not None and policy.get("requireRegisteredOwners", True):
        extra = sorted({o for o in reported if o and o.lower() not in named})
        if extra:
            out.append(Finding("OWNER-UNREGISTERED", "block",
                               "The agent has owners who aren't named in the approval",
                               {"unregisteredOwners": extra}))
    inactive = {o.lower() for o in (ownership.get("inactive") or [])}
    if named and policy.get("requireActiveOwner", True):
        gone = sorted(o for o in entry_owners(entry) if o.lower() in inactive)
        if len(gone) == len(named):
            out.append(Finding("OWNER-NONE-ACTIVE", "block",
                               "None of the agent's named owners has an active account",
                               {"inactiveOwners": gone}))
        elif gone:
            out.append(Finding("OWNER-INACTIVE", "warn",
                               "Some of the agent's named owners no longer have an active account",
                               {"inactiveOwners": gone}))
    return out


def evaluate(detail: dict, entry: dict, recipients: list[dict],
             embedded_names: list[str] | None = None,
             fail_closed: bool = True, ownership: dict | None = None) -> Evaluation:
    """Compare the live agent with its approved registry entry.

    ``ownership`` (optional) = {"reported": owner ids the platform reports, or None when
    it reports none; "inactive": owner ids whose accounts are deleted or disabled}."""
    findings: list[Finding] = []
    profile = build_profile(detail, embedded_names)
    config_hash = sha256(profile) if profile is not None else None
    policy = entry.get("policy") or {}
    baseline = (entry.get("baseline") or {}).get("profile")
    mode = policy.get("driftMode", "baseline")

    # 1. Sharing must stay within the approved audience.
    approved = {_principal_key(p) for p in (entry.get("sharing") or {}).get("allowedPrincipals", [])}
    extra = [r for r in recipients if _principal_key(r) not in approved]
    if extra:
        findings.append(Finding("SHARE-SCOPE", "block",
                                "Shared beyond the approved audience",
                                {"unapprovedRecipients": extra}))

    if ownership is not None:
        findings += _ownership_findings(entry, ownership, policy)

    if profile is None:
        if fail_closed:
            findings.append(Finding("CONFIG-UNREADABLE", "block",
                                    "Agent definition could not be read, so it can't be validated"))
        return Evaluation(None, None, findings)

    # 2. Hard rules (both modes).
    if profile["embeddedFiles"] and not policy.get("allowEmbeddedFiles", False):
        base_files = (baseline or {}).get("embeddedFiles", [])
        if profile["embeddedFiles"] != base_files:
            findings.append(Finding("EMBEDDED-FILES", "block",
                                    "Embedded knowledge files were added or changed",
                                    {"embeddedFiles": profile["embeddedFiles"],
                                     "approved": base_files}))
    for name, scope in profile["capabilities"].items():
        if scope.get("unscoped") and name in KNOWLEDGE_CAPABILITIES \
                and name not in policy.get("allowUnscoped", []):
            base_scope = (baseline or {}).get("capabilities", {}).get(name, {})
            if not base_scope.get("unscoped"):
                findings.append(Finding("UNSCOPED-KNOWLEDGE", "block",
                                        f"{name} is unscoped (searches all available content)",
                                        {"capability": name}))

    # 3. Drift from the approved baseline, or policy constraints.
    if mode == "baseline":
        if baseline is None:
            findings.append(Finding("NO-BASELINE", "block",
                                    "Registry entry has no configuration baseline"))
        else:
            findings += _baseline_drift(baseline, profile, policy)
    else:
        findings += _policy_constraints(profile, policy)

    # De-duplicate (a hard rule and a drift rule can describe the same change).
    seen, unique = set(), []
    for f in findings:
        key = (f.rule, f.message)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return Evaluation(profile, config_hash, unique)


def _baseline_drift(base: dict, live: dict, policy: dict) -> list[Finding]:
    out: list[Finding] = []
    bcaps, lcaps = base.get("capabilities", {}), live.get("capabilities", {})
    for name in sorted(set(lcaps) - set(bcaps)):
        out.append(Finding("DRIFT-CAPABILITY-ADDED", "block",
                           f"Capability '{name}' was added", {"capability": name,
                                                              "live": lcaps[name]}))
    for name in sorted(set(bcaps) - set(lcaps)):
        out.append(Finding("DRIFT-CAPABILITY-REMOVED", "warn",
                           f"Capability '{name}' was removed", {"capability": name}))
    for name in sorted(set(bcaps) & set(lcaps)):
        if bcaps[name] != lcaps[name]:
            out.append(Finding("DRIFT-SCOPE-CHANGED", "block",
                               f"Scope of '{name}' changed",
                               {"capability": name, "approved": bcaps[name],
                                "live": lcaps[name]}))
    if live.get("embeddedFiles") != base.get("embeddedFiles"):
        out.append(Finding("EMBEDDED-FILES", "block",
                           "Embedded knowledge files were added or changed",
                           {"embeddedFiles": live.get("embeddedFiles"),
                            "approved": base.get("embeddedFiles")}))
    for key, rule in (("actions", "DRIFT-ACTIONS"), ("workerAgents", "DRIFT-WORKER-AGENTS"),
                      ("userOverrides", "DRIFT-USER-OVERRIDES"),
                      ("behaviorOverrides", "DRIFT-BEHAVIOR-OVERRIDES")):
        if live.get(key) != base.get(key):
            out.append(Finding(rule, "block", f"'{key}' changed from the approved configuration",
                               {"approved": base.get(key), "live": live.get(key)}))
    if live.get("instructionsHash") != base.get("instructionsHash"):
        sev = policy.get("instructionsChange", "warn")
        if sev in ("warn", "block"):
            out.append(Finding("DRIFT-INSTRUCTIONS", sev, "Agent instructions changed"))
    return out


def _policy_constraints(live: dict, policy: dict) -> list[Finding]:
    out: list[Finding] = []
    allowed_caps = policy.get("allowedCapabilities")
    if allowed_caps is not None:
        for name in sorted(set(live["capabilities"]) - set(allowed_caps)):
            out.append(Finding("POLICY-CAPABILITY", "block",
                               f"Capability '{name}' isn't allowed by the approval",
                               {"capability": name}))
    prefixes = [_norm_url(p) for p in policy.get("allowedKnowledgeUrlPrefixes", [])]
    if prefixes:
        for name in ("OneDriveAndSharePoint", "TeamsMessages", "WebSearch"):
            scope = live["capabilities"].get(name, {})
            for url in scope.get("urls", []) + scope.get("sites", []):
                if not any(url == p or url.startswith(p + "/") for p in prefixes):
                    out.append(Finding("POLICY-KNOWLEDGE-SOURCE", "block",
                                       f"Knowledge source outside the approved locations: {url}",
                                       {"capability": name, "url": url}))
    if live.get("actions") and not policy.get("allowActions", False):
        out.append(Finding("POLICY-ACTIONS", "block", "Actions or plugins aren't allowed",
                           {"actions": live["actions"]}))
    return out


# --------------------------------------------------------------------------
# Helpers for the governance process
# --------------------------------------------------------------------------
def draft_entry(detail: dict, owner_id: str | list[str] | None, recipients: list[dict],
                embedded_names: list[str] | None = None) -> dict:
    """Draft a registry entry from the agent's live configuration.

    ``owner_id`` is the owner, or a list of named owners (the first is the primary
    contact). Reviewers complete the approval section (criteria, risk rating,
    approver) and sign it.
    """
    profile = build_profile(detail, embedded_names)
    now = datetime.now(timezone.utc).isoformat()
    owners = [o for o in (owner_id if isinstance(owner_id, list) else [owner_id]) if o]
    return {
        "packageId": detail.get("id"),
        "manifestId": detail.get("manifestId"),
        "displayName": detail.get("displayName"),
        "ownerId": owners[0] if owners else None,
        "owners": owners,
        "status": "approved",
        "approval": {
            "requestId": "<governance ticket / request ID>",
            "approvedBy": "<approver UPN>",
            "approvedAt": now,
            "expiresAt": "<ISO date, e.g. 12 months>",
            "riskRating": "<low | medium | high>",
            "riskScore": None,
            "criteria": [
                {"id": "KS-01", "description": "Knowledge sources limited to approved SharePoint sites",
                 "result": "<pass|fail|n/a>", "evidence": "<link>"},
                {"id": "KS-02", "description": "No embedded knowledge files",
                 "result": "<pass|fail|n/a>", "evidence": "<link>"},
                {"id": "DS-01", "description": "Content sensitivity reviewed; highest label in scope",
                 "result": "<pass|fail|n/a>", "evidence": "<link>"},
                {"id": "AU-01", "description": "Audience appropriate for the content",
                 "result": "<pass|fail|n/a>", "evidence": "<link>"},
                {"id": "AC-01", "description": "No actions or plugins that write data",
                 "result": "<pass|fail|n/a>", "evidence": "<link>"},
            ],
            "conditions": [],
            "notes": "",
        },
        "sharing": {"allowedPrincipals": recipients},
        "policy": {
            "driftMode": "baseline",
            "instructionsChange": "warn",
            "allowEmbeddedFiles": False,
            "allowUnscoped": [],
            "requireRegisteredOwners": True,
            "requireActiveOwner": True,
        },
        "baseline": {"capturedAt": now, "configHash": sha256(profile) if profile else None,
                     "profile": profile},
        "governanceContacts": [],
    }
