# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""Azure deployment: SharePoint stores, Key Vault ES256 signing, managed identity wiring."""
import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

import pytest

from absg.ack import AckTokenSigner
from absg.cloud import KeyVault, KeyVaultTokenCache
from absg.core import AuditLog, Config, GraphClient, GraphError, StateStore, verify_audit_lines
from absg.registry import (Registry, attach_signature, draft_entry, generate_keypair, sign_entry,
                           signing_payload, verify_entry)
from absg.sharepoint import (ConflictError, SharePointAckStore, SharePointAuditBackend,
                             SharePointJsonDocument, SharePointRegistrySource, SharePointSite)

SECRET = "k" * 40


# ------------------------------------------------------------------ fakes
class Resp:
    def __init__(self, body=None, status=200, content=None):
        self._b, self.status_code = body if body is not None else {}, status
        self.content = content if content is not None else json.dumps(self._b).encode()
        self.text = self.content.decode(errors="replace")
        self.headers = {}

    def json(self):
        return self._b

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.status_code)


class FakeGraph:
    """Enough of Graph for drives (files with eTags) and lists."""

    def __init__(self):
        self.files = {}          # (drive, path) -> [bytes, etag, id]
        self.lists = {}          # list name -> {id: {"id", "fields", "createdDateTime"}}
        self.users = {}          # upn -> id
        self.calls = []
        self.n = 0

    def _etag(self):
        self.n += 1
        return f'"{{E{self.n}}},1"'

    def request(self, method, url, headers=None, json=None, data=None, **kw):
        self.calls.append((method, url, headers))
        headers = headers or {}
        if url.endswith("/drives?$select=id,name"):
            return Resp({"value": [{"id": "d-state", "name": "ABSG State"}, {"id": "d-audit", "name": "ABSG Audit"},
                                     {"id": "d-arch", "name": "Retired Agents"}]})
        m = re.match(r"/drives/([^/]+)/root:/(.+?)(:/content|:/children\?.*)?$", url)
        if m:
            drive, path, tail = m.group(1), unquote(m.group(2)), m.group(3)
            key = (drive, path)
            if tail and tail.startswith(":/children"):
                return Resp({"value": [{"id": f[2], "name": p.split("/")[-1], "eTag": f[1]}
                                       for (d, p), f in self.files.items() if d == drive and p.startswith(path + "/")]})
            if method == "GET" and tail is None:
                if key not in self.files:
                    raise GraphError(404, "itemNotFound")
                f = self.files[key]
                return Resp({"id": f[2], "eTag": f[1], "@microsoft.graph.downloadUrl": f"https://dl/{drive}/{path}"})
            if method == "PUT" and tail == ":/content":
                cur = self.files.get(key)
                if "If-Match" in headers and (not cur or cur[1] != headers["If-Match"]):
                    raise GraphError(412, "preconditionFailed")
                if "If-None-Match" in headers and cur:
                    raise GraphError(412, "preconditionFailed")
                etag = self._etag()
                self.files[key] = [data, etag, cur[2] if cur else f"i{self.n}"]
                return Resp({"eTag": etag})
        m = re.match(r"/drives/([^/]+)/root/children\?.*", url)
        if m:
            drive = m.group(1)
            return Resp({"value": [{"id": f[2], "name": p, "eTag": f[1]}
                                   for (d, p), f in self.files.items() if d == drive and "/" not in p]})
        m = re.match(r"/drives/([^/]+)/items/([^/]+)/retentionLabel", url)
        if m:
            self.calls.append(("LABEL", m.group(2), json))
            return Resp({})
        m = re.match(r"/sites/[^/]+/lists/([^/]+)/items(?:/([^/?]+)/fields)?(\?.*)?$", url)
        if m:
            name, item_id = unquote(m.group(1)), m.group(2)
            items = self.lists.setdefault(name, {})
            if method == "GET":
                return Resp({"value": [json_copy(i) for i in items.values()]})
            if method == "PATCH":
                items[item_id]["fields"].update(json)
                return Resp({})
            if method == "POST":
                iid = str(len(items) + 1)
                items[iid] = {"id": iid, "fields": dict(json["fields"]), "createdDateTime": "2026-11-21T00:00:00Z"}
                return Resp(items[iid])
        m = re.match(r"/users/([^?]+)\?\$select=id$", url)
        if m:
            uid = self.users.get(unquote(m.group(1)))
            if not uid:
                raise GraphError(404, "no user")
            return Resp({"id": uid})
        raise AssertionError(f"unexpected {method} {url}")

    def get_paged(self, url):
        yield from self.request("GET", url).json().get("value", [])


def json_copy(o):
    return json.loads(json.dumps(o))


class DownloadSession:
    def __init__(self, graph):
        self.graph = graph

    def get(self, url, timeout=None):
        _, _, _, drive, path = url.split("/", 4)
        return Resp(content=self.graph.files[(drive, path)][0])


@pytest.fixture
def site():
    g = FakeGraph()
    return SharePointSite(g, "contoso.sharepoint.com,1,2", session=DownloadSession(g)), g


# ------------------------------------------------------------------ state
def test_state_document_round_trip_with_etag_checks(site):
    sp, g = site
    doc = SharePointJsonDocument(sp, "ABSG State", "state.json")
    state = StateStore(backend=doc)
    assert state.data == {}
    state.record_block("p1", {"caseId": "c1"})
    state.save()
    put = [c for c in g.calls if c[0] == "PUT"][0]
    assert put[2]["If-None-Match"] == "*"                        # first write: must not exist
    again = StateStore(backend=SharePointJsonDocument(sp, "ABSG State", "state.json"))
    assert again.is_ours("p1")
    # another writer changes the file: our save is refused, not silently overwritten
    other = SharePointJsonDocument(sp, "ABSG State", "state.json")
    other.load()
    other.save({"blocked_by_guard": {}})
    again.record_block("p2", {})
    with pytest.raises(ConflictError):
        again.save()


# ------------------------------------------------------------------ audit
def test_audit_chain_spans_daily_files_and_verifies(site, monkeypatch):
    sp, g = site
    backend = SharePointAuditBackend(sp, "ABSG Audit", "audit", retention_label="ABSG audit record")
    log = AuditLog(actor={"role": "guard"}, backend=backend)
    log.record("cycle_start")
    log.record("block", package={"id": "p1"})
    assert not [k for k in g.files if k[0] == "d-audit"]            # buffered until flush
    log.flush()
    (path,) = [p for d, p in g.files if d == "d-audit"]
    assert path.startswith("audit/absg-audit-") and path.endswith(".jsonl")
    # yesterday's file, then a new day's records continue the chain
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).date().isoformat()
    content = g.files[("d-audit", path)][0]
    g.files[("d-audit", f"audit/absg-audit-{yesterday}.jsonl")] = g.files.pop(("d-audit", path))
    resumed = AuditLog(actor={"role": "guard"}, backend=SharePointAuditBackend(
        sp, "ABSG Audit", "audit", retention_label="ABSG audit record"))
    assert resumed._seq == 2
    resumed.record("cycle_end")
    resumed.flush()
    assert len([k for k in g.files if k[0] == "d-audit"]) == 2
    v = verify_audit_lines(resumed.backend.iter_lines())
    assert v.ok and v.records == 3
    assert any(c[0] == "LABEL" for c in g.calls)                   # the closed day got the label
    # tampering with yesterday's file is detected across files
    g.files[("d-audit", f"audit/absg-audit-{yesterday}.jsonl")][0] = content.replace(b'"p1"', b'"p9"')
    assert not verify_audit_lines(resumed.backend.iter_lines()).ok


def test_failed_audit_flush_keeps_records(site):
    sp, g = site
    backend = SharePointAuditBackend(sp, "ABSG Audit")
    log = AuditLog(actor={}, backend=backend)
    log.record("a")
    real = g.request

    def failing(method, url, **kw):
        if method == "PUT":
            raise GraphError(503, "busy")
        return real(method, url, **kw)
    g.request = failing
    with pytest.raises(GraphError):
        log.flush()
    assert len(backend.buffer) == 1
    g.request = real
    log.record("b")
    log.flush()
    assert backend.buffer == [] and verify_audit_lines(backend.iter_lines()).records == 2


# ------------------------------------------------------------------ registry
def test_registry_from_list_with_es256_signatures(site):
    sp, g = site
    priv, pub = generate_keypair("es256")
    d = {"id": "p1", "displayName": "HR", "elementDetails": []}
    good = sign_entry(draft_entry(d, ["u1"], []), priv)
    assert good["signatureAlgorithm"] == "ES256" and len(base64.b64decode(good["signature"])) == 64
    tampered = {**good, "packageId": "p2", "displayName": "HR (edited)"}
    g.lists["Approved Agents"] = {
        "1": {"id": "1", "fields": {"Title": "p1", "EntryJson": json.dumps(good)}},
        "2": {"id": "2", "fields": {"Title": "p2", "EntryJson": json.dumps(tampered)}},
        "3": {"id": "3", "fields": {"Title": "p3", "EntryJson": "{not json"}}}
    reg = Registry(source=SharePointRegistrySource(sp), public_key=pub)
    reg.load()
    assert list(reg.entries) == ["p1"]
    assert reg.invalid == {"p2": "signature missing or invalid", "p3": "entry is not valid JSON"}


def test_es256_entries_reject_algorithm_confusion():
    ec_priv, ec_pub = generate_keypair("es256")
    ed_priv, ed_pub = generate_keypair("ed25519")
    entry = sign_entry({"packageId": "p"}, ed_priv)
    assert verify_entry(entry, ed_pub) and not verify_entry(entry, ec_pub)
    relabelled = {**entry, "signatureAlgorithm": "ES256"}
    assert not verify_entry(relabelled, ed_pub)


# ------------------------------------------------------------------ Key Vault
class FakeVault:
    """Key Vault REST: secrets and an EC-HSM key that signs digests (raw r||s)."""

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.secrets, self.calls = {}, []

    def request(self, method, url, timeout=None, headers=None, json=None):
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        from cryptography.hazmat.primitives import hashes
        assert headers["Authorization"] == "Bearer kv-token" and url.endswith("api-version=7.4")
        path = url.split(".vault.azure.net")[1].split("?")[0]
        self.calls.append((method, path))
        if path.startswith("/secrets/"):
            name = path.split("/")[2]
            if method == "PUT":
                self.secrets[name] = json["value"]
                return Resp({"value": json["value"]})
            if name not in self.secrets:
                return Resp({"error": "SecretNotFound"}, status=404)
            return Resp({"value": self.secrets[name]})
        if path.endswith("/sign"):
            assert json["alg"] == "ES256"
            digest = base64.urlsafe_b64decode(json["value"] + "==")
            der = self.key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            r, s = utils.decode_dss_signature(der)
            raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            return Resp({"value": base64.urlsafe_b64encode(raw).rstrip(b"=").decode()})
        if path.startswith("/keys/"):
            nums = self.key.public_key().public_numbers()
            b = lambda n: base64.urlsafe_b64encode(n.to_bytes(32, "big")).rstrip(b"=").decode()  # noqa: E731
            return Resp({"key": {"kty": "EC-HSM", "crv": "P-256", "x": b(nums.x), "y": b(nums.y),
                                 "kid": "https://kv/keys/registry-signing-key/1", "key_ops": ["sign", "verify"]}})
        raise AssertionError(path)


def test_key_vault_es256_signature_verifies_with_published_jwk():
    fake = FakeVault()
    kv = KeyVault("https://kv-absg.vault.azure.net", lambda: "kv-token", session=fake)
    jwk = kv.public_jwk("registry-signing-key")
    assert set(jwk) == {"kty", "crv", "x", "y", "kid"}
    entry = {**draft_entry({"id": "p1", "elementDetails": []}, ["u1"], []), "signatureAlgorithm": "ES256"}
    signed = attach_signature(entry, kv.sign_es256("registry-signing-key", signing_payload(entry)), "ES256")
    assert verify_entry(signed, jwk) and verify_entry(signed, json.dumps(jwk))
    signed["approval"]["riskRating"] = "low"
    assert not verify_entry(signed, jwk)
    with pytest.raises(ValueError):
        attach_signature({"packageId": "p"}, b"x" * 64, "ES256")   # algorithm must be in the signed content


def test_key_vault_secrets_and_token_cache():
    fake = FakeVault()
    kv = KeyVault("https://kv-absg.vault.azure.net", lambda: "kv-token", session=fake)
    assert kv.get_secret("missing") is None
    kv.set_secret("ack-token-hmac-key", "v" * 40)
    assert kv.get_secret("ack-token-hmac-key") == "v" * 40

    class Cache:
        has_state_changed = True
        def serialize(self): return '{"AccessToken": {}}'
        def deserialize(self, data): self.data = data
    store, cache = KeyVaultTokenCache(kv, "delegated-token-cache"), Cache()
    store.save(cache)
    assert fake.secrets["delegated-token-cache"] == '{"AccessToken": {}}' and not cache.has_state_changed
    fresh = Cache()
    store.load(fresh)
    assert fresh.data == '{"AccessToken": {}}'


# ------------------------------------------------------------------ acknowledgements
def test_forms_acknowledgements_are_verified_before_use(site):
    sp, g = site
    signer = AckTokenSigner(SECRET, 24)
    g.users = {"olivia@contoso.com": "owner-1", "eve@contoso.com": "user-9"}
    tok, claims = signer.issue("p1", "owner-1", "case-1")
    tok2, _ = signer.issue("p2", "owner-1", "case-2")
    other = AckTokenSigner("z" * 40).issue("p3", "owner-1", "case-3")[0]
    g.lists["Agent Acknowledgements"] = {
        "1": {"id": "1", "fields": {"Token": tok, "ResponderUpn": "olivia@contoso.com", "Status": "New"}},
        "2": {"id": "2", "fields": {"Token": tok, "ResponderUpn": "olivia@contoso.com", "Status": "New"}},
        "3": {"id": "3", "fields": {"Token": tok2, "ResponderUpn": "eve@contoso.com", "Status": "New"}},
        "4": {"id": "4", "fields": {"Token": other, "ResponderUpn": "olivia@contoso.com", "Status": "New"}}}
    store = SharePointAckStore(sp, signer, lambda upn: g.users.get(upn))
    seen = []
    store.refresh(lambda event, pid=None, **f: seen.append((event, pid, f.get("reason"))))
    status = {i: g.lists["Agent Acknowledgements"][i]["fields"]["Status"] for i in "1234"}
    assert status == {"1": "Accepted", "2": "Rejected", "3": "Rejected", "4": "Rejected"}
    assert ("ack_rejected", "p1", "case already acknowledged") in seen
    assert ("ack_rejected", "p2", "responder is not the owner the link was sent to") in seen
    assert ("ack_rejected", None, "token invalid signature") in seen
    (ack,) = store.pending_for_package("p1")
    assert ack["caseId"] == "case-1" and ack["ownerId"] == "owner-1"
    assert store.bump_attempt("case-1") == 1
    store.close("case-1")
    assert g.lists["Agent Acknowledgements"]["1"]["fields"]["Status"] == "Closed" and store.pending() == []
    store.refresh()
    assert store.pending() == []                                       # closed items stay closed


# ------------------------------------------------------------------ configuration + wiring
def test_managed_identity_config_from_app_settings(monkeypatch):
    cfg_json = {"tenant_id": "t", "client_id": "mi-client", "use_managed_identity": True,
                "storage_backend": "sharepoint", "sharepoint_operations_site_id": "ops",
                "sharepoint_registry_site_id": "reg", "key_vault_url": "https://kv-absg.vault.azure.net"}
    monkeypatch.setenv("ABSG_CONFIG_JSON", json.dumps(cfg_json))
    monkeypatch.setenv("ABSG_DRY_RUN", "true")
    cfg = Config.load(None)
    assert cfg.use_managed_identity and cfg.dry_run and cfg.storage_backend == "sharepoint"
    monkeypatch.setenv("ABSG_CONFIG_JSON", json.dumps({**cfg_json, "key_vault_url": None}))
    with pytest.raises(ValueError, match="public key"):
        Config.load(None)
    monkeypatch.setenv("ABSG_CONFIG_JSON", json.dumps({**cfg_json, "sharepoint_operations_site_id": None}))
    with pytest.raises(ValueError, match="sharepoint_operations_site_id"):
        Config.load(None)


def test_managed_identity_token_provider_used_for_graph(monkeypatch):
    import absg.cloud as cloud
    calls = []
    monkeypatch.setattr(cloud, "managed_identity_provider",
                        lambda resource, client_id=None, http=None: calls.append((resource, client_id)) or (lambda: "mi"))
    g = GraphClient(Config(tenant_id="t", client_id="mi-client", use_managed_identity=True))
    assert g._token_provider() == "mi" and calls == [("https://graph.microsoft.com", "mi-client")]


def test_runtime_build_wires_sharepoint_and_key_vault(monkeypatch, site):
    import absg.runtime as runtime
    sp, g = site
    fake_vault = FakeVault()
    fake_vault.secrets["ack-token-hmac-key"] = SECRET
    kv = KeyVault("https://kv-absg.vault.azure.net", lambda: "kv-token", session=fake_vault)
    monkeypatch.setattr(runtime, "key_vault", lambda cfg: kv)
    monkeypatch.setattr(runtime, "GraphClient", lambda cfg, **kw: g)
    import absg.sharepoint as spmod
    monkeypatch.setattr(spmod.SharePointSite, "__init__",
                        lambda self, graph, site_id, session=None: (
                            setattr(self, "graph", g), setattr(self, "site_id", site_id),
                            setattr(self, "session", DownloadSession(g)), setattr(self, "_drives", {}))[0])
    cfg = Config(tenant_id="t", client_id="mi", use_managed_identity=True, storage_backend="sharepoint",
                 sharepoint_operations_site_id="ops", sharepoint_registry_site_id="reg",
                 key_vault_url="https://kv-absg.vault.azure.net", ack_enabled=True,
                 ack_form_url="https://forms.office.com/r/abc?r1={token}", mail_sender="s@contoso.com")
    parts = runtime.build(cfg)
    assert isinstance(parts.acks, SharePointAckStore) and parts.signer is not None
    assert parts.guard.registry.public_key["kty"] == "EC-HSM"
    assert isinstance(parts.audit.backend, SharePointAuditBackend)
    _ = hashlib


# ------------------------------------------------------------------ archive and templates
def test_sharepoint_archive_writes_labelled_files_and_status(site):
    from absg.archive import SharePointArchiveStore, archive_files
    sp, g = site
    store = SharePointArchiveStore(sp, "Retired Agents", retention_label="ShareGuard retired agent")
    detail = {"id": "P_1", "displayName": "Old agent"}
    where = store.save("P_1", archive_files(detail, {"packageId": "P_1"}))
    folder = where["reference"]
    assert folder.endswith("/P_1")
    manifest = json.loads(g.files[("d-arch", f"{folder}/manifest.json")][0])
    assert manifest["agentJsonSha256"] and json.loads(g.files[("d-arch", f"{folder}/agent.json")][0])["id"] == "P_1"
    assert len([c for c in g.calls if c[0] == "LABEL"]) == 2
    store.record_status(folder, "deleted", {"packageId": "P_1"})
    assert ("d-arch", f"{folder}/status-deleted.json") in g.files
    # an interrupted earlier attempt left a file behind: saving again overwrites it
    store.save("P_1", archive_files(detail, {"packageId": "P_1", "retry": True}))
    assert json.loads(g.files[("d-arch", f"{folder}/manifest.json")][0])["retry"] is True


def test_email_templates_from_sharepoint_folder(site):
    from absg.mail import TemplateError
    from absg.runtime import email_templates
    sp, g = site
    sp.upload("ABSG State", "templates/welcome.html", b"Subject: Hi {{owner_name}}\n<p>Hello</p>", None)
    cfg = Config(tenant_id="t", client_id="c", storage_backend="sharepoint",
                 sharepoint_operations_site_id="ops", sharepoint_templates_folder="templates")
    assert email_templates(cfg, sp)["welcome"][0] == "Hi {{owner_name}}"
    sp.upload("ABSG State", "templates/share_notice.html", b"Subject: x\n{{oops}}", None)
    with pytest.raises(TemplateError):
        email_templates(cfg, sp)
