# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""Azure building blocks for ShareGuard for Agent Builder: managed identity
tokens and a small Azure Key Vault client (secrets and ES256 signing).

Only ``msal`` and ``requests`` are used, so the Azure SDKs aren't required.
Tokens for a user-assigned managed identity are requested with
``msal.ManagedIdentityClient``; set ``client_id`` to the identity's client ID.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import threading
import time
from typing import Any, Callable
from urllib.parse import quote

import requests

log = logging.getLogger("absg.cloud")

GRAPH_RESOURCE = "https://graph.microsoft.com"
KEY_VAULT_RESOURCE = "https://vault.azure.net"
KEY_VAULT_API = "7.4"


class CloudError(RuntimeError):
    def __init__(self, status: int, body: str):
        super().__init__(f"Azure error {status}: {body[:400]}")
        self.status = status


def managed_identity_provider(resource: str, client_id: str | None = None,
                              http: requests.Session | None = None) -> Callable[[], str]:
    """Token provider for a managed identity (user-assigned when ``client_id`` is set)."""
    import msal

    identity: Any = (msal.UserAssignedManagedIdentity(client_id=client_id) if client_id
                     else msal.SystemAssignedManagedIdentity())
    app = msal.ManagedIdentityClient(identity, http_client=http or requests.Session())
    lock = threading.Lock()

    def provider() -> str:
        with lock:
            result = app.acquire_token_for_client(resource=resource)  # cached by MSAL
        if "access_token" not in result:
            raise CloudError(401, f"managed identity token failed: {result.get('error_description') or result}")
        return result["access_token"]

    return provider


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class KeyVault:
    """Minimal Key Vault data-plane client (REST, API version 7.4)."""

    def __init__(self, vault_url: str, token_provider: Callable[[], str],
                 session: requests.Session | None = None, timeout: int = 30):
        self.url = vault_url.rstrip("/")
        self._token = token_provider
        self.session = session or requests.Session()
        self.timeout = timeout

    def _call(self, method: str, path: str, **kwargs: Any) -> dict:
        url = f"{self.url}{path}?api-version={KEY_VAULT_API}"
        for attempt in range(5):
            resp = self.session.request(method, url, timeout=self.timeout,
                                        headers={"Authorization": f"Bearer {self._token()}"}, **kwargs)
            if resp.status_code in (429, 500, 502, 503, 504):
                retry = resp.headers.get("Retry-After")
                time.sleep(min(float(retry) if retry and retry.isdigit() else 2 ** attempt, 30))
                continue
            if resp.status_code >= 400:
                raise CloudError(resp.status_code, resp.text)
            return resp.json() if resp.content else {}
        raise CloudError(resp.status_code, resp.text)

    # -- secrets ------------------------------------------------------------
    def get_secret(self, name: str) -> str | None:
        """Secret value, or None when the secret doesn't exist yet."""
        try:
            return self._call("GET", f"/secrets/{quote(name)}").get("value")
        except CloudError as exc:
            if exc.status == 404:
                return None
            raise

    def set_secret(self, name: str, value: str, content_type: str | None = None) -> None:
        body: dict[str, Any] = {"value": value}
        if content_type:
            body["contentType"] = content_type
        self._call("PUT", f"/secrets/{quote(name)}", json=body)

    # -- keys ---------------------------------------------------------------
    def public_jwk(self, key_name: str) -> dict:
        """Public part of a key as a JWK (private material never leaves the HSM)."""
        key = self._call("GET", f"/keys/{quote(key_name)}").get("key") or {}
        return {k: v for k, v in key.items() if k in ("kty", "crv", "x", "y", "n", "e", "kid")}

    def sign_es256(self, key_name: str, data: bytes) -> bytes:
        """ECDSA P-256 signature over SHA-256(data), as raw r || s (64 bytes)."""
        digest = hashlib.sha256(data).digest()
        out = self._call("POST", f"/keys/{quote(key_name)}/sign",
                         json={"alg": "ES256", "value": _b64url(digest)})
        sig = _b64url_decode(out["value"])
        if len(sig) != 64:
            raise CloudError(500, f"unexpected ES256 signature length {len(sig)}")
        return sig


class KeyVaultTokenCache:
    """Stores an MSAL token cache (the delegated service account's refresh token)
    in a Key Vault secret instead of a local file."""

    def __init__(self, vault: KeyVault, secret_name: str):
        self.vault, self.secret_name = vault, secret_name

    def load(self, cache: Any) -> None:
        data = self.vault.get_secret(self.secret_name)
        if data:
            cache.deserialize(data)

    def save(self, cache: Any) -> None:
        if cache.has_state_changed:
            self.vault.set_secret(self.secret_name, cache.serialize(), content_type="application/json")
            cache.has_state_changed = False
