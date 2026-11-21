# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""
Owner acknowledgement flow for ShareGuard for Agent Builder (ABSG).

When the guard blocks a shared agent, the owner gets a notice email with a
link of the form  {ack_base_url}?t=<signed token>.

* GET  shows a confirmation page only. It records nothing, because mail
  security scanners (Safe Links and similar) pre-fetch links. A GET
  that acted would be triggered by the scanner, not the user.
* POST (the "Confirm" button) validates the token, optionally checks the
  signed-in identity supplied by an authenticating reverse proxy, and puts
  the acknowledgement in a queue. The daemon picks it up on its next
  cycle, removes sharing on the owner's behalf and unblocks the agent.

Tokens are HMAC-SHA256 signed, expire, are bound to (package, owner, case),
and are single-use.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import logging
import os
import secrets
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlparse

log = logging.getLogger("absg.ack")


# --------------------------------------------------------------------------
# Tokens
# --------------------------------------------------------------------------
class TokenError(ValueError):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass
class AckClaims:
    package_id: str
    owner_id: str
    case_id: str
    token_id: str
    expires: int


class AckTokenSigner:
    def __init__(self, secret: str, ttl_hours: int = 168):
        if not secret or len(secret) < 32:
            raise ValueError("ack secret must be at least 32 characters")
        self._key = secret.encode()
        self.ttl = ttl_hours * 3600

    def issue(self, package_id: str, owner_id: str, case_id: str) -> tuple[str, AckClaims]:
        claims = AckClaims(package_id, owner_id, case_id, secrets.token_hex(8),
                           int(time.time()) + self.ttl)
        body = _b64(json.dumps({"p": claims.package_id, "o": claims.owner_id,
                                "c": claims.case_id, "j": claims.token_id,
                                "e": claims.expires}, separators=(",", ":")).encode())
        sig = _b64(hmac.new(self._key, body.encode(), hashlib.sha256).digest())
        return f"{body}.{sig}", claims

    def verify(self, token: str) -> AckClaims:
        try:
            body, sig = token.split(".", 1)
        except (ValueError, AttributeError):
            raise TokenError("malformed token") from None
        expected = _b64(hmac.new(self._key, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            raise TokenError("invalid signature")
        try:
            data = json.loads(_unb64(body))
        except Exception:
            raise TokenError("malformed token") from None
        if int(data["e"]) < time.time():
            raise TokenError("token expired")
        return AckClaims(data["p"], data["o"], data["c"], data["j"], int(data["e"]))


# --------------------------------------------------------------------------
# Acknowledgement queue (file-backed, thread-safe)
# --------------------------------------------------------------------------
class AckStore:
    """Holds pending acknowledgements and the set of used case IDs."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._data: dict[str, Any] = {"pending": {}, "used_cases": []}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                self._data = json.load(fh)

    def _save(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".acks-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

    def submit(self, ack: dict) -> bool:
        """Queue an acknowledgement. False if the case was already acknowledged."""
        with self._lock:
            case = ack["caseId"]
            if case in self._data["used_cases"] or case in self._data["pending"]:
                return False
            self._data["pending"][case] = {**ack, "attempts": 0}
            self._save()
            return True

    def pending(self) -> list[dict]:
        with self._lock:
            return [dict(v) for v in self._data["pending"].values()]

    def pending_for_package(self, package_id: str) -> list[dict]:
        return [a for a in self.pending() if a["packageId"] == package_id]

    def bump_attempt(self, case_id: str) -> int:
        with self._lock:
            entry = self._data["pending"].get(case_id)
            if not entry:
                return 0
            entry["attempts"] += 1
            self._save()
            return entry["attempts"]

    def close(self, case_id: str) -> None:
        """Mark a case as finished (single use)."""
        with self._lock:
            self._data["pending"].pop(case_id, None)
            if case_id not in self._data["used_cases"]:
                self._data["used_cases"].append(case_id)
            self._save()

    def is_used(self, case_id: str) -> bool:
        with self._lock:
            return case_id in self._data["used_cases"]


# --------------------------------------------------------------------------
# HTTP endpoint
# --------------------------------------------------------------------------
_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · ShareGuard for Agent Builder</title><style>
body{{font-family:Segoe UI,system-ui,sans-serif;max-width:560px;margin:40px auto;padding:0 16px;color:#222}}
h1{{font-size:1.4em}} .box{{border:1px solid #ddd;border-radius:8px;padding:16px;background:#fafafa}}
button{{background:#0f6cbd;color:#fff;border:0;border-radius:4px;padding:10px 18px;font-size:1em;cursor:pointer}}
label{{display:block;margin:12px 0}}</style></head><body>{body}</body></html>"""


def _page(title: str, body: str) -> bytes:
    return _PAGE.format(title=html.escape(title), body=body).encode()


class AckServer:
    """Small HTTP server for owner acknowledgements.

    Put it behind an authenticating reverse proxy (for example Azure App
    Service / Container Apps authentication with Entra ID, or Entra
    application proxy). Set ``identity_header`` to the header the proxy
    uses for the signed-in user's object ID
    (``X-MS-CLIENT-PRINCIPAL-ID`` for App Service / Container Apps auth).
    The server then rejects acknowledgements from anyone except the owner.
    """

    def __init__(self, signer: AckTokenSigner, store: AckStore,
                 audit: Callable[..., Any], host: str = "127.0.0.1", port: int = 8080,
                 path: str = "/ack", identity_header: str | None = None,
                 require_identity: bool = True, on_ack: Callable[[], None] | None = None,
                 poll_minutes: int = 5):
        self.signer, self.store, self.audit = signer, store, audit
        self.path = path
        self.identity_header = identity_header
        self.require_identity = require_identity and bool(identity_header)
        self.on_ack = on_ack or (lambda: None)
        self.poll_minutes = poll_minutes
        self.httpd = ThreadingHTTPServer((host, port), self._handler())
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    def start(self) -> None:
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True,
                                        name="ack-server")
        self._thread.start()
        log.info("Ack endpoint listening on %s:%s%s", *self.httpd.server_address[:2], self.path)

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    # ------------------------------------------------------------------
    def _handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):  # route to our logger
                log.debug("ack-http %s " + fmt, self.client_address[0], *args)

            def _send(self, code: int, body: bytes, ctype="text/html; charset=utf-8"):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy",
                                 "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
                self.end_headers()
                self.wfile.write(body)

            def _context(self) -> dict:
                return {"remoteAddr": self.headers.get("X-Forwarded-For") or self.client_address[0],
                        "userAgent": (self.headers.get("User-Agent") or "")[:300]}

            def do_GET(self):
                url = urlparse(self.path)
                if url.path == "/healthz":
                    return self._send(200, b"ok", "text/plain")
                if url.path != server.path:
                    return self._send(404, _page("Not found", "<h1>Not found</h1>"))
                token = (parse_qs(url.query).get("t") or [""])[0]
                try:
                    claims = server.signer.verify(token)
                except TokenError as exc:
                    return self._send(400, _page("Link not valid",
                        f"<h1>This link isn't valid</h1><p>{html.escape(str(exc))}. "
                        "Contact your IT service desk if you still need help.</p>"))
                if server.store.is_used(claims.case_id):
                    return self._send(200, _page("Already received",
                        "<h1>Already received</h1><p>This request has already been processed.</p>"))
                # GET never acts: show a confirmation form (protects against link scanners).
                body = (
                    "<h1>Remove sharing and restore your agent</h1>"
                    "<div class='box'><p>Your agent was blocked because it was shared with other "
                    "people, which isn't allowed for Agent Builder agents.</p>"
                    "<p>If you confirm, IT will <b>remove all sharing</b> from the agent on your "
                    "behalf and then <b>unblock it</b> for your own use. This is recorded in the "
                    "audit log.</p>"
                    f"<form method='post' action='{html.escape(server.path)}'>"
                    f"<input type='hidden' name='t' value='{html.escape(token)}'>"
                    "<label><input type='checkbox' name='confirm' value='yes' required> "
                    "I agree that sharing will be removed and I won't share Agent Builder "
                    "agents in future.</label>"
                    "<button type='submit'>Confirm</button></form></div>")
                return self._send(200, _page("Confirm", body))

            def do_POST(self):
                url = urlparse(self.path)
                if url.path != server.path:
                    return self._send(404, _page("Not found", "<h1>Not found</h1>"))
                length = min(int(self.headers.get("Content-Length") or 0), 8192)
                form = parse_qs(self.rfile.read(length).decode(errors="replace"))
                token = (form.get("t") or [""])[0]
                ctx = self._context()
                try:
                    claims = server.signer.verify(token)
                except TokenError as exc:
                    server.audit("ack_rejected", reason=str(exc), **ctx)
                    return self._send(400, _page("Link not valid",
                        f"<h1>This link isn't valid</h1><p>{html.escape(str(exc))}.</p>"))
                pkg = {"id": claims.package_id}
                if (form.get("confirm") or [""])[0] != "yes":
                    return self._send(400, _page("Please confirm",
                        "<h1>Please tick the confirmation box</h1>"))
                identity = self.headers.get(server.identity_header) if server.identity_header else None
                if server.require_identity:
                    if not identity:
                        server.audit("ack_rejected", package=pkg, caseId=claims.case_id,
                                     reason="no authenticated identity", **ctx)
                        return self._send(401, _page("Sign-in required",
                            "<h1>Sign-in required</h1><p>Open the link again and sign in "
                            "with your work account.</p>"))
                    if identity.lower() != claims.owner_id.lower():
                        server.audit("ack_rejected", package=pkg, caseId=claims.case_id,
                                     reason="signed-in user is not the agent owner",
                                     signedInUser=identity, ownerId=claims.owner_id, **ctx)
                        return self._send(403, _page("Not the owner",
                            "<h1>Only the agent's owner can confirm this</h1>"))
                ack = {"caseId": claims.case_id, "packageId": claims.package_id,
                       "ownerId": claims.owner_id, "tokenId": claims.token_id,
                       "receivedAt": datetime.now(timezone.utc).isoformat(),
                       "signedInUser": identity, **ctx}
                if not server.store.submit(ack):
                    return self._send(200, _page("Already received",
                        "<h1>Already received</h1><p>This request has already been processed.</p>"))
                server.audit("ack_received", package=pkg, caseId=claims.case_id,
                             tokenId=claims.token_id, ownerId=claims.owner_id,
                             signedInUser=identity, identityVerified=bool(server.require_identity),
                             **ctx)
                server.on_ack()
                return self._send(200, _page("Received",
                    "<h1>Thanks, we've received your confirmation</h1>"
                    f"<p>Sharing will be removed and your agent unblocked within about "
                    f"{server.poll_minutes} minutes. You'll get an email when it's done.</p>"))

        return Handler


def ack_link(base_url: str, token: str) -> str:
    """Link for the notice email: the built-in endpoint (``?t=``), or a pre-filled
    Microsoft Forms URL whose ``{token}`` placeholder is replaced."""
    if "{token}" in base_url:
        from urllib.parse import quote
        return base_url.replace("{token}", quote(token, safe=""))
    return f"{base_url}?{urlencode({'t': token})}"
