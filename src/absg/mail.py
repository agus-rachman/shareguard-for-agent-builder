# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""
Email, email templates and owner lookup for ShareGuard for Agent Builder.

Emails are sent with Microsoft Graph ``POST /users/{sender}/sendMail`` using
the guard's app identity (application permission ``Mail.Send``). Limit that
permission to the sender mailbox with an Exchange Online RBAC for
Applications scope (or an application access policy).
Recipient and owner lookups use ``/users`` (``User.Read.All``) and group names
use ``/groups`` (``GroupMember.Read.All``); ``Directory.Read.All`` isn't needed.
"""
from __future__ import annotations

import html
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("absg.mail")


# --------------------------------------------------------------------------
# Owner lookup
# --------------------------------------------------------------------------
def _dig(obj: Any, dotted: str) -> Any:
    for part in dotted.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


def _ids(value: Any) -> list[str]:
    """Owner IDs from a field value: a string, a list of strings, or a list of objects
    carrying ``id`` / ``resourceId`` / ``userId``."""
    if isinstance(value, str):
        return [value] if value else []
    out: list[str] = []
    if isinstance(value, list):
        for v in value:
            if isinstance(v, str) and v:
                out.append(v)
            elif isinstance(v, dict):
                rid = v.get("id") or v.get("resourceId") or v.get("userId")
                if isinstance(rid, str) and rid:
                    out.append(rid)
    elif isinstance(value, dict):
        out = _ids([value])
    return list(dict.fromkeys(out))


class OwnerResolver:
    """Works out the owners (Entra user object IDs) of an agent.

    Agent Builder agents can have several owners with equal rights. The Package
    Management API doesn't document an owner property, so sources are tried in order:
      1. ``owner_map``: an explicit packageId -> userId (or list of user IDs) mapping.
      2. ``owner_fields``: dotted paths in the package detail (for example "ownerId",
         "owners" or "createdBy.user.id") in case Microsoft exposes one; values may be
         a string or a list. These are the *platform-reported* owners.
      3. A previously learned owner for this package (from state).
      4. Inference: while the agent is NOT shared, if allowedUsersAndGroups
         holds exactly one user, that user is taken to be the owner. The owner is
         learned on first sight and remembered, so it's still known after the
         agent is later shared.
    """

    def __init__(self, owner_fields: list[str], owner_map_file: str | None,
                 learned: dict[str, str], infer_from_allowed_list: bool = True,
                 owner_map: dict[str, Any] | None = None):
        self.owner_fields = owner_fields
        self.learned = learned
        self.infer = infer_from_allowed_list
        self.owner_map: dict[str, Any] = dict(owner_map or {})
        if owner_map_file and os.path.exists(owner_map_file):
            with open(owner_map_file, encoding="utf-8") as fh:
                self.owner_map.update(json.load(fh))

    def reported(self, detail: dict) -> list[str] | None:
        """Owners the platform reports through ``owner_fields`` (None if it reports none)."""
        found: list[str] = []
        for path in self.owner_fields:
            found += _ids(_dig(detail, path))
        return list(dict.fromkeys(found)) if found else None

    def resolve_all(self, detail: dict, shared: bool) -> tuple[list[str], str | None]:
        """All known owners (primary first) and where the primary came from."""
        pid = detail.get("id")
        if pid in self.owner_map:
            return _ids(self.owner_map[pid]), "owner_map"
        reported = self.reported(detail)
        if reported:
            first = next(p for p in self.owner_fields if _ids(_dig(detail, p)))
            return reported, f"field:{first}"
        owner, source = self.resolve(detail, shared)
        return ([owner] if owner else []), source

    def resolve(self, detail: dict, shared: bool) -> tuple[str | None, str | None]:
        pid = detail.get("id")
        if pid in self.owner_map:
            ids = _ids(self.owner_map[pid])
            if ids:
                return ids[0], "owner_map"
        for path in self.owner_fields:
            ids = _ids(_dig(detail, path))
            if ids:
                return ids[0], f"field:{path}"
        if pid in self.learned:
            return self.learned[pid], "learned"
        if self.infer and not shared:
            users = [e for e in (detail.get("allowedUsersAndGroups") or [])
                     if str(e.get("resourceType", "")).lower() == "user"]
            groups = [e for e in (detail.get("allowedUsersAndGroups") or [])
                      if str(e.get("resourceType", "")).lower() != "user"]
            if len(users) == 1 and not groups and users[0].get("resourceId"):
                return users[0]["resourceId"], "inferred:allowed_list"
        return None, None


# --------------------------------------------------------------------------
# Templates
# --------------------------------------------------------------------------
# Email templates
# --------------------------------------------------------------------------
# Every email is rendered from a template: a subject line and an HTML body with
# {{placeholders}}. The defaults below can be replaced one by one: put files named
# "<template>.html" (or "<template>.<variant>.html") in email_templates_dir or in
# the SharePoint folder sharepoint_templates_folder. The first line of each file is
# "Subject: ...", and the rest is the body. "layout.html" replaces the wrapper
# around every body. Run `absg --export-email-templates DIR` to get these defaults
# as files, and `absg --preview-emails DIR` to see the result.
#
# Placeholders whose names end in _html are inserted as they are (they're built by
# ShareGuard and already escaped); all others are HTML-escaped in the body.

COMMON_VARIABLES = ("owner_name", "agent_name", "agent_id", "brand_name", "policy_url",
                    "policy_link_html", "helpdesk")

TEMPLATE_VARIABLES: dict[str, tuple[str, ...]] = {
    "layout": ("content_html", "footer_html", "brand_name", "helpdesk"),
    "welcome": (),
    "share_notice": ("shared_with_html", "ack_url", "ack_expires", "ack_button_html", "ack_expiry_html"),
    "restored": ("restore_reason",),
    "drift_notice": ("violations_html", "request_id", "request_ref_html", "ack_url", "ack_expires",
                     "option_unshare_html"),
    "inactivity_warning": ("last_activity", "retire_on", "inactivity_days", "notice_days", "days_left",
                           "after_retirement_html"),
    "retired_notice": ("inactivity_days", "retired_on", "archive_on", "ack_url", "ack_expires",
                       "ack_button_html", "after_retirement_html"),
    "archived_notice": ("archived_on", "archive_reference", "deletion_html"),
    "ownership_transferred": ("previous_owner",),
    "admin_alert": ("subject", "details_html"),
}
VARIANTS = {
    "restored": ("unshared", "approved", "drift_fixed", "reactivated"),
    "inactivity_warning": ("reminder",),
}

_HI = "<p>Hi {{owner_name}},</p>\n"
DEFAULT_TEMPLATES: dict[str, tuple[str, str]] = {
    "layout": ("", """<html><body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#222;max-width:620px">
{{content_html}}
<hr style="border:0;border-top:1px solid #ddd;margin-top:24px">
<p style="font-size:12px;color:#666">This is an automated message from {{brand_name}}, IT's Copilot agent governance service.
{{footer_html}}</p></body></html>"""),
    "welcome": ("Welcome to Copilot Agent Builder", _HI + """<p>You've just created your first Copilot agent, <b>{{agent_name}}</b>, with Agent Builder. Welcome!</p>
<p><b>Before you go further:</b></p><ul>
<li>Agent Builder agents are for <b>your own use</b>. Don't share them with other people or groups.</li>
<li>If an agent is shared, it is <b>blocked automatically</b> for everyone, including you, until sharing is removed.</li>
<li>Need an agent for your team? Ask IT about publishing it through the approved process.</li>
<li>Your agent can only use content you already have access to. Keep sensitive content labelled correctly.</li>
<li>Agents nobody uses are retired automatically.</li></ul>
{{policy_link_html}}"""),
    "share_notice": ("Action needed: your Copilot agent '{{agent_name}}' is blocked", _HI + """<p>Your Copilot agent <b>{{agent_name}}</b> has been <b>blocked</b> because it was shared with other people. Sharing isn't allowed for Agent Builder agents.</p>
<p>It was shared with:</p><ul>{{shared_with_html}}</ul>
<p><b>To restore your agent</b>, select the button below and confirm. IT will then remove all sharing from the agent on your behalf and unblock it for your own use, usually within a few minutes.</p>
{{ack_button_html}}{{ack_expiry_html}}
{{policy_link_html}}"""),
    "restored.unshared": ("Your Copilot agent '{{agent_name}}' is unblocked", _HI + """<p>Sharing has been removed from <b>{{agent_name}}</b>, and the agent is <b>unblocked</b> for your own use. It may take a little while to show up again in Copilot.</p>
<p>Please don't share it again: a shared agent is blocked automatically.</p>
{{policy_link_html}}"""),
    "restored.approved": ("Your Copilot agent '{{agent_name}}' is unblocked", _HI + """<p>Good news about <b>{{agent_name}}</b>: it has been approved for sharing, and the agent is <b>unblocked</b> for its approved audience.</p>
<p>Remember: changing its knowledge sources, capabilities or audience without a new approval will block it again.</p>
{{policy_link_html}}"""),
    "restored.drift_fixed": ("Your Copilot agent '{{agent_name}}' is unblocked", _HI + """<p>Good news about <b>{{agent_name}}</b>: its configuration matches what was approved again, and the agent is <b>unblocked</b> for its approved audience.</p>
<p>Remember: changing its knowledge sources, capabilities or audience without a new approval will block it again.</p>
{{policy_link_html}}"""),
    "restored.reactivated": ("Your Copilot agent '{{agent_name}}' is active again", _HI + """<p>Your Copilot agent <b>{{agent_name}}</b> is <b>active again</b>. It may take a little while to show up in Copilot.</p>
<p>Agents that go unused are retired automatically, so use it or delete it when you no longer need it.</p>
{{policy_link_html}}"""),
    "drift_notice": ("Action needed: approved agent '{{agent_name}}' is blocked (configuration changed)", _HI + """<p>Your approved Copilot agent <b>{{agent_name}}</b> has been <b>blocked</b>. Its current configuration no longer matches what was approved{{request_ref_html}}.</p>
<p>What changed:</p><table>{{violations_html}}</table>
<p><b>Option 1: undo the change.</b> Put the agent back to its approved configuration (for example, remove embedded files or knowledge sources that were added). The agent is checked automatically every few minutes and unblocked as soon as it matches. If you need the change, submit the agent for re-approval.</p>
{{option_unshare_html}}
{{policy_link_html}}"""),
    "inactivity_warning": ("Your Copilot agent '{{agent_name}}' will be retired on {{retire_on}}", _HI + """<p>Your Copilot agent <b>{{agent_name}}</b> hasn't been used since {{last_activity}}. Agents that aren't used for {{inactivity_days}} days are retired automatically.</p>
<p><b>It will be retired on {{retire_on}}</b> unless it's used before then. To keep it, just use it in Copilot. If you no longer need it, you can delete it in Agent Builder.</p>
{{after_retirement_html}}
{{policy_link_html}}"""),
    "inactivity_warning.reminder": ("Reminder: your Copilot agent '{{agent_name}}' will be retired on {{retire_on}}", _HI + """<p>This is a reminder: your Copilot agent <b>{{agent_name}}</b> will be <b>retired in {{days_left}} days, on {{retire_on}}</b>, because it hasn't been used since {{last_activity}}.</p>
<p>To keep it, just use it in Copilot before then.</p>
{{after_retirement_html}}
{{policy_link_html}}"""),
    "retired_notice": ("Your Copilot agent '{{agent_name}}' has been retired", _HI + """<p>Your Copilot agent <b>{{agent_name}}</b> wasn't used for {{inactivity_days}} days, so it has been <b>retired</b> and is now blocked.</p>
{{after_retirement_html}}
{{ack_button_html}}
{{policy_link_html}}"""),
    "archived_notice": ("Your retired Copilot agent '{{agent_name}}' has been archived", _HI + """<p>Your retired Copilot agent <b>{{agent_name}}</b> has been <b>archived</b>: IT has kept a copy of its configuration (reference {{archive_reference}}).</p>
{{deletion_html}}
<p>If you need it back, contact {{helpdesk}} and quote the reference.</p>
{{policy_link_html}}"""),
    "ownership_transferred": ("You now own the Copilot agent '{{agent_name}}'", _HI + """<p>You are now the owner of the Copilot agent <b>{{agent_name}}</b>. Its previous owner's account is no longer active, so ownership was passed to you as their manager.</p>
<p>If the agent is still useful, review it and keep it up to date. If it isn't, delete it in Agent Builder. Shared agents need a governance approval naming you as an owner.</p>
{{policy_link_html}}"""),
    "admin_alert": ("[{{brand_name}}] {{subject}}", "<p>{{subject}}</p><table>{{details_html}}</table>"),
}

_PLACEHOLDER = re.compile(r"\{\{\s*([a-z0-9_]+)\s*\}\}")


class TemplateError(ValueError):
    """A customised email template can't be used."""


def parse_template(text: str) -> tuple[str, str]:
    """A template file: first line "Subject: ...", then the HTML body."""
    text = text.lstrip("﻿")
    first, _, body = text.partition("\n")
    if first.lower().startswith("subject:"):
        return first.split(":", 1)[1].strip(), body.strip("\n")
    return "", text


def check_templates(templates: dict[str, tuple[str, str]]) -> list[str]:
    """Problems with customised templates (unknown names or placeholders)."""
    problems = []
    for key, (subject, body) in templates.items():
        base, _, variant = key.partition(".")
        if base not in TEMPLATE_VARIABLES or (variant and variant not in VARIANTS.get(base, ())):
            problems.append(f"{key}: unknown template (expected one of: {', '.join(sorted(DEFAULT_TEMPLATES))})")
            continue
        allowed = set(TEMPLATE_VARIABLES[base]) | set(COMMON_VARIABLES)
        for name in _PLACEHOLDER.findall(subject + body):
            if name not in allowed:
                problems.append(f"{key}: unknown placeholder {{{{{name}}}}}")
        if base != "layout" and not subject:
            problems.append(f"{key}: missing 'Subject:' first line")
        if base == "layout" and "content_html" not in _PLACEHOLDER.findall(body):
            problems.append("layout: must contain {{content_html}}")
    return problems


def load_templates(files: dict[str, str]) -> dict[str, tuple[str, str]]:
    """Customised templates from {file name: text}; raises TemplateError on problems."""
    out = {}
    for name, text in files.items():
        if name.lower().endswith(".html"):
            out[name[:-5]] = parse_template(text)
    problems = check_templates(out)
    if problems:
        raise TemplateError("; ".join(problems))
    return out


def load_template_dir(path: str) -> dict[str, tuple[str, str]]:
    files = {}
    for name in sorted(os.listdir(path)):
        if name.lower().endswith(".html"):
            with open(os.path.join(path, name), encoding="utf-8") as fh:
                files[name] = fh.read()
    return load_templates(files)


def export_templates(path: str) -> list[str]:
    """Write the default templates as files, as a starting point for customising."""
    os.makedirs(path, exist_ok=True)
    written = []
    for key, (subject, body) in DEFAULT_TEMPLATES.items():
        name = os.path.join(path, f"{key}.html")
        with open(name, "w", encoding="utf-8") as fh:
            fh.write((f"Subject: {subject}\n" if key != "layout" else "") + body + "\n")
        written.append(name)
    return written


def _fill(template: str, values: dict[str, Any], escape: bool) -> str:
    def sub(m: re.Match) -> str:
        name = m.group(1)
        value = values.get(name)
        if value is None:
            return ""
        return str(value) if (name.endswith("_html") or not escape) else html.escape(str(value))
    return _PLACEHOLDER.sub(sub, template)


def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


class Mailer:
    def __init__(self, graph: Any, sender: str | None, admin_emails: list[str] | None = None,
                 policy_url: str | None = None, helpdesk: str | None = None,
                 dry_run: bool = False, brand_name: str = "ShareGuard for Agent Builder",
                 subject_prefix: str = "", footer: str | None = None,
                 button_colour: str = "#0f6cbd",
                 templates: dict[str, tuple[str, str]] | None = None):
        self.graph = graph
        self.sender = sender
        self.admin_emails = admin_emails or []
        self.policy_url = policy_url
        self.helpdesk = helpdesk
        self.dry_run = dry_run
        self.brand_name = brand_name
        self.subject_prefix = subject_prefix
        self.footer = footer
        self.button_colour = button_colour
        self.custom = dict(templates or {})
        self.customised = sorted(self.custom)
        self.outbox: list[dict] | None = None     # set to a list to capture instead of sending
        self._name_cache: dict[str, str] = {}

    @property
    def enabled(self) -> bool:
        return bool(self.sender) or self.outbox is not None

    # -- lookups ----------------------------------------------------------
    def get_user(self, user_id: str) -> dict:
        return self.graph.request(
            "GET", f"/users/{user_id}?$select=id,displayName,mail,userPrincipalName,accountEnabled").json()

    def principal_name(self, entity: dict) -> str:
        rid = entity.get("resourceId", "")
        if entity.get("resourceType") == "tenant":
            return "Everyone in the organisation"
        kind = str(entity.get("resourceType", "")).lower()
        if rid not in self._name_cache:
            collection = "groups" if kind == "group" else "users"
            try:
                obj = self.graph.request(
                    "GET", f"/{collection}/{rid}?$select=displayName,mail").json()
                self._name_cache[rid] = obj.get("displayName") or obj.get("mail") or rid
            except Exception:  # best effort only
                self._name_cache[rid] = rid
        return f"{self._name_cache[rid]} ({'group' if kind == 'group' else kind or 'user'})"

    # -- rendering ----------------------------------------------------------
    def _button(self, url: str, label: str) -> str:
        return (f'<p><a href="{_e(url)}" style="background:{_e(self.button_colour)};color:#fff;'
                'padding:10px 18px;border-radius:4px;text-decoration:none;display:inline-block">'
                f'{_e(label)}</a></p>')

    @staticmethod
    def _small(text: str) -> str:
        return f"<p style='font-size:12px;color:#666'>{text}</p>"

    def _common(self, user: dict | None, agent: dict | None) -> dict[str, Any]:
        return {"owner_name": (user or {}).get("displayName") or "there",
                "agent_name": (agent or {}).get("displayName"), "agent_id": (agent or {}).get("id"),
                "brand_name": self.brand_name, "policy_url": self.policy_url,
                "policy_link_html": (f'<p>Read the <a href="{_e(self.policy_url)}">Copilot agent policy</a>.</p>'
                                     if self.policy_url else ""),
                "helpdesk": self.helpdesk or "the IT service desk"}

    def render(self, template: str, values: dict[str, Any], variant: str | None = None) -> tuple[str, str]:
        subject_t, body_t = self._template(template, variant)
        subject = " ".join(_fill(subject_t, values, escape=False).split())
        if self.subject_prefix and not subject.startswith(self.subject_prefix):
            subject = f"{self.subject_prefix} {subject}"
        footer = _e(self.footer) if self.footer else (
            f"Need help? Contact {_e(self.helpdesk)}." if self.helpdesk else "")
        layout = self._template("layout", None)[1]
        page = _fill(layout, {"content_html": _fill(body_t, values, escape=True), "footer_html": footer,
                              "brand_name": self.brand_name, "helpdesk": values.get("helpdesk")}, escape=True)
        return subject, page

    def _template(self, template: str, variant: str | None) -> tuple[str, str]:
        """Customised variant, customised template, default variant, default template."""
        keys = ([f"{template}.{variant}"] if variant else []) + [template]
        for source in (self.custom, DEFAULT_TEMPLATES):
            for key in keys:
                if key in source:
                    return source[key]
        raise KeyError(template)

    # -- send -------------------------------------------------------------
    def _send(self, to: list[str], template: str, values: dict[str, Any],
              variant: str | None = None, header: str | None = None) -> dict:
        subject, page = self.render(template, values, variant)
        header = header or template
        meta = {"template": header, "to": to, "subject": subject,
                "sentAt": datetime.now(timezone.utc).isoformat()}
        if self.outbox is not None:
            self.outbox.append({**meta, "html": page, "variant": variant})
            meta["simulated"] = True
            return meta
        if self.dry_run:
            meta["simulated"] = True
            return meta
        message = {
            "message": {
                "subject": subject,
                "body": {"contentType": "HTML", "content": page},
                "toRecipients": [{"emailAddress": {"address": a}} for a in to],
                # Lets Exchange transport rules and eDiscovery identify ShareGuard mail.
                "internetMessageHeaders": [{"name": "X-ABSG", "value": header}],
            },
            "saveToSentItems": True,
        }
        self.graph.request("POST", f"/users/{self.sender}/sendMail", json=message)
        return meta

    @staticmethod
    def _address(user: dict) -> str:
        addr = user.get("mail") or user.get("userPrincipalName")
        if not addr:
            raise ValueError(f"user {user.get('id')} has no mail address")
        return addr

    def _ack(self, ack_url: str | None, expires_at: str | None, label: str,
             fallback: str) -> dict[str, Any]:
        return {"ack_url": ack_url, "ack_expires": expires_at,
                "ack_button_html": self._button(ack_url, label) if ack_url else f"<p>{fallback}</p>",
                "ack_expiry_html": self._small(f"This link is personal to you and expires on {_e(expires_at)}. "
                                               "You may be asked to sign in.") if ack_url and expires_at else ""}

    # -- templates --------------------------------------------------------
    def send_welcome(self, user: dict, agent: dict) -> dict:
        return self._send([self._address(user)], "welcome", self._common(user, agent))

    def send_share_notice(self, user: dict, agent: dict, recipients: list[dict],
                          ack_url: str | None, expires_at: str | None) -> dict:
        names = "".join(f"<li>{_e(self.principal_name(r))}</li>" for r in recipients[:25])
        more = f"<li>…and {len(recipients) - 25} more</li>" if len(recipients) > 25 else ""
        values = {**self._common(user, agent), "shared_with_html": names + more,
                  **self._ack(ack_url, expires_at, "Remove sharing and unblock my agent",
                              "To restore your agent, contact the IT service desk and ask for sharing to be removed.")}
        return self._send([self._address(user)], "share_notice", values)

    def send_restored(self, user: dict, agent: dict, reason: str = "") -> dict:
        if "reactivated" in reason or "active owner" in reason:
            variant = "reactivated"
        elif "drift rectified" in reason:
            variant = "drift_fixed"
        elif "approved in the registry" in reason:
            variant = "approved"
        else:
            variant = "unshared"
        return self._send([self._address(user)], "restored",
                          {**self._common(user, agent), "restore_reason": reason}, variant=variant)

    def send_drift_notice(self, user: dict, agent: dict, violations: list[dict],
                          approval_entry: dict, ack_url: str | None,
                          expires_at: str | None) -> dict:
        approval = approval_entry.get("approval") or {}
        rows = "".join(
            f"<tr><td style='padding:4px 12px 4px 0;vertical-align:top'><code>{_e(v['rule'])}</code></td>"
            f"<td style='padding:4px 0'>{_e(v['message'])}</td></tr>" for v in violations)
        option = ""
        if ack_url:
            option = ("<p><b>Option 2: stop sharing it.</b> If the agent no longer needs to be shared, "
                      "IT can remove all sharing for you and unblock it for your own use:</p>"
                      + self._button(ack_url, "Remove sharing and unblock my agent")
                      + (self._small(f"This link is personal to you and expires on {_e(expires_at)}.")
                         if expires_at else ""))
        rid = approval.get("requestId")
        values = {**self._common(user, agent), "violations_html": rows, "request_id": rid,
                  "request_ref_html": f" under request <b>{_e(rid)}</b>" if rid else "",
                  "ack_url": ack_url, "ack_expires": expires_at, "option_unshare_html": option}
        return self._send([self._address(user)], "drift_notice", values)

    @staticmethod
    def _after_retirement(archive_after_days: int | None, deletion_mode: str,
                          archive_on: str | None = None) -> str:
        text = "A retired agent is blocked, not deleted, and you can reactivate it"
        if archive_after_days is not None:
            when = f"on {_e(archive_on)}" if archive_on else f"{archive_after_days} days after retirement"
            text = (f"{text}. If it's still retired {when}, IT archives a copy"
                    + (" and then deletes it from Microsoft 365" if deletion_mode != "none" else ""))
        return f"<p>{text}.</p>"

    def send_inactivity_warning(self, user: dict, agent: dict, last_activity: str | None,
                                retire_on: str, inactivity_days: int, *, notice_days: int | None = None,
                                days_left: int | None = None, reminder: bool = False,
                                archive_after_days: int | None = None, deletion_mode: str = "none") -> dict:
        values = {**self._common(user, agent), "last_activity": last_activity or "it was created",
                  "retire_on": retire_on, "inactivity_days": inactivity_days,
                  "notice_days": notice_days, "days_left": days_left,
                  "after_retirement_html": self._after_retirement(archive_after_days, deletion_mode)}
        return self._send([self._address(user)], "inactivity_warning", values,
                          variant="reminder" if reminder else None,
                          header="inactivity_reminder" if reminder else None)

    def send_retired_notice(self, user: dict, agent: dict, inactivity_days: int,
                            ack_url: str | None, expires_at: str | None, *,
                            archive_on: str | None = None, archive_after_days: int | None = None,
                            deletion_mode: str = "none") -> dict:
        after = self._after_retirement(archive_after_days, deletion_mode, archive_on)
        ack = self._ack(ack_url, expires_at, "Reactivate my agent",
                        "Still need it? Contact the IT service desk to have it reactivated.")
        if ack_url:
            ack["ack_button_html"] = ("<p>Still need it? Select the button below and confirm. The agent is "
                                      "reactivated for your own use within a few minutes.</p>"
                                      + ack["ack_button_html"] + ack["ack_expiry_html"])
        values = {**self._common(user, agent), "inactivity_days": inactivity_days,
                  "retired_on": datetime.now(timezone.utc).strftime("%d %b %Y"), "archive_on": archive_on,
                  "after_retirement_html": after, **ack}
        return self._send([self._address(user)], "retired_notice", values)

    def send_archived_notice(self, user: dict, agent: dict, reference: str, deletion_mode: str) -> dict:
        deletion = {"manual": "<p>It will now be <b>deleted from Microsoft 365</b> by an administrator.</p>",
                    "api": "<p>It is now being <b>deleted from Microsoft 365</b>.</p>"}.get(
                        deletion_mode, "<p>It stays blocked in Microsoft 365.</p>")
        values = {**self._common(user, agent), "archived_on": datetime.now(timezone.utc).strftime("%d %b %Y"),
                  "archive_reference": reference, "deletion_html": deletion}
        return self._send([self._address(user)], "archived_notice", values)

    def send_ownership_transferred(self, user: dict, agent: dict, previous_owner: str | None) -> dict:
        return self._send([self._address(user)], "ownership_transferred",
                          {**self._common(user, agent), "previous_owner": previous_owner})

    def send_admin_alert(self, subject: str, lines: dict[str, Any],
                         extra_recipients: list[str] | None = None) -> dict | None:
        to = list(dict.fromkeys(self.admin_emails + (extra_recipients or [])))
        if not to:
            return None
        rows = "".join(f"<tr><td style='padding:2px 12px 2px 0;vertical-align:top'><b>{_e(k)}</b></td>"
                       f"<td>{_e(v)}</td></tr>" for k, v in lines.items())
        return self._send(to, "admin_alert", {**self._common(None, None), "subject": subject,
                                              "details_html": rows})


def preview_emails(mailer: Mailer, out_dir: str) -> list[str]:
    """Render every email with sample data into out_dir (for reviewing customisations)."""
    class _Sample:
        def request(self, method: str, url: str, **kw: Any) -> Any:
            class R:
                @staticmethod
                def json() -> dict:
                    return {"displayName": "Finance Team"}
            return R()
    original_graph, mailer.graph = mailer.graph, _Sample()
    mailer.outbox, saved_admins = [], mailer.admin_emails
    mailer.admin_emails = mailer.admin_emails or ["admins@example.com"]
    user = {"id": "u", "displayName": "Olivia Owner", "mail": "olivia@example.com"}
    agent = {"id": "P_00000000-0000-0000-0000-000000000000", "displayName": "Sales Helper"}
    link, expires = "https://forms.office.com/example?token=sample", "01 Jan 2027 09:00 UTC"
    try:
        mailer.send_welcome(user, agent)
        mailer.send_share_notice(user, agent, [{"resourceType": "group", "resourceId": "g"}], link, expires)
        for reason in ("sharing removed", "agent approved in the registry",
                       "configuration drift rectified", "owner reactivated a retired agent"):
            mailer.send_restored(user, agent, reason)
        mailer.send_drift_notice(user, agent, [{"rule": "EMBEDDED-FILES", "message": "Embedded files were added"}],
                                 {"approval": {"requestId": "REQ-0042"}}, link, expires)
        mailer.send_inactivity_warning(user, agent, "01 Sep 2026", "01 Jan 2027", 90, notice_days=30,
                                       days_left=30, archive_after_days=30, deletion_mode="manual")
        mailer.send_inactivity_warning(user, agent, "01 Sep 2026", "01 Jan 2027", 90, notice_days=30,
                                       days_left=7, reminder=True, archive_after_days=30,
                                       deletion_mode="manual")
        mailer.send_retired_notice(user, agent, 90, link, expires, archive_on="31 Jan 2027",
                                   archive_after_days=30, deletion_mode="manual")
        mailer.send_archived_notice(user, agent, "2027/P_00000000", "manual")
        mailer.send_ownership_transferred(user, agent, "former-owner@example.com")
        mailer.send_admin_alert("Agent ready for deletion", {"Agent": "Sales Helper", "Next step": "Delete it"})
        os.makedirs(out_dir, exist_ok=True)
        written = []
        for i, mail in enumerate(mailer.outbox, 1):
            label = mail["template"] + (f".{mail['variant']}" if mail.get("variant") and
                                         mail["variant"] != "reminder" else "")
            name = os.path.join(out_dir, f"{i:02d}-{label}.html")
            with open(name, "w", encoding="utf-8") as fh:
                fh.write(f"<!-- Subject: {html.escape(mail['subject'])} -->\n{mail['html']}")
            written.append(name)
        return written
    finally:
        mailer.graph, mailer.outbox, mailer.admin_emails = original_graph, None, saved_admins
