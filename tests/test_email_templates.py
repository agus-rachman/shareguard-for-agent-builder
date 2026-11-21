# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""Customisable email templates."""
import pytest

from absg.core import main
from absg.mail import (DEFAULT_TEMPLATES, Mailer, TemplateError, check_templates, load_templates,
                       parse_template)

USER = {"id": "u", "displayName": "Olivia <Owner>", "mail": "olivia@contoso.com"}
AGENT = {"id": "p1", "displayName": "Sales & Co"}


class Graph:
    def __init__(self):
        self.sent = []

    def request(self, method, url, json=None, **kw):
        self.sent.append(json)


def test_defaults_are_valid_and_escape_values():
    assert check_templates(DEFAULT_TEMPLATES) == []
    g = Graph()
    Mailer(g, "sg@contoso.com").send_welcome(USER, AGENT)
    body = g.sent[0]["message"]["body"]["content"]
    assert "Olivia &lt;Owner&gt;" in body and "Sales &amp; Co" in body
    assert g.sent[0]["message"]["internetMessageHeaders"][0]["value"] == "welcome"


def test_override_branding_and_layout():
    templates = load_templates({
        "welcome.html": "Subject: Hello {{owner_name}} from {{brand_name}}\n<p>Custom for {{agent_name}}</p>",
        "layout.html": "<div class='x'>{{content_html}}<small>{{footer_html}}</small></div>",
    })
    g = Graph()
    m = Mailer(g, "sg@contoso.com", brand_name="Contoso Agent Guard", subject_prefix="[IT]",
               footer="Questions? Visit go/agents.", templates=templates)
    m.send_welcome(USER, AGENT)
    msg = g.sent[0]["message"]
    assert msg["subject"] == "[IT] Hello Olivia <Owner> from Contoso Agent Guard"
    assert msg["body"]["content"] == ("<div class='x'><p>Custom for Sales &amp; Co</p>"
                                      "<small>Questions? Visit go/agents.</small></div>")


def test_variant_falls_back_to_base_template():
    templates = load_templates({"restored.html": "Subject: Back: {{agent_name}}\n<p>{{restore_reason}}</p>"})
    g = Graph()
    m = Mailer(g, "sg@contoso.com", templates=templates)
    m.send_restored(USER, AGENT, "sharing removed")
    assert g.sent[0]["message"]["subject"] == "Back: Sales & Co"
    specific = load_templates({"restored.reactivated.html": "Subject: Alive\n<p>x</p>"})
    m = Mailer(g, "sg@contoso.com", templates=specific)
    m.send_restored(USER, AGENT, "owner reactivated a retired agent")
    m.send_restored(USER, AGENT, "sharing removed")
    assert [s["message"]["subject"] for s in g.sent[1:]] == ["Alive", "Your Copilot agent 'Sales & Co' is unblocked"]


def test_template_problems_are_rejected():
    with pytest.raises(TemplateError, match="unknown placeholder"):
        load_templates({"welcome.html": "Subject: Hi\n{{favourite_colour}}"})
    with pytest.raises(TemplateError, match="unknown template"):
        load_templates({"goodbye.html": "Subject: Bye\nx"})
    with pytest.raises(TemplateError, match="Subject"):
        load_templates({"welcome.html": "<p>no subject</p>"})
    with pytest.raises(TemplateError, match="content_html"):
        load_templates({"layout.html": "<p>nothing</p>"})
    assert parse_template("﻿Subject: A\nB") == ("A", "B")


def test_export_check_and_preview_commands(tmp_path, capsys):
    out = tmp_path / "templates"
    assert main(["--export-email-templates", str(out)]) == 0
    assert (out / "retired_notice.html").read_text().startswith("Subject: ")
    assert main(["--check-email-templates", str(out)]) == 0
    (out / "welcome.html").write_text("Subject: Hi\n{{nope}}")
    assert main(["--check-email-templates", str(out)]) == 1
    (out / "welcome.html").write_text("Subject: Hi {{owner_name}}\n<p>ok</p>")
    preview = tmp_path / "preview"
    assert main(["--preview-emails", str(preview), "--templates", str(out)]) == 0
    files = sorted(p.name for p in preview.iterdir())
    assert "01-welcome.html" in files and any("archived_notice" in f for f in files)
    assert any("inactivity_reminder" in f for f in files)
    assert "Hi Olivia Owner" in (preview / "01-welcome.html").read_text()
