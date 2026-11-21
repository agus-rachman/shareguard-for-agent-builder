# Security policy

## Reporting a vulnerability

**Please don't report security vulnerabilities through public GitHub issues, discussions or pull requests.**

Report them privately through GitHub's **[private vulnerability reporting](https://github.com/OWNER/absg/security/advisories/new)** (Security tab → *Report a vulnerability*).

Please include:

- a description of the issue and its impact;
- steps to reproduce, or a proof of concept;
- the affected version or commit;
- any suggested fix.

Remove tenant identifiers, tokens, user data and audit logs from your report.

We aim to acknowledge reports within 5 business days, and to agree a disclosure timeline with you once we've assessed the issue.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.x (latest release) | ✅ |
| Older 0.x releases | ❌ (please upgrade) |

## Scope

In scope: this repository's code and documentation, including token handling, signature verification, the audit hash chain, the acknowledgement endpoint, and permission guidance.

Out of scope: vulnerabilities in Microsoft 365, Microsoft Graph, Entra ID or other Microsoft services. Report those to the [Microsoft Security Response Center](https://msrc.microsoft.com/).

## Hardening guidance

ShareGuard for Agent Builder holds permissions that can block and unblock every agent in a tenant. Before production:

- Use a certificate or managed identity, never a client secret in a file.
- Scope `Mail.Send` to a single mailbox with Exchange RBAC for Applications.
- Keep the registry signing **private key offline** (or in an HSM). The daemon needs only the public key.
- Store the audit trail somewhere immutable, and verify it on a schedule with `absg --verify-audit`.
- Restrict the delegated account (it blocks, unblocks and removes sharing) with Conditional Access, and monitor its sign-ins.
- If you enable the built-in acknowledgement endpoint, run it only behind an authenticating proxy with `ack_require_identity: true`.

See [docs/deployment-architecture.md](docs/deployment-architecture.md) for a full least-privilege design.
