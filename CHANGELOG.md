# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Azure deployment.** Azure Functions app (`azure/functionapp`) with a guard role (timer scan, nightly audit chain check) and a separate registry signer role; Bicep template (`azure/infra`) for Flex Consumption, VNet with NAT gateway, private Key Vault (HSM key) and storage, managed identities, role assignments and alerts; provisioning scripts (`azure/scripts`) for Graph permissions, `Sites.Selected` site access, Exchange RBAC for Applications, SharePoint lists and libraries, and the delegated client; `azure/deploy.sh`; [Azure deployment guide](docs/azure-deployment.md).
- Managed identity authentication and a Key Vault client (`absg.cloud`), with no Azure SDK dependency.
- SharePoint storage (`storage_backend: "sharepoint"`): eTag-checked state, daily hash-chained audit files with a retention label, registry from the *Approved Agents* list, acknowledgements from a Microsoft Forms + Power Automate list. `--verify-audit-store` checks the chain wherever it's stored.
- Registry signer (`absg.signer`): turns approved SharePoint sharing requests into signed entries with Key Vault, checking criteria, segregation of duties, expiry, audience and owners; handles revocation; writes its own audit chain.
- ES256 registry signatures (ECDSA P-256, as Key Vault produces), and RS256 keys (`--registry-keygen --algorithm rs256`, `--registry-export-jwk`). The signature algorithm is part of the signed content.
- Multiple owners: every owner is notified with a personal link; registry entries list `owners`; new rules `OWNER-UNREGISTERED`, `OWNER-NONE-ACTIVE` and `OWNER-INACTIVE`.
- Ownerless agents: owner account checks and `ownerless_action` (`report`, `reassign_to_manager`, `block`).
- Inactivity lifecycle: a notice to every owner `inactivity_notice_days` (default 30) before the agent becomes inactive, never less than the full notice; a reminder (`inactivity_reminder_days`); retirement (a `retired` block) with self-service reactivation; after `archive_after_days`, an archive of the full definition and a manifest in a restricted SharePoint library (or a local folder), with a retention label; then deletion from Microsoft 365, as an admin task that ShareGuard requests, reminds and verifies (`deletion_mode: manual`), or by an experimental API call (`api`). Reactivation is possible until deletion and cancels it.
- Customisation in one place ([customisation guide](docs/customisation.md)): the Bicep parameters file now holds `naming` (every Azure, Key Vault, Entra and Exchange name), `sharePointNames`, `archiveSiteId`, `lifecycle`, `email`, `approvalCriteria`, `maxApprovalDays`, `auditCheckSchedule` and `notRunningAlertMinutes`. Every provisioning script takes `-ParametersFile`, and finds the managed identities by name.
- Email templates: every email is a template that can be replaced, with branding settings (`email_brand_name`, `email_subject_prefix`, `email_footer`, `email_button_colour`), templates from a local folder or SharePoint, and `--export-email-templates`, `--check-email-templates` and `--preview-emails`. New emails: retirement reminder, archived notice.
- Configurable sharing criteria (`approval_criteria`), with matching columns created in the requests list.
- Configuration from `ABSG_CONFIG_JSON`; `audit_to_log` sends audit records to Application Insights.

### Changed

- Group names are looked up through `/groups`, so `GroupMember.Read.All` replaces `Directory.Read.All`.
- Welcome emails skip disabled or deleted accounts.
- `inactivity_warning_days` is now `inactivity_notice_days` (the old name is still accepted).

## [0.1.0] - 2026-11-21

### Added

- Daemon that blocks shared Microsoft 365 Copilot Agent Builder agents through the Package Management API, and unblocks them once sharing is removed. It only unblocks agents it blocked itself.
- Signed (Ed25519) approved-agent registry with approval criteria, risk rating, approved audience and configuration baseline. Includes governance commands: `--registry-keygen`, `--registry-draft`, `--registry-sign` and `--registry-validate`.
- Continuous drift detection for approved agents: embedded files, new or changed knowledge sources, unscoped knowledge, actions, worker agents, overrides, sharing beyond the approved audience, and unreadable definitions (fails closed).
- Owner emails through Microsoft Graph: welcome (with a first-run baseline), share notice, drift notice, restored, and admin alerts. Every message carries an `X-ABSG` header.
- Owner acknowledgement flow: signed, expiring, single-use links; confirmation by POST only (safe against link scanners); optional identity check behind an authenticating proxy; sharing removed on the owner's behalf with verification before unblocking.
- Hash-chained, tamper-evident JSON Lines audit trail with case IDs, plus the `--verify-audit` and `--audit-history` commands. The daemon refuses to start if the chain is broken.
- Safety features: dry run, circuit breaker, last-good registry on load failure, retries with `Retry-After`.
- Reference deployment architecture for Microsoft 365 (Azure Functions, SharePoint Online, Exchange Online, Key Vault).

### Security

- The built-in acknowledgement endpoint listens on `127.0.0.1` by default.

[Unreleased]: https://github.com/OWNER/absg/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/OWNER/absg/releases/tag/v0.1.0
