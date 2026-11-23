# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- Requesters could approve their own sharing requests: item-level permissions let them edit `Status`, `ApprovedBy`, the criteria and `PolicyJson` on their own item, and the signer trusted those fields. `Provision-AbsgSharePoint.ps1` now gives requesters an *ABSG Submit* permission level (add and read own, no edits). With `signer_trusted_editors` set, the signer also checks each request's version history. It refuses to register a request twice, which could otherwise renew an approval and re-baseline a drifted agent, and treats `RequestedBy` as the requester.
- An earlier signed registry entry could be put back, for example from SharePoint version history, to undo a revocation: its signature still verified. Entries now carry a signed `signedAt`. The guard records the newest one it has seen for each agent in its state, and rejects older entries (`registry_rollback_rejected`, with an admin alert).

- The signer took the configuration baseline when it ran, not when reviewers looked at the agent. An owner could add embedded files between approval and signing, and they became part of the approved baseline. The signer now records the configuration while a request is in review (`ReviewConfigHash`, plus a readable `ReviewConfigSummary` for reviewers). It refuses to register the agent unless it still matches, refuses agents whose definition can't be read, and refuses a KS-02 Pass when embedded files are present.
- Lifting a retired or ownerless block (reactivation, or an active owner assigned again) unblocked the agent even if it was shared and unapproved, until the next cycle blocked it again. Such an agent now stays blocked under the sharing policy, with a new case and a notice (`block_reason_changed`). An approved, compliant agent is still released straight away.

### Fixed

- Block, unblock and reassign now run as the delegated account (`block_identity: "delegated"`, the default), because Microsoft documents them with delegated permissions only; with no delegated client configured, ShareGuard falls back to the application with a warning. A refused block, unblock or reassign records `enforcement_identity_failed` and alerts the admins once per cycle, with an Azure Monitor alert rule. `block`, `unblock` and `ownership_reassigned` audit records name the `actingIdentity`.
- The Package Management API's write methods (update, block, unblock, reassign) are documented only under `/beta`, but were sent to v1.0. They now go to `graph_beta_base` (default `https://graph.microsoft.com/beta`), as does the experimental delete call. Reads (list, get) stay on v1.0.
- Azure deployment guide: the `local.json` example for `--login-delegated` was refused by the settings check (it needs `client_id` and a credential setting), and the registry key rotation steps relied on re-approving registered requests, which the signer now refuses.
- A cycle that failed part-way, for example when the package list failed on a later page, lost the state of blocks it had already issued. Those agents then looked like admin blocks and were never released. State is now saved after each block and at the end of every cycle, and an unexpected error on one package no longer aborts the cycle.
- Azure Functions start every invocation with no registry in memory, so one failed registry read blocked every approved, shared agent. The last good registry copy is now kept in the state and re-verified when it's used. With no copy at all, decisions on shared agents are deferred (`decision_deferred`).
- Audit records that the SharePoint backend couldn't write were lost when the invocation ended. They're now kept in the state and written first by the next invocation, either joined onto the stored chain or dropped if they were written after all.

### Added

- Daily sharing limit per owner (`daily_share_limit_per_owner`, default 5): once that many of one owner's agents have been blocked for sharing in a UTC day, each further one stays blocked until 00:00 UTC the next day, even after its sharing is removed, or until governance releases it. New audit events `daily_share_limit_locked` and `lock_expired`, and a `locked_notice.daily` template.
- Repeat-violation lock: the Nth block of the same agent within a window (default 3 in 30 days; `repeat_violation_limit`, `repeat_violation_window_days`, `repeat_violation_block_types`) locks it. A locked agent stays blocked after the sharing or change is undone, gets no self-service link, and is released only by governance: an item in the new *Agent Lock Releases* list (Azure), or `absg --release-lock` (local). New audit events `repeat_violation_locked`, `unblock_withheld`, `lock_released`, `lock_release_rejected`, a *locked* owner email template, an admin alert and an Azure Monitor rule.
- [Test environment setup guide](docs/test-environment-setup.md): an end-to-end test environment in a separate tenant, smoke checks in dry run, 18 test scenarios with expected results, troubleshooting and teardown, and a local Windows path for testers without an Azure subscription.
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
