# Operations guide

How ShareGuard for Agent Builder behaves, how to configure and run it, and how to operate the registry and audit trail. To change names, schedules, lifecycle periods, criteria or email wording, see the [customisation guide](customisation.md).

**ShareGuard for Agent Builder** (short name **ShareGuard**) enforces a **"build for yourself, don't share"** policy for Microsoft 365 Copilot Agent Builder agents.

| Agent state | Action |
|---|---|
| Agent Builder agent, not shared | Nothing |
| Shared with any user/group (or `availableTo = all`) | **Block** (tenant-wide), record in state |
| Blocked by the guard, sharing removed | **Unblock**, clear state |
| Blocked by the guard, someone unblocked it while still shared | **Re-block** |
| Blocked by an admin for another reason | Never touched |
| Copilot Studio / 3P / other agents | Ignored (filter is `platform eq 'Microsoft 365 Copilot Agent Builder'`) |
| Listed in `exempt_ids` | Allowed to be shared; any guard block is released |
| A user's **first** Agent Builder agent | **Welcome email** with the rules |
| Agent blocked | **Notice email** to the owner with a personal "remove sharing and unblock" link |
| Owner confirms through the link | Guard **removes sharing on the owner's behalf**, checks it's gone, **unblocks**, emails the owner |
| Shared, with a **valid, signed registry approval**, configuration matches the approval | Allowed. **Validated every cycle.** |
| Approved agent **drifts**: config changed, or shared beyond the approved audience | **Block** (`blockType: drift`), owner and governance notified |
| Drift rectified, or sharing removed | **Unblock** |
| Registry approval expired, suspended, revoked, tampered with or unsigned | Treated as unapproved: the normal no-sharing block applies |
| Agent with several owners | Every owner gets the notices, each with a personal link; any of them can confirm |
| Approved agent gains an owner who isn't named in the approval | **Block** (`OWNER-UNREGISTERED`) until governance re-approves with the new owner |
| None of an agent's owners has an active account | Report to admins, reassign to a former owner's manager, or block (`ownerless_action`) |
| Agent not used for `inactivity_days` | Owners told `inactivity_notice_days` before that it's bound for retirement, and reminded; then **retired** (blocked), **archived** after `archive_after_days`, and **deleted** from Microsoft 365. An owner can reactivate it until it's deleted. |

## How it works

The daemon polls the Agent 365 **Package Management API** (Microsoft Graph):

| Call | Graph version |
|---|---|
| `GET /copilot/admin/catalog/packages?$filter=platform eq 'Microsoft 365 Copilot Agent Builder'` | v1.0 |
| `GET /copilot/admin/catalog/packages/{id}`: reads `sharedWithUsersAndGroups`, `availableTo`, `isBlocked` | v1.0 |
| `POST /copilot/admin/catalog/packages/{id}/block` and `/unblock` | beta |
| `PATCH /copilot/admin/catalog/packages/{id}` (sharing removal) and `POST …/reassign` | beta |

Microsoft documents the write methods (update, block, unblock, reassign) only under `/beta`, as a preview: they can change without notice. ShareGuard sends them to `graph_beta_base` (default `https://graph.microsoft.com/beta`) and everything else to `graph_base` (default v1.0). Microsoft's pages also list only delegated permissions for these methods: see the pilot checklist.

It saves the IDs of agents it blocked to a state file, so it only ever unblocks its own blocks.

## Prerequisites

1. **Microsoft Agent 365 licence** in the tenant (the API needs it).
2. **Guard app registration** (confidential client, certificate credential), with these admin-consented **application** permissions:

   | Permission | Used for |
   |---|---|
   | `CopilotPackages.ReadWrite.All` | List, read, block and unblock agents |
   | `Mail.Send` | Welcome, notice, restored and admin emails. **Restrict it to the sender mailbox** with Exchange Online RBAC for Applications (or an application access policy). |
   | `User.Read.All` | Look up owners' names, email addresses and account status |
   | `GroupMember.Read.All` | Show the names of the groups an agent was shared with, in the notice |

3. **Delegated identity for blocking, unblocking, reassigning and removing sharing.** Microsoft documents block, unblock, reassign and update (`PATCH`) with **delegated permissions only**. So ShareGuard makes those calls as a service account (`block_identity: "delegated"`, the default), and you need:
   - A **public client app registration** with the delegated permission `CopilotPackages.ReadWrite.All`, and "Allow public client flows" turned on.
   - A **dedicated service account** (for example `svc-absg@`) holding an admin role that can manage agents. Use the least-privileged role that works in your pilot.
   - A one-off sign-in: `absg --config config.json --login-delegated` (device code). After that, the daemon refreshes the token silently from `delegated_token_cache`. Store the cache like a secret (it's written with mode 600). If Conditional Access sign-in frequency or token revocation expires the session, the daemon records the failure and falls back to admin escalation. Run `--login-delegated` again to restore it.
   - If you leave `delegated_client_id` unset, the guard logs a warning and blocks and unblocks as the application instead, which Microsoft's documentation says isn't supported; sharing removal becomes **manual** (admins get an email, and the guard unblocks once they've removed sharing). Set `block_identity: "application"` only if your tenant accepts app-only block calls.
   - If the account's block or unblock is refused (expired sign-in, missing role), the guard records `enforcement_identity_failed` and alerts the admins, once per cycle, until it works again.
4. **Acknowledgement endpoint hosting.** The daemon runs a small web endpoint (`ack_listen_host:ack_listen_port`, path `/ack`). Publish it at `ack_base_url` **behind Entra ID authentication**, for example Azure Container Apps or App Service built-in authentication, or Entra application proxy. That way only signed-in staff can reach it, and the proxy passes the user's object ID in `X-MS-CLIENT-PRINCIPAL-ID`. Keep `ack_require_identity: true`, so only the agent's owner can confirm.
5. Python 3.10+ and `pip install absg` (or `pip install -e .` from a clone).

## Run

```bash
export ABSG_TENANT_ID=... ABSG_CLIENT_ID=... ABSG_CERT_PATH=/secrets/guard.pem ABSG_CERT_THUMBPRINT=...
absg --config config.json --dry-run --once   # see what would happen
absg --config config.json --login-delegated  # one-off sign-in of the service account
absg --config config.json                    # run as a daemon
```

Secrets go in environment variables: `ABSG_CLIENT_SECRET` or `ABSG_CERT_*`, `ABSG_ACK_SECRET` (generate one with `python -c "import secrets;print(secrets.token_urlsafe(48))"`) and `ABSG_MAIL_SENDER`.

Hosting options:
- **Azure Functions with SharePoint storage** (recommended): see the [Azure deployment guide](azure-deployment.md). State, audit, registry and acknowledgements live in SharePoint, secrets and the registry signing key in Key Vault, and both Function apps run as managed identities.
- A container (Azure Container Apps or AKS) or a systemd service with local files (`storage_backend: "file"`, the default).

## Approved-agent registry and drift detection

Users submit agents for sharing through your governance process, which lives outside the daemon. An agent that meets the risk-rating criteria is added to the **registry**: a JSON whitelist the daemon reads every cycle (`registry_file`). See [`examples/registry.example.json`](../examples/registry.example.json).

### What a registry entry records

| Section | Contents |
|---|---|
| Identity | `packageId`, `manifestId` (must match, so an entry can't be reused for another agent), `displayName`, `ownerId` |
| `status` | `approved`, or `suspended` / `revoked` (either one removes the approval immediately) |
| `approval` | `requestId`, `approvedBy`, `approvedAt`, `expiresAt`, `riskRating`, `riskScore`, the **`criteria`** assessed (`id`, `description`, `result`, `evidence` link), `conditions`, `notes` |
| `sharing.allowedPrincipals` | The users and groups the agent is approved to be shared with. Sharing with anyone else is a violation (`SHARE-SCOPE`), which closes the "share with a giant group" loophole. |
| `baseline` | A normalised snapshot of the approved configuration, plus its hash: knowledge sources and scopes, capabilities, embedded files, actions, worker agents, overrides, and an instructions hash |
| `policy` | `driftMode` (`baseline` or `policy`), `instructionsChange` (`warn`, `block` or `ignore`), `allowEmbeddedFiles`, `allowUnscoped`, and for policy mode `allowedCapabilities`, `allowedKnowledgeUrlPrefixes` and `allowActions` |
| `governanceContacts` | Also emailed when this agent is drift-blocked |
| `signedAt`, `signatureAlgorithm`, `signature` | When the entry was signed, and the Ed25519, ES256 or RS256 signature over everything else |

### Signed entries

Governance signs each entry with a **private key kept offline**. The daemon has only the **public key** (`registry_public_key_file`). Entries that are unsigned, altered after signing, expired, suspended, or have a `manifestId` mismatch are ignored. A shared agent with such an entry is blocked under the normal no-sharing policy, and the reason is recorded in `approvalStatus`. This means write access to the registry file isn't enough to whitelist an agent.

Putting back an *earlier* signed entry doesn't work either, for example restoring an `approved` entry after it was revoked. The signature on an old entry still verifies, so the guard also records, in its own state, the newest `signedAt` it has seen for each agent. An entry signed before that is rejected: `registry_rollback_rejected` is audited, the admins are alerted, and the agent is treated as unapproved until a current entry is signed. Because of this, keep the guard's state somewhere that registry editors can't write to. When signing by hand, re-sign an entry to change it; never copy back an old file.

### Governance workflow

```bash
# One-off: create the signing key pair (store the private key in a vault or HSM, never on the daemon host)
absg --registry-keygen ./keys

# 1. Draft an entry from the agent's live configuration (captures the baseline)
absg --config config.json --registry-draft P_7c1e... > GOV-1042.json

# 2. Reviewers complete the approval section: criteria, risk rating, approver, expiry, audience

# 3. Sign it. This refuses to sign while any "<placeholder>" fields remain.
absg --registry-sign GOV-1042.json --key ./keys/absg_registry_signing_key.pem > GOV-1042.signed.json

# 4. Add the signed entry to the registry file's "agents" array (via your change process)

# Any time: validate every approved agent against its live configuration (exit 3 if any fail)
absg --config config.json --registry-validate
```

The registry is a JSON file, so you can generate it from a SharePoint list, Dataverse table or Git repository. Signing is what makes it trustworthy, not where it's stored. If you need a different source, replace `absg.registry.Registry.load()` with your own loader.

### Continuous validation

For every **shared** agent with a valid approval, each cycle:
1. Reads the live declarative agent definition from the package's `elementDetails` and normalises it into a profile. URLs are compared case-insensitively and in any order.
2. Compares the profile with the baseline (or the policy constraints) and the actual audience with `allowedPrincipals`.
3. Records a `registry_validation` audit entry whenever the result changes, or every cycle with `audit_no_action`.

| Rule | Severity | Example |
|---|---|---|
| `EMBEDDED-FILES` | block | Approved for SharePoint knowledge, then **embedded files uploaded**. A `sensitivity_label` also counts, because the schema only allows it when files are embedded. |
| `DRIFT-CAPABILITY-ADDED` | block | Web search, Copilot connectors, email or code interpreter added |
| `DRIFT-SCOPE-CHANGED` | block | Another SharePoint site added, or a web search site changed |
| `UNSCOPED-KNOWLEDGE` | block | SharePoint or web search with no scope, meaning **all** content the user can reach |
| `DRIFT-ACTIONS`, `DRIFT-WORKER-AGENTS`, `DRIFT-*-OVERRIDES` | block | Plugins, worker agents or overrides changed |
| `SHARE-SCOPE` | block | Shared with users or groups outside the approved audience |
| `CONFIG-UNREADABLE` | block (`drift_fail_closed`) | The definition can't be read, so the agent can't be validated |
| `POLICY-*` | block | In `policy` mode: a capability, knowledge location or action outside the constraints |
| `DRIFT-INSTRUCTIONS` | warn (default) | Instructions edited. Set `instructionsChange: "block"` to enforce. |
| `DRIFT-CAPABILITY-REMOVED` | warn | The agent was narrowed, which doesn't increase risk |

`baseline` mode (the default) treats **any** knowledge or capability change as drift. `policy` mode lets the owner change things within approved limits, for example adding pages under the approved SharePoint site.

### When drift is detected

1. The agent is blocked with `blockType: "drift"`. The violations, approval reference and live config hash are all recorded under a new `caseId`.
2. The **owner** gets a drift notice listing each violation. It gives two options: undo the change (the agent is re-checked every cycle and unblocked automatically once it matches), or use the link to have sharing removed and keep the agent for personal use.
3. **Governance contacts** and admins get an alert.
4. While it's blocked, any change to the violations is recorded (`violation_updated`).
5. When the configuration matches the approval again, the agent is unblocked (reason: `configuration drift rectified`) and the owner gets a "restored" email. If sharing is removed instead, it's unblocked as a private agent.
6. Changes to the registry are recorded too: `registry_entry_added`, `registry_entry_updated`, `registry_entry_removed` (with approval details, criteria and hashes) and `registry_entry_invalid`. Each `cycle_start` records the registry file hash, so you can show which version of the whitelist was in force for any decision.

**Fail-safes:** if the registry file is corrupt or missing, the daemon keeps the last good copy and records an `error`, instead of treating every approval as withdrawn. The circuit breaker also limits blocks per cycle.

## Repeat violations

Removing sharing releases a blocked agent, so without a limit a maker could unshare, wait for the unblock, share again and use the agent until the next cycle, over and over. ShareGuard counts each block of the same agent, and the Nth one within the window **locks** it.

| Setting | Default | Meaning |
|---|---|---|
| `repeat_violation_limit` | `3` | The block that locks the agent (3 = the third block in the window). `0` turns it off. |
| `repeat_violation_window_days` | `30` | The window, in days: `1` for a day, `7` for a week, `30` for a month. Older blocks don't count. |
| `repeat_violation_block_types` | `["sharing", "drift"]` | What counts: sharing without approval, and an approved agent breaking its approval. |

A locked agent stays blocked even after the sharing or the change is undone, and every unblock is withheld (`unblock_withheld`, recorded once per reason). The owners get a *locked* notice with no self-service link, and an owner confirmation that arrives anyway is rejected. Admins and the agent's governance contacts get an alert, and an Azure Monitor rule fires on `repeat_violation_locked`.

Only governance can release it:

- **Azure (SharePoint storage):** add an item to *Agent Lock Releases* on the Operations site, with `Title` = the package id and a `Reason`. Only the group given to `Provision-AbsgSharePoint.ps1 -GovernanceGroup` can write there. SharePoint records who created the item.
- **Local files:** `absg --config config.json --release-lock <package id> --by <your UPN> --reason "<text>"`. `absg --config config.json --list-locked` lists the locked agents.

On its next cycle the guard applies a release made after the lock: it records `lock_released` with who released it and why, clears the agent's violation count, and then applies the normal policy (unblocked if it's no longer shared; still blocked, with a self-service link, if it is). A release from one of the agent's own owners, or one made before the lock, is refused (`lock_release_rejected`, or ignored). If an admin unblocks a locked agent by hand, that counts as a release, but its violation count is kept, so its next violation locks it again at once.

### Daily sharing limit per owner

A maker who shares many agents at once, or makes copies of an agent to start each repeat-violation count again, is held by a daily limit. Once **5** of one owner's agents have been blocked for sharing on the same day (UTC), each further one is **held**: it stays blocked until 00:00 UTC the next day, even if its sharing is removed.

| Setting | Default | Meaning |
|---|---|---|
| `daily_share_limit_per_owner` | `5` | How many of one owner's agents may be blocked for sharing in a day before the rest are held. `0` turns it off. |

An agent counts once a day, however often it's reblocked, and the count starts again each UTC day. For an agent with several owners, the owner with the most blocked agents that day decides. A held agent works like a locked one: unblocks are withheld, owner confirmations are rejected, the owners get a notice saying when it's released (with no self-service link), and admins get an alert (`daily_share_limit_locked`). When the hold ends (`lock_expired`), the normal policy applies: it's unblocked if its sharing is gone, and if it's still shared the owners get the usual notice with a link. Governance can release a held agent early in the same way as a locked one. A repeat-violation lock takes precedence: an agent that reaches both stays locked until governance releases it.

## Changes made and undone between checks

A change made and undone between two checks, such as sharing an agent for a few minutes or adding a file and removing it, leaves the agent's configuration as it was, so the normal checks can't see it. Two signals catch it afterwards. Neither prevents it.

### Usage from the audit log

Every use of an agent in Copilot is audited in Microsoft Purview as a `CopilotInteraction` record, with the user and the agent. If anyone other than an owner used an unapproved agent, it was shared at that moment; if anyone outside the approved audience used an approved one, it was shared beyond it. With `usage_monitoring` on, the guard reads these records through the Graph audit log query API (v1.0) and records each finding as `usage_violation`, with the user, the number of interactions and when, plus an admin alert and an Azure Monitor rule.

| Setting | Default | Meaning |
|---|---|---|
| `usage_monitoring` | `false` | Turn it on once the guard has the permission below. |
| `usage_counts_as_violation` | `true` | A finding counts towards the [repeat-violation lock](#repeat-violations), at most once a day per agent, and not when a block was already counted within a day of the use. Reaching the limit blocks and locks the agent, even if it's no longer shared. |
| `usage_record_types` | `["copilotInteraction"]` | Audit record types queried. |
| `usage_agent_id_keys` | `["AgentId"]` | Where in a record's `auditData` the agent is named. An agent matches when its package id or manifest id appears in that value. |
| `usage_lookback_hours` | `24` | How far back the first query reaches. |
| `usage_overlap_minutes` | `120` | Each query also re-reads this much of the previous window, because audit records can arrive late. Records already seen are skipped. |
| `usage_query_timeout_minutes` | `60` | A query that hasn't finished by then is dropped and started again. |

The query is asynchronous: the guard creates it in one cycle and reads its results in a later one, so findings arrive with the audit log's own delay (minutes to hours). Use by an owner, by an exempt agent's users, or of an agent whose owner isn't known is never counted. When a group membership check fails, the use isn't counted either.

Permission: the application permission `AuditLogsQuery.Read.All` on the guard's identity (`Grant-AbsgGraphPermissions.ps1 -UsageMonitoring`). Microsoft also documents narrower, per-service permissions; check which one your tenant needs in the pilot.

### Edits undone between checks

The guard remembers each agent's `lastModifiedDateTime` and a hash of its definition, name, description, sharing state and blocked state. If the time has moved but all of those read exactly as before, something was changed and changed back in between (or saved unchanged). That's recorded as `edit_between_checks`; for an approved agent, the admins and its governance contacts are also alerted.

| `between_check_edits` | Effect |
|---|---|
| `report` (default) | Audit record; admin alert for approved agents |
| `violation` | Also counts towards the repeat-violation lock, as `drift` for an approved agent and `sharing` otherwise |
| `off` | Not checked |

It shows that something changed, not what, and it relies on Microsoft updating `lastModifiedDateTime` for the changes that matter: check that in the pilot before using `violation`.

## Ownership and lifecycle

### Multiple owners

Agent Builder agents can have several owners with equal rights. ShareGuard keeps a list of owners for every agent (`OwnerResolver.resolve_all`): from `owner_map` (a value may be a list), from `owner_fields` (a field may hold a list of IDs or of objects with `id`), or the learned or inferred owner. Every owner gets each notice with their own acknowledgement link, and any of them can confirm.

Registry entries name their owners in `owners` (older entries with a single `ownerId` still work). Two rules apply to approved agents:

| Rule | Severity | Meaning |
|---|---|---|
| `OWNER-UNREGISTERED` | block | The platform reports an owner who isn't named in the approval, for example a co-owner added after approval, who can edit and re-share the agent. Needs `owner_fields` that expose owners; skipped otherwise. Turn off per entry with `policy.requireRegisteredOwners: false`. |
| `OWNER-NONE-ACTIVE` | block | None of the named owners has an active account (`policy.requireActiveOwner`) |
| `OWNER-INACTIVE` | warn | Some named owners are deleted or disabled |

> The Package Management API doesn't document an owners property. Check in your pilot what the package detail returns and set `owner_fields` (for example `["owners"]`). Until then, co-owner detection relies on `owner_map`.

### Ownerless agents

With `owner_status_checks` (default on), owners' accounts are checked each cycle: a deleted (404) or disabled account is inactive. When **every** owner of an agent is inactive, `ownerless_action` decides:

| Value | What happens |
|---|---|
| `report` (default) | `ownerless_detected` is audited and admins get one alert (repeated only if the owners change) |
| `reassign_to_manager` | The agent is reassigned (`POST …/packages/{id}/reassign`) to the manager of a disabled owner, if that manager is active. The new owner gets an email. Falls back to `report` when no manager can take over. An approved agent's registry entry doesn't name the new owner, so it's blocked by `OWNER-UNREGISTERED` until re-approved. |
| `block` | The agent is blocked (`blockType: ownerless`) and admins are alerted. It's unblocked automatically once an active owner is found, for example after an admin reassigns it. |

### Inactivity: notice, retirement, archive, deletion

Set `inactivity_days` (for example `90`) to retire agents nobody uses. Last activity is the latest of `lastUsedDateTime`, `lastModifiedDateTime`, `createdDateTime` (all from the package detail) and the last reactivation.

1. **Notice.** `inactivity_notice_days` (default 30) before the agent becomes inactive, every owner is told it's bound for retirement, and on which date (`inactivity_warning`). Retirement is never sooner than the full notice period, even for agents that were already past the limit when the policy was switched on.
2. **Reminder.** `inactivity_reminder_days` (default 7) before the date (`inactivity_reminder`). Using the agent at any point cancels the countdown (`inactivity_cleared`).
3. **Retirement.** On the date, the agent is blocked (`blockType: retired`). Owners get a notice with a "Reactivate my agent" link and the archive date. Retirement counts towards the circuit breaker.
4. **Archive.** After `archive_after_days` (default 30), the agent's full definition and a manifest are saved to the archive library, on a restricted site (`agent_archived`), and owners are told. Embedded files aren't copied; see the [customisation guide](customisation.md#lifecycle).
5. **Deletion.** With `deletion_mode: manual` (default), admins are asked to delete the agent in the Microsoft 365 admin centre (`deletion_requested`), and reminded every `deletion_reminder_days`. When the agent disappears from the catalog, ShareGuard records `agent_deleted` and marks the archive. `api` mode tries an undocumented delete call first; `none` keeps the agent blocked.

An owner who confirms the reactivation link gets the agent back at any stage before deletion (`reactivation_requested`, then `unblock`). If deletion was already requested, admins get a "Don't delete" alert (`deletion_cancelled`). `inactivity_applies_to_approved` (default on) applies all of this to registry-approved agents too.

## Owner emails

| Email | When | To |
|---|---|---|
| **Welcome** | The first time an owner is seen with an Agent Builder agent | Owner |
| **Share notice** | The agent is blocked for sharing. Lists who it was shared with and includes the acknowledgement link. | Owner |
| **Drift notice** | An approved agent is blocked for drift. Lists each violation and the approval reference, with options to fix it or remove sharing. | Owner, plus a governance alert |
| **Restored** | The agent is unblocked: sharing removed, drift rectified, newly approved, or reactivated | Owner |
| **Retirement notice** | The agent is bound for retirement on a given date unless it's used | Every owner |
| **Retirement reminder** | `inactivity_reminder_days` before that date | Every owner |
| **Retired** | The agent was retired for inactivity, with a "Reactivate my agent" link and the archive date | Every owner |
| **Archived** | The retired agent was archived and is being deleted | Every owner |
| **Ownership transferred** | A former owner's manager now owns the agent (`reassign_to_manager`) | New owner |
| **Admin alert** | Owner unknown, notice couldn't be sent, manual removal needed, removal failed or couldn't be verified after `ack_max_attempts`, ownerless agent, archive failed, agent ready for deletion (and reminders), deletion cancelled | `admin_emails` |

The wording of every email can be changed with template files: see [Emails](customisation.md#emails) in the customisation guide.

**First-run baseline.** On the first cycle, owners who already have agents are recorded as "known" without being emailed, so turning the feature on doesn't send a burst of welcome emails. Set `welcome_backfill: true` if you want to welcome existing owners too.

**Owner identification.** The Package Management API doesn't document an owner property, so `absg.mail.OwnerResolver` tries these sources in order:
1. `owner_map_file` (or `sharepoint_owner_map_path`): an explicit `{packageId: userObjectId or [userObjectIds]}` file.
2. `owner_fields`: dotted paths in the package detail, in case Microsoft exposes one (for example `"ownerId"` or `"owners"`).
3. An owner learned earlier for this package.
4. Inference. While an agent is **not shared**, the single user in `allowedUsersAndGroups` is taken as the owner. Because the daemon normally sees an agent before it's shared, it learns the owner then and remembers it.

An agent that's already shared the first time the daemon sees it has no inferable owner. Its notice goes to `admin_emails` instead, and an `owner_unknown` record is written.

## Acknowledgement flow

```
block ──► notice email (signed link, caseId) ──► owner opens link (GET: confirmation page only)
      ──► owner signs in and ticks "I agree" (POST) ──► ack queued, daemon woken
      ──► daemon PATCHes sharing back to owner-only (delegated identity, on the owner's behalf)
      ──► daemon re-reads the agent: sharing gone? ──► unblock ──► "restored" email
                                     still shared? ──► stay blocked, retry, escalate to admins
```

Security properties:
- **Signed, expiring, single-use links.** Each token is HMAC-SHA256 signed (key `ABSG_ACK_SECRET`, at least 32 characters), bound to package, owner and case, and valid for `ack_token_ttl_hours`. A used case can't be acknowledged again.
- **Link scanners can't trigger it.** Opening the link (GET) only shows a confirmation page. Mail security scanners such as Safe Links pre-fetch links, so nothing happens until the owner clicks **Confirm** (POST).
- **Owner-only.** With `ack_require_identity`, the signed-in identity from the authenticating proxy must match the agent's owner. Otherwise the request is rejected and recorded as `ack_rejected`.
- **Stale links are ignored.** If the agent was re-blocked since the email was sent, the old link's case no longer matches and is recorded as `ack_stale`.
- **Never unblocks on trust alone.** The guard re-reads the agent after removing sharing, and only unblocks if no sharing remains.

## Webhook notifications

Set `notify_webhook_url` to a Teams Workflows or Logic App HTTP trigger to receive `blocked`, `unblocked`, `circuit_breaker` and `audit_integrity_failure` events, for example for a SOC channel.

## Safety features

- **Dry run** (`--dry-run` / `ABSG_DRY_RUN=1`): logs and audits what would happen (outcome `simulated`), but blocks, unblocks, edits and emails nothing.
- **Circuit breaker** (`max_blocks_per_cycle`): stops issuing new blocks after N in one pass and raises a `circuit_breaker` event, in case an API change makes every agent look shared.
- **Repeat-violation lock** (`repeat_violation_limit`): an agent blocked again and again in a short time stays blocked until governance releases it, and an owner's agents beyond the daily sharing limit (`daily_share_limit_per_owner`, default 5) stay blocked until the next day. See [Repeat violations](#repeat-violations).
- Errors on one agent are logged, and the rest of the scan carries on. Throttling (429) and 5xx responses are retried, honouring `Retry-After`.

## Audit trail

Every decision and action the guard takes is written to `audit_file` (default `absg_audit.jsonl`). The file is append-only and uses JSON Lines, one record per line.

**Each record captures:**

| Field | Meaning |
|---|---|
| `seq`, `timestamp` | Order and UTC time |
| `event` | **Enforcement:** `block`, `reblock`, `unblock`, `block_deferred`, `exempt_skip`, `state_forget`, `circuit_breaker`, `error`, `no_action` (optional)<br>**Owners and email:** `owner_resolved`, `owner_unknown`, `welcome_baseline`, `welcome_email_sent`, `notice_email_sent`, `restored_email_sent`, `admin_alert_sent`, `email_failed`<br>**Between checks:** `usage_checked`, `usage_violation`, `edit_between_checks`<br>**Repeat violations and daily limit:** `repeat_violation_locked`, `daily_share_limit_locked`, `unblock_withheld`, `lock_released`, `lock_release_rejected`, `lock_expired`<br>**Registry and drift:** `registry_entry_added`, `registry_entry_updated`, `registry_entry_removed`, `registry_entry_invalid`, `registry_validation`, `violation_updated`<br>**Acknowledgement:** `ack_received`, `ack_rejected`, `ack_stale`, `ack_closed`, `ack_escalated`, `sharing_removal`, `sharing_removal_unverified`<br>**Ownership and lifecycle:** `ownerless_detected`, `ownership_reassigned`, `ownership_email_sent`, `inactivity_warning`, `inactivity_reminder`, `inactivity_cleared`, `reactivation_requested` (retirements are `block` records with `blockType: retired`), `agent_archived`, `archive_failed`, `archived_email_sent`, `deletion_requested`, `deletion_reminder`, `deletion_submitted`, `deletion_failed`, `deletion_unverified`, `deletion_cancelled`, `agent_deleted`<br>**Daemon:** `daemon_start`, `daemon_stop`, `invocation_start`, `cycle_start`, `cycle_end`, `audit_integrity_failure` |
| `caseId` | Links every record about one block: block, notice, link token, acknowledgement, removal, unblock, restored email |
| `onBehalfOf` | On `sharing_removal` and `unblock`: the owner the guard acted for |
| `actingIdentity` | On `block`, `unblock`, `ownership_reassigned` and `sharing_removal`: who made the call (the delegated service account, or `application`) |
| `ackTokenId`, `ackReceivedAt`, `signedInUser`, `identityVerified`, `remoteAddr`, `userAgent` | Evidence of who acknowledged, when and from where |
| `removedRecipients` | Exactly which sharing the guard removed |
| `email` | Template, recipients, subject and send time for each email |
| `source` | `ack_endpoint` for records written by the web endpoint |
| `blockType` | `sharing` or `drift` |
| `violations`, `warnings` | Each one's rule ID, severity, message, and approved-versus-live detail |
| `approvalRef`, `approvalStatus` | Registry request ID, risk rating and approver, or why the approval wasn't valid |
| `configHash`, `baselineHash`, `registryFileHash` | Prove exactly which configuration and which whitelist version a decision was based on |
| `actor` | App (client) ID, tenant, host, process ID and instance ID |
| `cycleId` | Links every record from one polling pass |
| `package` | Agent `id`, `displayName`, `manifestId` |
| `before` / `after` | `isBlocked`, `shared` and recipient count around the action |
| `recipients` | Who the agent was shared with: the evidence for the block |
| `reason` | Which policy rule fired |
| `outcome` | `success`, `failed` (with `error`), `simulated` (dry run) or `deferred` |
| `originallyBlockedAt` | On unblock: how long the agent was blocked |
| `config`, `configHash` | On `daemon_start`: the policy settings in force, without secrets |

**Tamper evidence.** Each record contains a `prevHash` and a SHA-256 `hash` of its own content, so the records form a hash chain. Editing, deleting or reordering any record breaks the chain. The daemon checks the chain at startup and **refuses to run (exit code 2)** if the chain is broken, sending an `audit_integrity_failure` notification.

**Commands** (these don't need Graph credentials):

```bash
# Verify integrity (exit 1 if broken)
absg --verify-audit /data/absg_audit.jsonl

# Full history of one agent
absg --audit-history /data/absg_audit.jsonl --package P_19ae...

# Everything about one block, from detection to restoration
absg --audit-history /data/absg_audit.jsonl --case 3f2a...

# All blocks since 1 November
absg --audit-history /data/absg_audit.jsonl --event block --since 2026-11-01
```

Set `audit_no_action: true` to also record each agent that was checked and left unchanged. This lets you prove an agent was evaluated at a given time, but it makes the log much larger.

**Retention and independence.** The hash chain shows tampering, but someone with write access could still delete the whole file. For evidence that holds up independently:
- Ship the file to Microsoft Sentinel or Log Analytics (for example, with the Azure Monitor Agent custom text log collector) or to your SIEM.
- And/or copy it on a schedule to **immutable** Azure Blob storage (a WORM/time-based retention policy).
- Run `--verify-audit` on a schedule against the shipped copy, and alert on failure.
- Cross-check against Microsoft's own record. The guard's block and unblock calls should also appear in the Purview unified audit log under the app's identity.

## Validate in a pilot before enforcing

These behaviours aren't fully documented. Check each one in a test tenant or with pilot users:

1. **Owner visibility in `sharedWithUsersAndGroups`.** Confirm that an unshared agent returns an empty list, and that the owner isn't included. If a fixed principal always shows up, add it to `ignore_principal_ids`.
2. **Does the `PATCH` remove Agent Builder sharing?** The update call is documented for `allowedUsersAndGroups` and `availableTo`. It doesn't mention `sharedWithUsersAndGroups`. Confirm in the pilot that setting `allowedUsersAndGroups` to the owner alone (with `availableTo: "allowedForSome"`) clears the sharing the owner sees in Agent Builder. The guard verifies by re-reading before it unblocks. If removal doesn't take, it escalates instead of unblocking, so a wrong assumption fails safe. Adjust `removal_available_to_value` if your tenant uses a different value.
3. **Can a blocked owner edit the agent?** Drift remediation ("undo the change") assumes the owner can still edit a blocked agent in Agent Builder. If they can't, the remaining paths are removing sharing through the link, or governance re-approving the new configuration (re-baselining) after review.
4. **How Agent Builder represents uploaded files.** Check the `definition` of an agent with uploaded files, and set `embedded_capability_names` to match. The `sensitivity_label` check is a backstop.
5. **Owner inference.** Confirm that an unshared agent's `allowedUsersAndGroups` contains just the owner. If Microsoft exposes an owner field, add it to `owner_fields`.
6. **Propagation delay.** Measure how long a share takes to show up in the API, and how long a block takes to reach users. Set `poll_interval_seconds` with that in mind.
7. **`availableTo` values** for unshared Agent Builder agents (`some` / `none`). Confirm that `all` only appears for org-wide shares.
8. **Owners and usage fields.** Check whether the package detail exposes owners (set `owner_fields`) and whether `lastUsedDateTime` is populated for Agent Builder agents before turning on `inactivity_days`. Check too whether a deleted (soft-deleted) agent disappears from the package list, which is how ShareGuard confirms a deletion.
9. **Reassignment.** If you use `reassign_to_manager`, try `POST …/reassign` on a test agent with the delegated account first: like block and unblock, it runs as that account.
10. **Usage records and edit times.** Before turning on `usage_monitoring`, look at a few `CopilotInteraction` records for a test Agent Builder agent (Purview audit search): check that `auditData` names the agent under `AgentId` (or set `usage_agent_id_keys`) and that its package id or manifest id appears there. Before using `between_check_edits: violation`, check that sharing an agent, and adding or removing a file, updates its `lastModifiedDateTime`.
11. **API versions and app-only writes.** Reads (list, get) use v1.0; block, unblock, update and reassign use `/beta`, the only version Microsoft documents them in. Microsoft's pages for these write methods list delegated permissions only, so expect 401 or 403 from the guard's app-only block and unblock calls. Check this first. If they're refused, enforcement can't work app-only until Microsoft adds application support. If your tenant only exposes the reads under `/beta` too, set `graph_base` to the beta URL. Beta isn't supported for production.

## Known limitations and caveats

ShareGuard is a **detective** control built on preview APIs: it finds sharing and drift after the fact and reverses them, it doesn't prevent them. Read these before relying on it, and pair it with data-layer controls (sensitivity labels, Restricted Content Discovery, DLP) that limit what a briefly exposed agent can reach.

### Exposure ShareGuard can't prevent

| Caveat | Why | What reduces it |
|---|---|---|
| **Every share is usable for a while before it's blocked** | ShareGuard checks on a schedule; Microsoft offers no event when sharing changes. Each share stays usable for up to one polling interval plus Microsoft's propagation delay (measure it in the pilot). | A short `poll_interval_seconds` (guard schedule). The [repeat-violation lock](#repeat-violations) and the [daily limit](#daily-sharing-limit-per-owner) stop the window being reused, but the first exposures still happen. |
| **Approved audiences can grow through group membership** | An approval names the groups an agent may be shared with, and ShareGuard checks the groups it's shared with, not who's in them. Whoever manages an approved group can add anyone to it, and the agent's audience grows with no change ShareGuard can see. ShareGuard doesn't control group membership. | Approve only groups that governance or IT owns, with membership changes reviewed (Entra access reviews, dynamic groups); keep audiences small; record each group's owners in the approval. |
| **Changes between two checks can't be prevented** | An owner can add embedded files or a knowledge source, or share the agent, use it and undo it within one polling interval. | Detected afterwards, not prevented: [usage from the audit log](#usage-from-the-audit-log) shows who used an agent they weren't meant to, and [edits undone between checks](#edits-undone-between-checks) shows that something changed. Both arrive late, the second doesn't say what changed, and both rely on Microsoft's records being complete. A short polling interval and data-layer controls still matter. |
| **The circuit breaker can hide shares** | When `max_blocks_per_cycle` (25) blocks have been issued in one cycle, the rest are deferred (`block_deferred`) to the next cycle, so a burst of shares can delay the block of one that matters. | The `circuit_breaker` alert; investigate every one. Lowering the limit would defer more agents, not fewer. |

### Limits of the repeat-violation and daily controls

| Caveat | Detail |
|---|---|
| **Counting depends on knowing the owner** | The daily limit counts per owner. If an agent's owner can't be resolved (no owner field, not learned while unshared, no owner map), it isn't counted. The repeat-violation count is per agent and doesn't need an owner. |
| **Copies under the daily limit** | Copying an agent starts its repeat-violation count again. The daily limit (default 5 per owner per day) caps how far this goes, but a maker can still share up to the limit each day. |
| **"A day" is the UTC day** | Daily holds end at 00:00 UTC, whatever the tenant's time zone. |
| **An admin unblock releases a lock** | Unblocking a locked agent in the Microsoft 365 admin centre counts as a release (audited as `lock_released`). Its violation count is kept, so its next violation locks it again at once. Restrict who can unblock agents. |
| **Owners can't release their own agents, but other governance members can** | A release is refused only when it comes from one of the agent's owners. Who may write *Agent Lock Releases* (or run `--release-lock` locally) is decided by the list's permissions and file access. |

### Microsoft platform dependencies

| Caveat | Detail |
|---|---|
| **The write APIs are preview, under `/beta`** | Block, unblock, update and reassign exist only under `/beta` and can change or break without notice. Reads (list, get) use v1.0. See [How it works](#how-it-works). |
| **Enforcement runs as a delegated service account** | Microsoft documents the write methods with delegated permissions only, so blocking, unblocking, reassigning and removing sharing run as `svc-absg@`. That account holds an admin role, and if its sign-in expires or its role is removed, nothing is blocked or released until it's fixed (`enforcement_identity_failed`, alerted every cycle). Protect it with Conditional Access and sign-in monitoring. |
| **Undocumented behaviour** | Several things ShareGuard relies on aren't documented: whether `PATCH` clears Agent Builder sharing, how uploaded files appear in the definition, whether `sharedWithUsersAndGroups` excludes the owner, whether `lastUsedDateTime` is populated, and how a deleted agent disappears from the list. Work through the [pilot checklist](#validate-in-a-pilot-before-enforcing). |
| **Licensing** | The API needs Microsoft Agent 365 licensing, and Microsoft's statements on which licences are required have changed during the preview. |
| **Inactivity without usage data** | If `lastUsedDateTime` isn't populated, inactivity is measured from the last edit, so an agent used every day but never edited can be retired. Check before turning on `inactivity_days`. |

### Configuration and trust assumptions

| Caveat | Detail |
|---|---|
| **Exemptions match by manifest ID too** | An `exempt_ids` entry matches a package id or a manifest id. If copies of an agent keep the original's manifest id, the exemption covers them. Prefer package ids, and check in the pilot. |
| **Ignored principals are never sharing** | Anyone in `ignore_principal_ids` can be shared with freely. Keep it to fixed service accounts. |
| **The guard's state is trusted** | Rollback protection for the registry, the repeat-violation counts, the daily counts and the record of which blocks are the guard's own all live in the guard's state. Anyone who can write the state (the Operations site's *ABSG State* library, or `state_file`) can undo them. Registry editors must not have write access there. |
| **The audit chain shows tampering only to people who can't write it** | The hash chain detects edited or missing records, but an identity with write access to the audit library (including the guard's own) could rewrite the whole chain. Rely on the retention (record) label on closed days, the copy in Application Insights, and an exported copy in immutable storage. |
| **No registry at all on a first start** | If the registry can't be read and no earlier copy was ever saved, decisions on shared agents are deferred (`decision_deferred`) rather than blocking every approved agent. Someone able to break that read before the first successful load delays enforcement. |
| **Signer review checks have limits** | Only KS-02 (no embedded files) is checked against the live agent automatically; other criteria rely on reviewers reading `ReviewConfigSummary`. The edit-history check needs `signer_trusted_editors`, and is off without it. |
| **Local mode can't verify who confirms** | The built-in confirmation page on `localhost`, with `ack_require_identity: false`, accepts a forwarded link from anyone. Use it on a single test PC only, or put an authenticating proxy in front of it. |

## Tests

See [CONTRIBUTING.md](../CONTRIBUTING.md).
