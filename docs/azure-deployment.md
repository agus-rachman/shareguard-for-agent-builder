# Azure deployment guide

How to deploy ShareGuard for Agent Builder to Azure Functions, with SharePoint Online for state, audit, registry and acknowledgements, Exchange Online for email and Key Vault for secrets and the registry signing key. The design and its reasoning are in [deployment-architecture.md](deployment-architecture.md); this guide is the step-by-step. To build a test environment first, with test scenarios and expected results (or to test locally on Windows without Azure), follow the [test environment setup](test-environment-setup.md).

> **Status: pilot-ready, not production-proven.** The Python code is covered by the test suite. The Bicep template and PowerShell scripts haven't yet been run against a real tenant: expect to fix small issues on the first deployment, and please report them.

## What gets deployed

| Component | Name (env `prod`) | Purpose |
| --- | --- | --- |
| Guard Function app | `func-absg-guard-prod` | Every 5 minutes: scan, block, unblock, drift and lifecycle checks, emails, acknowledgements. Nightly audit chain check. |
| Signer Function app | `func-absg-signer-prod` | Every 15 minutes: signs approved sharing requests into the registry. Can't block or send mail. |
| Managed identities | `id-absg-guard-prod`, `id-absg-signer-prod` | One per app, no secrets |
| Key Vault (Premium) | `kv-absg-prod-<suffix>` | Registry signing key (EC P-256, HSM), acknowledgement key, delegated token cache |
| Network | VNet, NAT gateway, private endpoints | Static outbound IP for Conditional Access; Key Vault and storage private only |
| Storage | `stabsgprod<suffix>` | Functions runtime only (no ShareGuard data), shared keys off |
| Monitoring | Log Analytics, Application Insights, alerts | Missed cycles, errors, circuit breaker, audit integrity, registry tampering |

In SharePoint, two sites, plus an optional restricted archive site:

| Site | Contents | Access |
| --- | --- | --- |
| **Operations** (for example `/sites/absg-operations`) | *ABSG State*, *ABSG Audit* libraries; *Agent Acknowledgements* list | ShareGuard administrators; guard (write); flow account (the list only) |
| **Registry** (for example `/sites/absg-registry`) | *Approved Agents*, *Agent Sharing Requests* lists; *ABSG Signer Audit* library | Governance reviewers; requesters (own requests); signer (write); guard (read) |
| **Archive** (optional, for example `/sites/absg-archive`) | *Retired Agents* library: archived definitions of retired agents | A few named records or governance staff; guard (write). Without it, the library goes on the Operations site. |

All of these names, and those of the Azure resources, can be changed in the parameters file: see the [customisation guide](customisation.md). Decide them before the first deployment.

## Before you start

- An Azure subscription in the Microsoft 365 tenant, and a resource group (`rg-absg-prod`).
- Azure CLI with Bicep; PowerShell 7 with `Microsoft.Graph`, `ExchangeOnlineManagement` and `PnP.PowerShell` (and a PnP app registration for `-PnPClientId`).
- Roles: Owner on the resource group; Privileged Role Administrator (Graph app roles); SharePoint Administrator; Exchange Administrator.
- A Microsoft Agent 365 licence in the tenant (the Package Management API needs it).
- Two empty SharePoint sites (three with a separate archive site), a shared mailbox address and a cloud-only service account (`svc-absg@`) that blocks, unblocks and removes sharing.

Start by copying `azure/infra/main.parameters.example.json` to a file **outside** the repository, for example `~/absg/main.parameters.prod.json`, and filling in what you know so far: names (`naming`, `sharePointNames`), lifecycle, email and criteria. Every step below reads it.

## Step 1: SharePoint

```powershell
$p = '~/absg/main.parameters.prod.json'
./azure/scripts/Provision-AbsgSharePoint.ps1 -ParametersFile $p -PnPClientId <pnp-app-id> `
  -OperationsSiteUrl https://contoso.sharepoint.com/sites/absg-operations `
  -RegistrySiteUrl   https://contoso.sharepoint.com/sites/absg-registry `
  -ArchiveSiteUrl    https://contoso.sharepoint.com/sites/absg-archive `
  -FlowAccount svc-absg-flow@contoso.com -GovernanceGroup ai-governance@contoso.com
```

`-GovernanceGroup` (an Entra group or user) may write *Agent Lock Releases* on the Operations site: it releases agents locked after repeated violations. It prints `operationsSiteId`, `registrySiteId` and `archiveSiteId`: put them in the parameters file. Then, in Purview, create **retention labels** for the audit (for example "ShareGuard audit record") and for the archive (for example "ShareGuard retired agent"), each a record label with your retention period. Publish them to the Operations and archive sites, and put their names in `auditRetentionLabel` and `lifecycle.archive_retention_label`. ShareGuard applies the audit label to each day's file once the day is closed, and the archive label to every archived file.

## Step 2: Infrastructure and code

Finish the parameters file and keep `dryRun: true` for now. Set `deploymentIpRanges` to the IP you deploy from (the apps deny all other inbound traffic).

```bash
./azure/deploy.sh rg-absg-prod ~/absg/main.parameters.prod.json
```

This builds `build/functionapp.zip` (the Functions entry point plus the `absg` package), deploys the Bicep template, and deploys the code to both apps. `build/outputs.json` holds the identity ids, Key Vault name and NAT IP. Later code-only releases: `./azure/deploy.sh rg-absg-prod <params> --code-only`.

`initialiseSecrets: true` creates the acknowledgement key and an empty token cache on the first deployment. **Set it to `false` for every later deployment**, or the acknowledgement key is replaced and outstanding links stop working.

## Step 3: Permissions

```powershell
$o = Get-Content build/outputs.json | ConvertFrom-Json
./azure/scripts/Grant-AbsgGraphPermissions.ps1 -ParametersFile $p      # finds the identities by name
./azure/scripts/Grant-AbsgSiteAccess.ps1 -ParametersFile $p            # site ids from the file
./azure/scripts/Grant-AbsgMailbox.ps1 -ParametersFile $p `
  -GuardClientId $o.guardClientId.value -GuardPrincipalId $o.guardPrincipalId.value
```

| Identity | Microsoft Graph | SharePoint (Sites.Selected) | Other |
| --- | --- | --- | --- |
| Guard | `CopilotPackages.ReadWrite.All`, `User.Read.All`, `GroupMember.Read.All`, `Sites.Selected`; with `-UsageMonitoring`, also `AuditLogsQuery.Read.All` (for `usage_monitoring`) | Operations: write · Registry: read · Archive: write | `Application Mail.Send` on the shared mailbox only; Key Vault: two secrets, public key |
| Signer | `CopilotPackages.Read.All`, `User.Read.All`, `Sites.Selected` | Registry: write | Key Vault: sign with the registry key |

Restart both apps afterwards so they pick up tokens with the new roles.

## Step 4: Delegated account (blocking and sharing removal)

Microsoft documents blocking, unblocking and removing sharing (`PATCH` on a package) with delegated permissions only, so ShareGuard runs them as `svc-absg@` (`block_identity: "delegated"`, the default). Until this account is signed in, the guard can detect shared agents but can't block them.

```powershell
./azure/scripts/Register-AbsgDelegatedClient.ps1 -ParametersFile $p   # account from delegatedUsername
```

Put the printed client id in `delegatedClientId` and redeploy. Then sign the account in once, from a trusted machine, and move the token cache into Key Vault:

```bash
absg --config local.json --login-delegated      # device code; sign in as svc-absg@
az keyvault secret set --vault-name <kv> --name delegated-token-cache --file absg_delegated_cache.json
shred -u absg_delegated_cache.json
```

`local.json` needs only these keys. `client_id` and `use_managed_identity` are there to pass the settings check; the sign-in doesn't use them:

```json
{"tenant_id": "<tenant-id>", "client_id": "unused", "use_managed_identity": true,
 "delegated_client_id": "<delegated-client-id>", "delegated_username": "svc-absg@contoso.com",
 "delegated_token_cache": "absg_delegated_cache.json"}
``` Key Vault is private, so run `az keyvault secret set` from inside the VNet, or add your IP to the vault firewall temporarily. Then:

- give `svc-absg@` the least-privileged admin role that can block, unblock and update agents in your pilot (try a block by hand with it first);
- add a Conditional Access policy allowing it to sign in **only** from the NAT IP (`natPublicIp`), and alert on any other sign-in.

When the refresh token expires (sign-in frequency, password reset, revocation), sharing removal fails, admins are told, and the agent stays blocked. Repeat the sign-in to restore it.

## Step 5: Acknowledgement form and flow

1. **Microsoft Form** (owned by the ShareGuard admins group): "Only people in my organization can respond", **record name** on. Questions:
   1. *Confirmation token* (text; pre-filled; tell users not to change it);
   2. *I confirm ShareGuard may remove sharing from my agent and unblock it for my personal use* (choice: Yes).
2. Get a pre-filled link: **⋯ → Get pre-filled URL**, type `TOKEN` in question 1, copy the link, and replace `TOKEN` with `{token}`. Put it in `ackFormUrl` and redeploy. Notices now link to the form with each owner's token filled in.
3. **Power Automate cloud flow**, standard connectors only, using the `svc-absg-flow@` connection:
   - Trigger: *Microsoft Forms → When a new response is submitted*.
   - *Microsoft Forms → Get response details*.
   - *SharePoint → Create item* in **Agent Acknowledgements** on the Operations site: `Title` = response id, `Token` = question 1, `ResponderUpn` = *Responders' Email*, `Status` = `New`.

The flow is deliberately dumb: it can't approve anything. Each guard cycle checks every new item: the token's signature and expiry, single use, that the case is still current, and that `ResponderUpn` is one of the agent's owners. Then it removes sharing (or reactivates a retired agent), verifies, unblocks and marks the item `Accepted`, or marks it `Rejected` with a reason. A forwarded link doesn't work for anyone else.

## Step 6: Intake and review

Owners request sharing by creating an item in **Agent Sharing Requests** (a SharePoint list form, or a Microsoft Form feeding it through another flow, which should put the responder's UPN in `RequestedBy`): `PackageId`, `Owners` (UPNs or object ids, separated by `;`), `AudienceGroupIds`, `Justification`, `ExpiresAt`. Item-level permissions mean they see only their own requests.

Requesters can **add** requests but can't **edit** them, not even their own. The signer trusts `Status`, `ApprovedBy`, the criteria, `PolicyJson` and `PackageId` as they stand, so a requester who could edit their item could approve it themselves. `Provision-AbsgSharePoint.ps1` gives the site's members (and `-RequestersGroup`, if given) an *ABSG Submit* permission level (Read plus Add Items) on the list, in place of Edit. Afterwards, check the list's permissions: only reviewers, the flow account and site owners may hold Edit, Contribute or Full Control.

As a second check, set `signerTrustedEditors` in the parameters file to the approval flow account and the reviewers. The signer then reads each request's version history, and refuses (`Needs criteria`) a request that anyone else changed after submitting it. In the pilot, confirm that the signer's own status updates show up in the version history under its managed identity's client ID; if they don't, add the identity that does appear.

Review it with a **Power Automate approval** flow (standard connectors):

1. *When an item is created* → set `Status` = `In review` → *Start and wait for an approval* to the reviewers group. Include `ReviewConfigSummary` in the approval details: the signer fills it in (with `ReviewConfigHash`) on its next run while the request is in review, and it's the configuration reviewers are approving. Have the flow wait until `ReviewConfigCapturedAt` is set before it starts the approval.
2. Reviewers score `KS01`–`AC01` (`Pass`, `Fail`, `N/A`), add `Evidence`, `RiskRating`, `Conditions` and optional `PolicyJson`.
3. Approved → set `Status` = `Approved` and `ApprovedBy` = the approver's UPN. Rejected → `Rejected` with `ReviewerComments`.

The signer then takes over. It reads the live agent, refuses (`Needs criteria`, with the reason in `SignerComments`) if any criterion is missing or failed, the approver is the requester or an owner, an owner's account is inactive, the expiry is past or beyond `max_approval_days`, the audience is empty, someone other than a trusted editor changed the request, or the request was already registered (renewing or changing an approval needs a new request). It also refuses if the agent's configuration no longer matches the one recorded during the review (`ReviewConfigHash`), if no configuration was recorded, if the definition can't be read, or if KS-02 is marked Pass while the agent has embedded files. When the configuration changed or was missing, the signer records the current one in `ReviewConfigSummary` so reviewers can assess it and approve again. The baseline in the signed entry is therefore always the configuration the reviewers saw. Otherwise it captures the configuration baseline, signs the entry with the HSM key, checks the signature, writes it to **Approved Agents** and sets the request to `Registered` with `RegisteredEntryHash`. To withdraw an approval, set the request to `Revoke requested`; the signer re-signs the entry as `revoked` and marks the request `Revoked`.

Nobody edits *Approved Agents* by hand. An edited entry fails signature verification, `registry_entry_invalid` is audited and an alert fires, and the agent is treated as unapproved. Restoring an earlier version from the list's version history (for example, putting back an approval that was revoked) is caught too. The guard keeps the newest `signedAt` it has seen for each agent in its state on the Operations site, and rejects older entries (`registry_rollback_rejected`). Registry site owners must therefore not have write access to the Operations site.

## Step 7: Pilot, then enforce

Run with `dryRun: true` for at least two weeks. Everything is audited as `simulated` and no email is sent. Check, in this order:

1. **App-only reads, delegated writes.** The guard lists and reads agents with its managed identity, and blocks, unblocks and removes sharing as `svc-absg@`. Look for 401 or 403 errors in the guard's first cycles: on a read, the managed identity lacks a role or the API refuses app-only reads; on a block or unblock, `svc-absg@`'s sign-in or admin role is the problem (an `enforcement_identity_failed` record and an admin alert say so).
2. **Agent 365 licence for the identities.** Microsoft documents the API as requiring an Agent 365 licence. We expect it's a tenant-level requirement, but if calls fail with a licensing error, assign a licence to the identities' service principals (or the service account) and retry.
3. The [pilot checklist](operations-guide.md#validate-in-a-pilot-before-enforcing) in the operations guide: owner fields, sharing fields, `PATCH` behaviour, `lastUsedDateTime`, propagation delay.
4. `absg --verify-audit-store` (or the nightly `verify_audit_chain` function) reports an intact chain.

Before enforcing, read the [known limitations and caveats](operations-guide.md#known-limitations-and-caveats) with your governance and security teams.

Then set `dryRun: false` for one pilot group (use `exempt_ids` for agents outside the pilot), and finally for everyone. Turn on lifecycle features one at a time: `owner_status_checks` first, then `ownerless_action`, then `inactivity_days`. Before archive and deletion begin, check the first archived agent in the archive library, and do one deletion by hand in the admin centre to confirm ShareGuard records it (`agent_deleted`).

## Configuration

The Bicep template builds the guard's configuration (`ABSG_CONFIG_JSON`) from the parameters file: the `lifecycle`, `email` and `guardSettings` objects are merged in, in that order. The [customisation guide](customisation.md) lists every setting and where it lives. [`examples/config.azure.example.json`](../examples/config.azure.example.json) shows the configuration the template generates.

To customise email wording, put template files in the `templates` folder of the state library (`sharePointNames.templatesFolder`): see [Emails](customisation.md#emails).

## Operations

| Task | How |
| --- | --- |
| See what happened to an agent | Download the day's files from *ABSG Audit*, then `absg --audit-history <file> --package <packageId>`, or query `AppTraces` in Log Analytics |
| Verify the audit trail | Runs nightly; on demand: `absg --verify-audit-store` with the guard's settings |
| Pause enforcement | Set `ABSG_DRY_RUN=1` on the guard app |
| Rotate the acknowledgement key | Set a new version of the `ack-token-hmac-key` secret; outstanding links stop working, owners get new ones with the next notice |
| Rotate the registry key | Every entry must be re-signed with the new key version. The signer refuses to approve a registered request again, so submit a new request for each approved agent. The guard and signer use the new version as soon as it exists, and until an agent's new entry is signed its old one doesn't verify, so the agent is treated as unapproved. Rotate in a maintenance window with the guard in dry run (`ABSG_DRY_RUN=1`), and end dry run once every agent is registered again. |
| Release an agent locked after repeated violations | Add an item to *Agent Lock Releases* (Operations site): `Title` = the package id, `Reason`. Applied on the next cycle (`lock_released`). See [Repeat violations](operations-guide.md#repeat-violations). |
| Release a stuck agent | Fix the cause (remove sharing, revert drift, approve); the guard unblocks on its next cycle. Never unblock a guard block by hand: the guard re-blocks it. |
