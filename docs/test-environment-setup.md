# ShareGuard test environment setup

> **Status:** written for pilot testing and not yet run end to end against a real tenant. The Bicep template, PowerShell scripts and Power Automate flows are untested; report what you have to change.

## Overview

This guide sets up a complete ShareGuard for Agent Builder test environment: a dedicated Microsoft 365 test tenant, three SharePoint sites, an Exchange shared mailbox, two Azure Function apps (guard and signer), a Key Vault with an HSM signing key, and the Forms and Power Automate flows. It ends with a set of test scenarios and the results you should see for each.

Use a **separate test tenant**, never production. ShareGuard blocks agents tenant-wide, and some steps in this guide (short inactivity periods, deletion) are only safe with test data.

**No Azure subscription?** Follow Step 1 only, then [Alternative: run ShareGuard locally on Windows](#alternative-run-shareguard-locally-on-windows). It runs the guard on a Windows PC against the same Microsoft 365 tenant, with local files instead of SharePoint and Key Vault.

The work runs in this order:

1. Prepare the test tenant: users, groups, licences, mailbox and service accounts.
2. Create the SharePoint sites and provision their lists and libraries.
3. Deploy the Azure infrastructure and code with Bicep, in dry run.
4. Grant permissions to the managed identities.
5. Set up the sharing removal account (delegated sign-in).
6. Finish the configuration and check the first cycles.
7. Build the acknowledgement form and flow, and the request approval flow.
8. Run smoke checks in dry run.
9. Switch to enforcement and run the test scenarios.

Conventions: commands marked **bash** run on Linux or macOS (or WSL); commands marked **PowerShell** run in PowerShell 7. Replace every `<placeholder>` with your own value, and record each value in the worksheet in the next section. Names follow the defaults with environment `test`, for example `func-absg-guard-test`.

The repository's own guides go deeper: [the Azure deployment guide](azure-deployment.md), [the operations guide](operations-guide.md) and [the customisation guide](customisation.md).

## Prerequisites

You need a test tenant with Copilot and Agent 365 licensing, an Azure subscription linked to that tenant, four admin roles, and a workstation with five tools installed.

**Licences and subscriptions**

- A Microsoft 365 test tenant with **Microsoft 365 Copilot** for the test users who build agents, and **Microsoft Agent 365** licensing (the Package Management API needs it).
- An Azure subscription in the same Entra tenant, where you can create a resource group.

**Roles for the person doing the setup** (one account can hold them all in a test tenant)

| Role | Needed for |
| --- | --- |
| Owner on the resource group | Bicep deployment, role assignments |
| Privileged Role Administrator (or Global Administrator) | Graph app roles for the managed identities |
| SharePoint Administrator | Sites, lists, `Sites.Selected` grants |
| Exchange Administrator | Shared mailbox, RBAC for Applications |

**Workstation tools**

- Azure CLI with Bicep (`az bicep install`), signed in with `az login --tenant <tenant-id>`.
- PowerShell 7 with the modules `Microsoft.Graph`, `ExchangeOnlineManagement` and `PnP.PowerShell`.
- A PnP app registration for interactive PnP sign-in (its client id is `-PnPClientId`). Create one with `Register-PnPEntraIDAppForInteractiveLogin`.
- Python 3.10 or later, with the repository installed: `pip install -e .` (for `absg --login-delegated` and the audit commands).
- `zip` and `git`, and a clone of the repository at the commit you want to test.

**Values worksheet** — fill this in as you go; later steps refer to these names.

| Value | Example | Comes from |
| --- | --- | --- |
| Tenant id | `00000000-…` | Entra admin centre |
| Tenant domain | `contosotest.onmicrosoft.com` | Step 1 |
| Resource group | `rg-absg-test` | Step 3 |
| PnP client id | `00000000-…` | Prerequisites |
| Operations / Registry / Archive site URLs | `…/sites/absg-operations` | Step 2 |
| Operations / Registry / Archive site ids | `contosotest.sharepoint.com,…,…` | Step 2 output |
| Shared mailbox | `shareguard@…` | Step 1 |
| Sharing removal account | `svc-absg@…` | Step 1 |
| Flow account | `svc-absg-flow@…` | Step 1 |
| Reviewers group | `ABSG - Governance Reviewers` | Step 1 |
| Deployment IP | `203.0.113.10/32` | your public IP |
| Guard / signer client and principal ids | from `build/outputs.json` | Step 3 output |
| NAT public IP | from `build/outputs.json` | Step 3 output |
| Delegated client id | from the script output | Step 5 |
| Form pre-filled URL | `https://forms.office.com/…{token}` | Step 7 |

## Step 1: Prepare the Microsoft 365 test tenant

Create the test people, two groups, the shared mailbox and two service accounts first: every later step refers to them.

1. **Test users** (Microsoft 365 admin centre → Users → Active users). Give the first three a Copilot licence so they can build agents in Agent Builder.

   | User | Role in the tests |
   | --- | --- |
   | `olivia@<domain>` | Agent owner and requester |
   | `noah@<domain>` | Co-owner; second owner in the multi-owner tests |
   | `rita@<domain>` | Recipient an agent gets shared with |
   | `jane.risk@<domain>` | Governance reviewer and approver (must not own the test agents) |
   | `admin@<domain>` | Your setup account, holding the roles listed above |

2. **Groups** (Entra admin centre → Groups, security groups):
   - `g-absg-approved-audience`: add `rita`. The audience an approved agent may be shared with.
   - `g-absg-other`: any one member. Sharing with it is outside the approved audience.
   - Note both groups' **object ids**; requests use them in `AudienceGroupIds`.
3. **Shared mailbox** (Exchange admin centre → Recipients → Mailboxes → Add a shared mailbox): `shareguard@<domain>`. ShareGuard sends every email from it. Also pick an address for admin alerts, for example `admin@<domain>`.
4. **Delegated account**: a cloud-only user `svc-absg@<domain>`, with a long random password and MFA registered. Microsoft only allows blocking, unblocking and removing sharing with a delegated (user) token, so this account does all three. Give it the least-privileged admin role that can block and update agents in your tenant; confirm the role in the pilot by blocking a test agent with it by hand.
5. **Flow account**: a cloud-only user `svc-absg-flow@<domain>` with a licence that includes Power Automate and Microsoft Forms. The two flows run under its connections.
6. **Agent Builder sharing**: in the Microsoft 365 admin centre, check that users may share Agent Builder agents with specific people. ShareGuard needs real shares to detect.
7. **Two test agents**: sign in as Olivia and build two agents in Agent Builder, for example *HR helper* (grounded on one SharePoint site) and *Personal notes* (no knowledge). Don't share them yet.

## Step 2: Create the SharePoint sites and lists

Three communication sites hold everything ShareGuard stores; one script creates their lists and libraries and prints the site ids the deployment needs.

1. **Create three communication sites** (SharePoint admin centre → Sites → Active sites → Create):

   | Site | URL | Members |
   | --- | --- | --- |
   | Operations | `/sites/absg-operations` | Only you (ShareGuard administrators) |
   | Registry | `/sites/absg-registry` | Olivia and Noah as **members** (they submit requests) |
   | Archive | `/sites/absg-archive` | Only you |

2. **Reviewers group**: on the Registry site, Site settings → People and groups → New group, named `ABSG - Governance Reviewers`. Add Jane. The provisioning script grants this SharePoint group Full Control on the requests list.
3. **Parameters file**: copy the example out of the repository and set the environment name. Fill in what you know now; the rest comes later.

   ```bash
   mkdir -p ~/absg && cp azure/infra/main.parameters.example.json ~/absg/main.parameters.test.json
   ```

   Set `env` to `test`, `mailSender` to the shared mailbox, `adminEmails` and `alertEmail` to your alert address, `delegatedUsername` to `svc-absg@<domain>`, `naming.reviewersGroup` to `ABSG - Governance Reviewers`, `dryRun` to `true` and `initialiseSecrets` to `true`. Set `signerTrustedEditors` to `["svc-absg-flow@<domain>", "jane.risk@<domain>"]`.
4. **Provision the lists and libraries** (PowerShell, as the SharePoint admin):

   ```powershell
   $p = '~/absg/main.parameters.test.json'
   ./azure/scripts/Provision-AbsgSharePoint.ps1 -ParametersFile $p -PnPClientId <pnp-client-id> `
     -OperationsSiteUrl https://<tenant>.sharepoint.com/sites/absg-operations `
     -RegistrySiteUrl   https://<tenant>.sharepoint.com/sites/absg-registry `
     -ArchiveSiteUrl    https://<tenant>.sharepoint.com/sites/absg-archive `
     -FlowAccount svc-absg-flow@<domain> -GovernanceGroup jane.risk@<domain>
   ```

5. **Copy the printed site ids** into `operationsSiteId`, `registrySiteId` and `archiveSiteId` in the parameters file.
6. **Check the requests list permissions**: Registry site → *Agent Sharing Requests* → List settings → Permissions for this list. Members should hold only *ABSG Submit*; only the reviewers group, the flow account and site owners may hold Edit, Contribute or Full Control. Remove *Everyone except external users* if it appears with Edit.
7. **Retention labels (optional for testing)**: either create and publish two Purview record labels and put their names in `auditRetentionLabel` and `lifecycle.archive_retention_label`, or set both to empty strings. Don't apply record labels in a test you want to clean up: labelled files can't be deleted until the retention period ends.

## Step 3: Deploy the Azure infrastructure and code

One script builds the Function package, deploys the Bicep template and pushes the code to both apps, all in dry run.

1. **Finish the parameters file.** Leave `delegatedClientId` and `ackFormUrl` as they are for now (Steps 5 and 7 fill them). Set `deploymentIpRanges` to your public IP as a `/32`: the apps refuse inbound traffic from anywhere else. For a quick lifecycle test later, you can lower `lifecycle.inactivity_days`; it must stay greater than `inactivity_notice_days`.
2. **Create the resource group** (bash):

   ```bash
   az group create -n rg-absg-test -l <region>
   ```

3. **Deploy** (bash, from the repository root):

   ```bash
   ./azure/deploy.sh rg-absg-test ~/absg/main.parameters.test.json
   ```

   This creates the guard and signer Function apps, a managed identity for each, a Premium Key Vault with the HSM registry key, a VNet with a NAT gateway and private endpoints, storage for the Functions runtime, Log Analytics, Application Insights and the alert rules.
4. **Record the outputs** from `build/outputs.json` in the worksheet: `guardClientId`, `guardPrincipalId`, `signerClientId`, `signerPrincipalId`, `keyVaultName` and `natPublicIp`.
5. **Set `initialiseSecrets` to `false`** in the parameters file now. Every later deployment must keep it `false`, or the acknowledgement key is replaced and outstanding links stop working.

If the deployment fails, fix the parameter it names and run the same command again. The template and scripts haven't yet been run against a real tenant, so small issues are expected on the first run; note them for the maintainers.

## Step 4: Grant permissions to the managed identities

Three scripts give the guard and the signer exactly the Graph roles, SharePoint sites and mailbox they need, and nothing else.

Run them in PowerShell 7 as an account with Privileged Role Administrator, SharePoint Administrator and Exchange Administrator:

```powershell
$p = '~/absg/main.parameters.test.json'
$o = Get-Content build/outputs.json | ConvertFrom-Json
./azure/scripts/Grant-AbsgGraphPermissions.ps1 -ParametersFile $p
./azure/scripts/Grant-AbsgSiteAccess.ps1 -ParametersFile $p
./azure/scripts/Grant-AbsgMailbox.ps1 -ParametersFile $p `
  -GuardClientId $o.guardClientId.value -GuardPrincipalId $o.guardPrincipalId.value
```

What each identity ends up with:

| Identity | Microsoft Graph | SharePoint (`Sites.Selected`) | Other |
| --- | --- | --- | --- |
| Guard | `CopilotPackages.ReadWrite.All`, `User.Read.All`, `GroupMember.Read.All`, `Sites.Selected` | Operations: write; Registry: read; Archive: write | `Mail.Send` on the shared mailbox only; Key Vault secrets and the public key |
| Signer | `CopilotPackages.Read.All`, `User.Read.All`, `Sites.Selected` | Registry: write | Key Vault: sign with the registry key |

Then check and restart:

1. In the Entra admin centre → Enterprise applications → filter *Managed identities*, open `id-absg-guard-test` and `id-absg-signer-test` → Permissions, and check the roles above are granted.
2. Restart both Function apps (Azure portal → the app → Restart) so they get tokens carrying the new roles.
3. If the Package Management API rejects calls with a licensing error later, assign an Agent 365 licence as the API documentation describes and try again.

## Step 5: Set up the sharing removal account

ShareGuard blocks, unblocks and removes sharing as `svc-absg@`, using a refresh token you create once by signing in, stored in Key Vault. Until this step is done, the guard detects shared agents but can't block them.

1. **Register the delegated client** (PowerShell):

   ```powershell
   ./azure/scripts/Register-AbsgDelegatedClient.ps1 -ParametersFile $p
   ```

   Put the client id it prints in `delegatedClientId` in the parameters file.
2. **Open the vault to your IP for a moment**: set `adminIpRanges` to `["<your-ip>/32"]` and redeploy (bash): `./azure/deploy.sh rg-absg-test ~/absg/main.parameters.test.json`. The vault is private otherwise.
3. **Give yourself rights on the vault** (bash):

   ```bash
   az role assignment create --role "Key Vault Secrets Officer" --assignee <your-upn> \
     --scope $(az keyvault show -n <kv-name> --query id -o tsv)
   ```

4. **Sign the account in once** (bash). Create `local.json` with only these keys:

   ```json
   {"tenant_id": "<tenant-id>", "client_id": "unused", "use_managed_identity": true,
    "delegated_client_id": "<delegated-client-id>", "delegated_username": "svc-absg@<domain>",
    "delegated_token_cache": "absg_delegated_cache.json"}
   ```

   ```bash
   absg --config local.json --login-delegated
   ```

   Open the device-code link it prints and sign in as `svc-absg@<domain>`.
5. **Move the token cache into Key Vault and delete the local copy** (bash):

   ```bash
   az keyvault secret set --vault-name <kv-name> --name delegated-token-cache --file absg_delegated_cache.json
   shred -u absg_delegated_cache.json
   ```

6. **Close the vault again**: set `adminIpRanges` back to `[]` and redeploy.
7. **Conditional Access** (recommended even in a test tenant): allow `svc-absg@` to sign in only from the NAT public IP in the worksheet. Add the NAT IP as a named location first.

If the refresh token later expires (sign-in frequency, password reset), sharing removal fails, admins are told and the agent stays blocked. Repeat steps 2 to 6 to restore it.

## Step 6: Finish the configuration and check the first cycles

Redeploy with every value filled in, then confirm the guard completes cycles in dry run without permission errors.

1. **Redeploy** with `delegatedClientId` set and `adminIpRanges` empty (bash): `./azure/deploy.sh rg-absg-test ~/absg/main.parameters.test.json`. Code-only changes later: add `--code-only`.
2. **Run a cycle now instead of waiting 5 minutes** (bash, from the deployment IP):

   ```bash
   KEY=$(az functionapp keys list -g rg-absg-test -n func-absg-guard-test --query masterKey -o tsv)
   curl -s -X POST "https://func-absg-guard-test.azurewebsites.net/admin/functions/guard_cycle" \
     -H "x-functions-key: $KEY" -H "Content-Type: application/json" -d '{"input":""}'
   ```

   The signer's function is `registry_signer` on `func-absg-signer-test`, called the same way.
3. **Read the logs** (Azure portal → Application Insights → Logs):

   ```kusto
   AppTraces
   | where TimeGenerated > ago(1h)
   | where Message has "absg"
   | project TimeGenerated, AppRoleName, SeverityLevel, Message
   | order by TimeGenerated desc
   ```

   Expect an `absg cycle_end` line every cycle with `scanned` equal to the number of Agent Builder agents. Any `Graph error 401` or `403` means a missing role (Step 4) or an API that rejects app-only tokens; record which call failed.
4. **Check what was written to SharePoint** on the Operations site:
   - *ABSG State* stays empty in dry run: the guard writes `state.json` only once it enforces.
   - *ABSG Audit* holds `absg-audit-<today>.jsonl`, with `cycle_start` and `cycle_end` records.
   - On the Registry site, *ABSG Signer Audit* holds the signer's file once it has run.
5. **Check the audit chain**: the nightly `verify_audit_chain` function logs `absg audit_verified` when the chain is intact. On the first day you can also download the day's file and run `absg --verify-audit absg-audit-<today>.jsonl` locally.

## Step 7: Build the acknowledgement form and the two flows

One form and flow carry owner confirmations to the guard, and a second flow runs the review; build both signed in as `svc-absg-flow@`, with standard connectors only.

### Acknowledgement form and flow

1. **Microsoft Form**: set *Only people in my organization can respond* and *Record name*. Two questions:
   1. *Confirmation token* (text). Tell people not to change it.
   2. *I confirm ShareGuard may remove sharing from my agent and unblock it for my personal use* (choice: Yes).
2. **Pre-filled link**: ⋯ → Get pre-filled URL, type `TOKEN` in question 1, copy the link and replace `TOKEN` with `{token}`. Put it in `ackFormUrl` and redeploy. A non-empty `ackFormUrl` turns acknowledgements on.
3. **Cloud flow** *ShareGuard acknowledgements*:
   - Trigger: *Microsoft Forms → When a new response is submitted* (your form).
   - *Microsoft Forms → Get response details*.
   - *SharePoint → Create item* on the Operations site, list *Agent Acknowledgements*: `Title` = response id, `Token` = question 1, `ResponderUpn` = *Responders' Email*, `Status` = `New`.

### Review and approval flow

Create the cloud flow *ShareGuard sharing review* on the Registry site's *Agent Sharing Requests* list:

1. Trigger: *SharePoint → When an item is created*.
2. *Update item*: `Status` = `In review`.
3. *Do until* `ReviewConfigCapturedAt` is not empty, with a limit of 12 runs: *Delay* 5 minutes, then *Get item*. The signer fills `ReviewConfigCapturedAt`, `ReviewConfigHash` and `ReviewConfigSummary` on its next run (every 15 minutes).
4. *Approvals → Start and wait for an approval* (*Approve/Reject – First to respond*), assigned to Jane. In *Details*, include `PackageId`, `Owners`, `AudienceGroupIds`, `ExpiresAt`, `Justification` and the whole `ReviewConfigSummary`: it's the configuration being approved.
5. Before answering, the reviewer opens the item in the list and sets the criteria columns `KS01`–`AC01` (Pass, Fail or N/A), `Evidence`, `RiskRating` and, if needed, `Conditions` and `PolicyJson`.
6. *Condition* on the outcome:
   - Approve: *Update item* `Status` = `Approved`, `ApprovedBy` = the responder's email.
   - Reject: *Update item* `Status` = `Rejected`, `ReviewerComments` = the response comments.

Only the flow account and the reviewers edit a request after it's created. That matches `signerTrustedEditors`, so the signer's edit-history check accepts these requests.

## Step 8: Smoke checks in dry run

In dry run the guard decides everything but changes nothing: each decision is audited with `outcome` = `simulated`, and no email is sent. Run these checks before enforcing anything.

Find each agent's package id in the audit records (`package.id`), or in Graph Explorer as an admin: `GET https://graph.microsoft.com/v1.0/copilot/admin/catalog/packages?$filter=platform eq 'Microsoft 365 Copilot Agent Builder'`. Use Graph Explorer for the package detail checks too.

| # | Do this | Expect |
| --- | --- | --- |
| 1 | Nothing; run a cycle | `cycle_end` with `scanned` = 2 and no `block` records. An `owner_resolved` record naming Olivia for each agent. |
| 2 | As Olivia, share *HR helper* with Rita; run a cycle | A `block` record, `outcome` = `simulated`, `recipients` naming Rita. The agent stays usable; no email. |
| 3 | Share *Personal notes* with `g-absg-other`; run a cycle | A second simulated `block`, the recipient being the group. |
| 4 | Open both agents' package detail | `sharedWithUsersAndGroups` holds only the people you shared with, never Olivia. `availableTo` is not `all`. |
| 5 | Look at `lastUsedDateTime` in the detail | Present and recent. If it's missing, inactivity falls back on the last edit date; note it before testing retirement. |
| 6 | Note the time between sharing and the `block` record | This is the propagation delay; it decides how quickly a share can be caught. |
| 7 | Remove both shares; run a cycle | No further `block` records for either agent. |

**Take the signer out of dry run now.** In dry run the signer never writes the review snapshot, so the approval flow would wait for ever. The signer only writes to the registry site, so this is safe: on `func-absg-signer-test` → Settings → Environment variables, set `ABSG_DRY_RUN` to `false`, save and restart. A later full redeploy sets it back from `dryRun`.

## Step 9: Enforce and run the test scenarios

Turn enforcement on, then run the scenarios in order: each one starts from the state the previous one left.

**Turn enforcement on**: set `dryRun` to `false` in the parameters file and redeploy (bash): `./azure/deploy.sh rg-absg-test ~/absg/main.parameters.test.json`. Run a guard cycle by hand (Step 6) after each action, or wait up to 5 minutes. Emails come from the shared mailbox.

### Sharing without approval

| # | Do this | Expect |
| --- | --- | --- |
| 1 | As Olivia, share *HR helper* with Rita | `block` with `outcome` = `success`. Olivia gets a notice with a *Confirm* link; Rita can no longer use the agent. |
| 2 | Forward the notice to Rita; as Rita, submit the form | The *Agent Acknowledgements* item turns `Rejected`: *responder is not the owner the link was sent to*. The agent stays blocked. |
| 3 | As Olivia, open the link and submit the form | Next cycle: the item turns `Accepted` then `Closed`; `sharing_removal` (success), then `unblock`. Olivia gets a *restored* email, and Agent Builder shows no sharing. If sharing is still there, record it: this checks Microsoft's undocumented `PATCH` behaviour. |
| 4 | Share *Personal notes* with Rita, then remove the share yourself before confirming | `block`, then `unblock` with *sharing removed*. |
| 4a | Repeat scenario 4 twice more (3 blocks in 30 days) | The third `block` also records `repeat_violation_locked`; Olivia gets a *locked* notice with no link, admins an alert. Removing the share now gives `unblock_withheld` and the agent stays blocked. |
| 4b | As Jane, add an item to *Agent Lock Releases* (Operations site): `Title` = the package id, `Reason` | Next cycle: `lock_released` naming Jane, the item turns `Applied`, then `unblock`. Locally: `absg --config C:\absg\config.json --release-lock <package-id> --by jane.risk@<domain> --reason "Reviewed"`. |
| 4c | As Olivia, build six more agents and share all of them with Rita in one go | The first five are blocked as usual; the sixth and later are held: `daily_share_limit_locked`, a notice saying *blocked until* 00:00 UTC tomorrow, no link. Removing their sharing doesn't release them today. |

### Approval, drift and revocation

| # | Do this | Expect |
| --- | --- | --- |
| 5 | As Olivia, add an item to *Agent Sharing Requests*: `PackageId` = HR helper, `Owners` = `olivia@<domain>`, `AudienceGroupIds` = the id of `g-absg-approved-audience`, `ExpiresAt` = 90 days ahead, `Justification` | The flow sets `In review`. Within 15 minutes the signer fills `ReviewConfigSummary`; then Jane gets the approval. |
| 6 | As Olivia, try to edit that request | Refused: the *ABSG Submit* level can't edit items. |
| 7 | As Jane, score every criterion Pass or N/A, set `RiskRating`, and approve | Next signer run: `Registered`, with `RegisteredEntryHash`, and an item in *Approved Agents*. The signer audit has `registry_entry_signed`. |
| 8 | Share *HR helper* with `g-absg-approved-audience` | No block; a `registry_validation` record with `result` = `compliant`. |
| 9 | Also share it with `g-absg-other` | `block` with `blockType` = `drift` and rule `SHARE-SCOPE`; Olivia gets a drift notice. Remove that share: `unblock`. |
| 10 | Upload a file to *HR helper* as knowledge | `block`, rule `EMBEDDED-FILES`. Remove the file: `unblock` with *configuration drift rectified*. |
| 11 | Submit a second request for *Personal notes*; after `ReviewConfigSummary` appears, add a knowledge source to the agent; Jane approves | `Needs criteria`: *the agent changed after the review started*, with a new summary. Jane approves again: `Registered`. |
| 12 | Jane sets the *HR helper* request to `Revoke requested` | Signer: `Revoked`. Guard: `block`, *registry approval isn't valid: registry status is 'revoked'*. |
| 13 | As a Registry site owner, restore the earlier (approved) version of the *Approved Agents* item from its version history | `registry_rollback_rejected` and an admin alert; the agent stays blocked. |
| 14 | Edit any character of an entry's `EntryJson` by hand | `registry_entry_invalid`; that agent is treated as unapproved. |

### Owners and lifecycle

| # | Do this | Expect |
| --- | --- | --- |
| 15 | As Noah, build an agent and leave it unshared for one cycle; then block Noah's sign-in (Entra admin centre) | `ownerless_detected` and an admin alert (`ownerless_action` = `report`). |
| 16 | Set `lifecycle` to `inactivity_days` 2, `inactivity_notice_days` 1, `inactivity_reminder_days` 0, `archive_after_days` 0; redeploy; leave an unused, unshared agent for 2 days | `inactivity_warning` and a notice; then `block` with `blockType` = `retired`; next cycle `agent_archived` in *Retired Agents* and an admin request to delete it. |
| 17 | Before deleting it, Olivia uses the *Reactivate* link | `reactivation_requested`, `unblock`, `deletion_cancelled`. If the agent was shared meanwhile: `block_reason_changed` instead, and it stays blocked. |
| 18 | Delete a retired agent in the admin centre | `agent_deleted` on the next cycle. |

After the scenarios, check the audit chain again (the nightly `absg audit_verified` line), and look through the Application Insights alerts that fired.

## Alternative: run ShareGuard locally on Windows

Without an Azure subscription, the guard runs as a Python program on a Windows PC: it uses an app registration with a client secret, keeps its state and audit trail in local files, and you sign approvals yourself with a local key.

### What changes

| Azure path | Local path |
| --- | --- |
| Function apps on a 5-minute timer | `absg` running in a PowerShell window (or Task Scheduler) |
| Managed identities | One app registration with a client secret |
| SharePoint state, audit, acknowledgements | JSON files in `C:\absg\data` |
| Registry list, signer app and Key Vault HSM key | A local `registry.json`, signed with an Ed25519 key you create |
| Sharing requests list and review flow | Not used: you draft, complete and sign entries on the command line |
| Microsoft Forms acknowledgement | The built-in confirmation page on `localhost`, or no acknowledgements |
| Archive library | A local folder |
| Application Insights alerts, NAT IP | None: read the console and the audit file |

Skip Steps 2 to 8. From Step 1 you need the test users, groups, the shared mailbox, the sharing removal account and the two test agents; the flow account isn't needed.

### L1. Register the ShareGuard app

1. Entra admin centre → App registrations → New registration: `ShareGuard local test`, single tenant. Note its **Application (client) id**.
2. API permissions → Add → Microsoft Graph → **Application permissions**: `CopilotPackages.ReadWrite.All`, `User.Read.All`, `GroupMember.Read.All`. Then **Grant admin consent**. Don't add `Mail.Send` here.
3. Certificates & secrets → New client secret, expiry 30 days. Copy the value now; it's shown once.
4. Enterprise applications → `ShareGuard local test`: note its **Object id** (the service principal).
5. Let it send mail from the shared mailbox only (PowerShell 7, as Exchange admin):

   ```powershell
   ./azure/scripts/Grant-AbsgMailbox.ps1 -Mailbox shareguard@<domain> `
     -GuardClientId <application-client-id> -GuardPrincipalId <enterprise-app-object-id>
   ```

6. Register the client for the sharing removal account:

   ```powershell
   ./azure/scripts/Register-AbsgDelegatedClient.ps1 -ServiceAccount svc-absg@<domain> -DisplayName 'ShareGuard local removal'
   ```

   Note the delegated client id it prints.

### L2. Install on Windows

In PowerShell 7 (`winget install --id Microsoft.PowerShell`):

```powershell
winget install -e --id Python.Python.3.12
winget install -e --id Git.Git
git clone https://github.com/agus-rachman/shareguard-for-agent-builder.git C:\absg\src
cd C:\absg\src
py -3.12 -m venv .venv
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.\.venv\Scripts\Activate.ps1
pip install -e .
absg --version
```

Create the data folder and limit it to your account, since it will hold the sharing removal account's token:

```powershell
New-Item -ItemType Directory C:\absg\data, C:\absg\keys | Out-Null
icacls C:\absg\data /inheritance:r /grant:r "${env:USERNAME}:(OI)(CI)F"
icacls C:\absg\keys /inheritance:r /grant:r "${env:USERNAME}:(OI)(CI)F"
```

### L3. Create the registry signing key

```powershell
absg --registry-keygen C:\absg\keys
```

This writes `absg_registry_signing_key.pem` (private: only you, as the approver, use it) and `absg_registry_public_key.pem` (the guard reads it). In a real deployment the private key would be kept offline.

### L4. Write the configuration

Save as `C:\absg\config.json`, in UTF-8 without a byte-order mark (VS Code, or Notepad on Windows 11, does this). Use forward slashes in paths.

```json
{
  "tenant_id": "<tenant-id>",
  "client_id": "<application-client-id>",
  "dry_run": true,
  "poll_interval_seconds": 120,
  "state_file": "C:/absg/data/absg_state.json",
  "audit_file": "C:/absg/data/absg_audit.jsonl",
  "mail_sender": "shareguard@<domain>",
  "admin_emails": ["admin@<domain>"],
  "helpdesk_contact": "the ShareGuard test team",
  "ack_enabled": true,
  "ack_base_url": "http://localhost:8080/ack",
  "ack_listen_host": "127.0.0.1",
  "ack_listen_port": 8080,
  "ack_require_identity": false,
  "ack_store_file": "C:/absg/data/absg_acks.json",
  "delegated_client_id": "<delegated-client-id>",
  "delegated_username": "svc-absg@<domain>",
  "delegated_token_cache": "C:/absg/data/absg_delegated_cache.json",
  "registry_file": "C:/absg/data/registry.json",
  "registry_public_key_file": "C:/absg/keys/absg_registry_public_key.pem",
  "archive_dir": "C:/absg/data/archive",
  "owner_status_checks": true,
  "ownerless_action": "report",
  "inactivity_days": null
}
```

Create an empty registry so the guard has one to read: `'{"agents": []}' | Out-File -Encoding utf8NoBOM C:\absg\data\registry.json`.

**About the confirmation page**: with `ack_require_identity` set to `false`, anyone holding the link could confirm, and the link only opens on this PC. That's acceptable for a test on one machine, never for real use. To skip acknowledgements entirely, set `ack_enabled` to `false`: owners then remove sharing themselves and the guard unblocks the agent.

### L5. Set the secrets for the session

The client secret and the acknowledgement key come from environment variables, never the config file. Set them in each new PowerShell window before running `absg`:

```powershell
$env:ABSG_CLIENT_SECRET = '<client-secret-value>'
$env:ABSG_ACK_SECRET = (python -c "import secrets; print(secrets.token_urlsafe(48))")
```

Keep the same `ABSG_ACK_SECRET` for the whole test (store it in a password manager): a new value invalidates every link already emailed.

### L6. Sign in the sharing removal account

```powershell
absg --config C:\absg\config.json --login-delegated
```

Open the device-code link, sign in as `svc-absg@<domain>`. The token cache is written to `C:\absg\data\absg_delegated_cache.json`. Optionally add a Conditional Access policy allowing this account to sign in only from your public IP.

### L7. Run it

- **One cycle**: `absg --config C:\absg\config.json --once`
- **Continuously**, with the confirmation page on `http://localhost:8080/ack`: `absg --config C:\absg\config.json`. Leave the window open; Ctrl+C stops it.
- **Read what happened**: the console shows `BLOCK` and `UNBLOCK` lines. For the full record:

  ```powershell
  absg --audit-history C:\absg\data\absg_audit.jsonl --package <package-id>
  absg --verify-audit C:\absg\data\absg_audit.jsonl
  ```

- **Unattended** (optional): Task Scheduler can run `absg --once` every 5 minutes, but then the confirmation page isn't running; use `ack_enabled: false` in that case. Never run two copies at once: they share the state file.

The guard refuses to start if the audit chain is broken. Never edit the audit file; to start again, move the whole `C:\absg\data` folder aside.

### L8. Approve an agent from the command line

Locally there is no requests list or signer: you play the reviewer by drafting an entry from the live agent, completing it and signing it.

1. **Share the agent with its approved audience first** (here `g-absg-approved-audience`), in dry run, so the draft records the audience exactly as the API reports it.
2. **Draft the entry** from the live agent; it captures the configuration baseline:

   ```powershell
   New-Item -ItemType Directory C:\absg\work -Force | Out-Null
   absg --config C:\absg\config.json --registry-draft <package-id> | Out-File -Encoding utf8NoBOM C:\absg\work\hr-draft.json
   ```

3. **Complete the approval** in an editor: in `approval`, set `requestId` (for example `TEST-1`), `approvedBy` (`jane.risk@<domain>`), `expiresAt` (an ISO date-time such as `2027-03-01T00:00:00+00:00`) and `riskRating`, and give every item in `criteria` a `result` (`pass`, `fail` or `n/a`) and an `evidence` text. Check `owners` and `sharing.allowedPrincipals`. Signing refuses unfinished top-level approval fields, but not unfinished criteria, so check those yourself.
4. **Sign it**:

   ```powershell
   absg --registry-sign C:\absg\work\hr-draft.json --key C:\absg\keys\absg_registry_signing_key.pem |
     Out-File -Encoding utf8NoBOM C:\absg\work\hr-signed.json
   ```

5. **Publish it to the registry** (list every signed file you want approved):

   ```powershell
   python -c "import json,sys; json.dump({'agents':[json.load(open(f,encoding='utf-8')) for f in sys.argv[1:]]}, open('C:/absg/data/registry.json','w',encoding='utf-8'), indent=2)" C:\absg\work\hr-signed.json
   ```

   Don't build the file with `ConvertFrom-Json` and `ConvertTo-Json`: PowerShell rewrites dates and numbers, and the signature then no longer verifies.
6. **Check it**: `absg --config C:\absg\config.json --registry-validate` prints each entry as `compliant`, `violation` or `approval_not_valid`.

**To revoke**: change `"status"` to `"revoked"` in the signed file, sign it again (step 4, to a new file such as `hr-revoked.json`) and publish that (step 5). Re-signing records a later `signedAt`, so the guard takes it over the earlier entry.

### L9. Test scenarios when running locally

Run the Step 9 scenarios with these differences. Turn enforcement on by setting `"dry_run": false` in `config.json` and restarting `absg`.

| Step 9 scenarios | Locally |
| --- | --- |
| 1, 3, 4 | As written. The notice's *Confirm* link opens `http://localhost:8080/ack` on this PC; tick the box and confirm. |
| 2 (forwarded link) | Behaves differently: with `ack_require_identity` off, a forwarded link **is** accepted. Identity checks need an authenticating proxy in front of the page, or the Azure path's Forms flow. |
| 5, 6, 7, 11 (requests list, review flow, signer checks) | Not available. Approve with L8 instead; reviewer independence and the review snapshot aren't enforced, since you sign directly. |
| 8, 9, 10 | As written, after approving *HR helper* with L8. |
| 12 (revoke) | Revoke as described under L8. |
| 13 (rollback) | Publish the earlier `hr-signed.json` again after the revoked one: `registry_rollback_rejected`, and the agent stays blocked. |
| 14 (tampering) | Change one character inside an entry in `registry.json`: `registry_entry_invalid`. |
| 15 to 18 (owners and lifecycle) | As written; set the `inactivity_*` and `archive_after_days` values in `config.json`. Archives go to `C:\absg\data\archive`. |

Emails, alerts and every decision are still recorded in `absg_audit.jsonl`; there are no Application Insights alerts, so watch the console and admin emails instead.

**Cleaning up locally**: stop `absg`, remove test sharing (or unblock agents in the Microsoft 365 admin centre), delete the app registrations `ShareGuard local test` and `ShareGuard local removal`, remove the Exchange role assignment, and delete `C:\absg`.

## Troubleshooting

Most first-run problems come from a missing permission or a value left out of the parameters file.

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `Graph error 401` or `403` in the logs | A role not granted yet, or tokens issued before the grant | Re-run Step 4, then restart the app. If it persists on the Package Management API only, the API may reject app-only tokens: record it for the maintainers. |
| `curl` to the admin endpoint returns 403 | Your IP isn't in `deploymentIpRanges` | Add it and redeploy. |
| The review flow never gets past *Do until* | The signer is still in dry run, can't write to the Registry site, or the `PackageId` is wrong | Check `ABSG_DRY_RUN` on the signer (Step 8), Step 4, and the request's `SignerComments`. |
| Requests turn `Needs criteria`: *edited by …, who isn't a reviewer or the approval flow* | Someone outside `signerTrustedEditors` edited the request, or the signer's own updates appear under an id other than its client id | Look at the request's version history. If the name shown is the signer's identity, add the id it shows to `signerTrustedEditors` and redeploy. |
| `Needs criteria`: *this request is already registered* | A registered request was approved again | Submit a new request to change or renew an approval. |
| An agent stays blocked with `unblock_withheld` | It's locked after repeated violations | Release it through *Agent Lock Releases* (or `--release-lock` locally), after reviewing it with the owner. |
| `enforcement_identity_failed`, or sharing removal fails: *Delegated sign-in missing or expired* | The refresh token expired or was revoked, or `svc-absg@` lost its admin role | Repeat Step 5, steps 2 to 6, and check the role. Nothing is blocked or released until it works. |
| No emails arrive | Mailbox scope not granted, or Exchange still propagating | Re-run `Grant-AbsgMailbox.ps1`; allow time for the RBAC change to take effect. |
| An agent stays blocked after sharing is removed | An admin blocked it (ShareGuard never touches those), or a failed cycle | Check `blocked_by_guard` in `state.json` and the `error` records in the audit. |
| `audit_integrity_failure` | An audit file was edited or a record is missing | Don't edit audit files; compare with the copy in Application Insights (`audit_to_log`). |

## Tear the environment down

Remove things in this order, so nothing is left blocked or running.

1. **Release agents**: remove all test sharing and run a guard cycle; the guard unblocks what it blocked. Unblock anything still blocked in the Microsoft 365 admin centre → Agents.
2. **Stop the apps**: set `ABSG_DRY_RUN` to `true` on both apps, or stop them.
3. **Delete the Azure resources** (bash): `az group delete -n rg-absg-test`. The Key Vault stays soft-deleted for its retention period; purge it (`az keyvault purge -n <kv-name>`) if purge protection allows, or use a different name next time.
4. **Delete the app registrations**: the delegated client and the PnP app. The managed identities and their Graph roles go with the resource group.
5. **Delete the Microsoft 365 parts**: both flows, the form, the three SharePoint sites (not possible while record labels hold files), the shared mailbox, the service accounts, test users and groups.
