# Naming convention

These are the defaults. To use your organisation's own names for Azure resources, identities, Entra and Exchange objects and SharePoint lists, set them in the parameters file: see [Naming](customisation.md#naming) in the customisation guide.

The formal name **ShareGuard for Agent Builder** is used wherever people read it: documents, emails and web pages. Documentation shortens it to **ShareGuard** after the first mention. The short name **ABSG** (`absg`) is used only where systems read it: code, scripts, configuration and the names of deployed components.

| Thing | Convention | Example |
|---|---|---|
| Formal name (documents, email footer, web page titles) | ShareGuard for Agent Builder | |
| Short name in prose (after the first mention) | ShareGuard | |
| Short name (code, scripts, resources, logs) | `ABSG` / `absg` | |
| Python package and modules | `absg`, `absg.<area>` | `absg.core`, `absg.ack`, `absg.mail`, `absg.registry` |
| Environment variables | `ABSG_*` | `ABSG_TENANT_ID`, `ABSG_ACK_SECRET` |
| Local or working files | `absg_*` | `absg_state.json`, `absg_audit.jsonl`, `absg_acks.json` |
| Signing keys | `absg_registry_*` | `absg_registry_signing_key.pem`, `absg_registry_public_key.pem` |
| Logger names | `absg`, `absg.<area>` | `absg.mail`, `absg.ack`, `absg.registry` |
| Email | Display name "ShareGuard for Agent Builder" (`email_brand_name`); subject prefix `[ShareGuard for Agent Builder]` on admin alerts; header `X-ABSG: <template>` on every message | `shareguard@contoso.com` |
| Webhook and audit `source` | `absg`, `ack_endpoint` | |
| Azure resources | `<type>-absg[-<role>]-<env>`, keeping Azure's type abbreviations (storage: `stabsg<env>`) | `rg-absg-prod`, `func-absg-guard-prod`, `func-absg-signer-prod`, `kv-absg-prod`, `id-absg-guard-prod`, `id-absg-signer-prod`, `stabsgprod` |
| Entra objects | `ABSG - <purpose>`; service accounts `svc-absg-<role>@` | `ABSG - Governance Reviewers`, `svc-absg@`, `svc-absg-flow@` |
| SharePoint | Sites `ABSG <area>` at `/sites/absg-<area>`; ShareGuard-owned libraries and lists prefixed `ABSG`; workflow lists people use keep plain names | `ABSG Registry`, `ABSG Operations`, `ABSG Archive`, `ABSG State`, `ABSG Audit`, `Approved Agents`, `Agent Acknowledgements`, `Retired Agents` |

