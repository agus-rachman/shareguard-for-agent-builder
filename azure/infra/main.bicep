// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The ShareGuard for Agent Builder Authors
//
// ShareGuard for Agent Builder - Azure deployment (one resource group per environment).
//
//   * two Flex Consumption Function apps (guard, registry signer), each with its own
//     user-assigned managed identity; no HTTP triggers
//   * VNet integration with a NAT gateway: one static outbound IP for Conditional Access
//   * Key Vault Premium (RBAC, purge protection, private endpoint): EC-HSM P-256 registry
//     signing key, acknowledgement HMAC key, delegated token cache
//   * storage for the Functions runtime (private endpoints, no shared keys)
//   * Log Analytics + Application Insights (Entra-authenticated ingestion) and alerts
//
// Deploy:  az deployment group create -g rg-absg-prod -f main.bicep -p main.parameters.json
// Customise names, schedules, lifecycle and email in the parameters file: see
// docs/customisation.md. Every name below comes from the `naming` and `sharePointNames`
// parameters (with defaults), so nothing needs editing in this file.
// Then run the scripts in ../scripts (Graph permissions, SharePoint, Exchange, delegated sign-in).

targetScope = 'resourceGroup'

@description('Environment suffix used in resource names, for example prod or pilot.')
@maxLength(8)
param env string = 'prod'

@description('Azure region. Use the same geography as the Microsoft 365 tenant.')
param location string = resourceGroup().location

@description('Graph site id of the ABSG Operations site (hostname,siteCollectionId,webId).')
param operationsSiteId string

@description('Graph site id of the ABSG Registry (governance) site.')
param registrySiteId string

@description('Graph site id of the restricted site that retired agents are archived to (empty = the Operations site).')
param archiveSiteId string = ''

@description('Names of Azure resources, Key Vault objects and Entra objects. Set workload to change the code used in every default name, or override single names. See docs/customisation.md for the keys.')
param naming object = {}

@description('Names of the SharePoint lists, libraries and folders. See docs/customisation.md for the keys.')
param sharePointNames object = {}

@description('Lifecycle settings merged into the guard configuration, for example inactivity_days, inactivity_notice_days, inactivity_reminder_days, archive_after_days, deletion_mode, ownerless_action.')
param lifecycle object = {}

@description('Sharing criteria reviewers score, each { column, id, description }; each column becomes a Pass/Fail/N/A choice in the requests list. Empty = the defaults (KS01, KS02, DS01, AU01, AC01).')
param approvalCriteria array = []

@description('Longest approval a reviewer may grant, in days.')
param maxApprovalDays int = 365

@description('Who may change a sharing request after it is submitted: the approval flow account and the reviewers (UPNs or Entra object ids). The signer refuses requests edited by anyone else. Empty = not checked (not recommended).')
param signerTrustedEditors array = []

@description('Email settings merged into the guard configuration, for example email_brand_name, email_subject_prefix, email_footer, email_button_colour.')
param email object = {}

@description('Shared mailbox the notices are sent from.')
param mailSender string

@description('Admin alert recipients.')
param adminEmails array

@description('Copilot agent policy page linked from every email.')
param policyUrl string = ''

@description('Helpdesk text shown in email footers.')
param helpdeskContact string = 'the IT service desk'

@description('Pre-filled Microsoft Forms link for owner acknowledgements; {token} is replaced. Empty = acknowledgements off.')
param ackFormUrl string = ''

@description('Client id of the public client app used by the sharing-removal account (empty = no removal on behalf).')
param delegatedClientId string = ''

@description('UPN of the sharing-removal service account.')
param delegatedUsername string = ''

@description('Start in dry run: decide, audit and email nothing for real. Set false after the pilot.')
param dryRun bool = true

@description('Any other guard settings merged into ABSG_CONFIG_JSON last (for example owner_fields, exempt_ids, max_blocks_per_cycle).')
param guardSettings object = {}

@description('Purview retention label applied to closed audit files (empty = none).')
param auditRetentionLabel string = ''

@description('Guard schedule (NCRONTAB).')
param guardSchedule string = '0 */5 * * * *'

@description('Signer schedule (NCRONTAB).')
param signerSchedule string = '0 */15 * * * *'

@description('Nightly audit chain check schedule (NCRONTAB, UTC).')
param auditCheckSchedule string = '0 30 2 * * *'

@description('Raise the "not running" alert when no guard cycle completed in this many minutes (about 4 x the guard interval).')
param notRunningAlertMinutes int = 20

@description('Public IP ranges (CIDR) allowed to deploy code to the Function apps, for example the CI runner. Empty = deployment from inside the VNet only.')
param deploymentIpRanges array = []

@description('Public IP ranges (CIDR) allowed to reach Key Vault data plane, for the admin who uploads the delegated token cache. Remove after setup.')
param adminIpRanges array = []

@description('First deployment: create the acknowledgement HMAC key and an empty delegated token cache. Set false afterwards, or the key is rotated and the uploaded token cache is overwritten.')
param initialiseSecrets bool = true

@secure()
@description('Acknowledgement HMAC key (generated when left empty).')
param ackTokenKey string = '${newGuid()}${newGuid()}'

@description('Email address for alert notifications.')
param alertEmail string = ''

// ------------------------------------------------------------------ names
var workload = toLower(naming.?workload ?? 'absg')
var suffix = '${workload}-${env}'
var unique = uniqueString(resourceGroup().id)
var names = union({
  logAnalytics: 'log-${suffix}'
  appInsights: 'appi-${suffix}'
  guardIdentity: 'id-${workload}-guard-${env}'
  signerIdentity: 'id-${workload}-signer-${env}'
  natPublicIp: 'pip-nat-${suffix}'
  natGateway: 'ng-${suffix}'
  vnet: 'vnet-${suffix}'
  functionSubnet: 'snet-func'
  endpointSubnet: 'snet-pe'
  storage: take('st${replace(workload, '-', '')}${env}${unique}', 24)
  keyVault: take('kv-${suffix}-${unique}', 24)
  plan: 'asp-${suffix}'
  guardApp: 'func-${workload}-guard-${env}'
  signerApp: 'func-${workload}-signer-${env}'
  actionGroup: 'ag-${suffix}'
  registryKey: 'registry-signing-key'
  ackSecret: 'ack-token-hmac-key'
  delegatedCacheSecret: 'delegated-token-cache'
}, naming)
var sp = union({
  stateLibrary: 'ABSG State'
  auditLibrary: 'ABSG Audit'
  acknowledgementsList: 'Agent Acknowledgements'
  registryList: 'Approved Agents'
  requestsList: 'Agent Sharing Requests'
  signerAuditLibrary: 'ABSG Signer Audit'
  archiveLibrary: 'Retired Agents'
  templatesFolder: ''
}, sharePointNames)

var tenantId = subscription().tenantId
var storageName = names.storage
var keyVaultName = names.keyVault
var registryKeyName = names.registryKey
var ackSecretName = names.ackSecret
var delegatedCacheSecretName = names.delegatedCacheSecret

var roles = {
  blobOwner: 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
  queueContributor: '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
  tableContributor: '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
  metricsPublisher: '3913510d-42f4-4e42-8a64-420c390055eb'
  kvSecretsUser: '4633458b-17de-408a-b874-0445c86b69e6'
  kvSecretsOfficer: 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'
  kvCryptoUser: '12338af0-0e69-4776-bea7-57ae8d297424'
  kvCryptoEncryptionUser: 'e147488a-f6f5-4113-8e2d-b22465e65bf6'
}

// ------------------------------------------------------------------ monitoring
resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: names.logAnalytics
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 90
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: names.appInsights
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'other'
    WorkspaceResourceId: logs.id
    DisableLocalAuth: true
  }
}

// ------------------------------------------------------------------ identities
resource guardId 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: names.guardIdentity
  location: location
}

resource signerId 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: names.signerIdentity
  location: location
}

// ------------------------------------------------------------------ network
resource natIp 'Microsoft.Network/publicIPAddresses@2024-01-01' = {
  name: names.natPublicIp
  location: location
  sku: { name: 'Standard' }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
  }
}

resource nat 'Microsoft.Network/natGateways@2024-01-01' = {
  name: names.natGateway
  location: location
  sku: { name: 'Standard' }
  properties: {
    idleTimeoutInMinutes: 10
    publicIpAddresses: [ { id: natIp.id } ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2024-01-01' = {
  name: names.vnet
  location: location
  properties: {
    addressSpace: { addressPrefixes: [ '10.80.0.0/24' ] }
    subnets: [
      {
        name: names.functionSubnet
        properties: {
          addressPrefix: '10.80.0.0/26'
          natGateway: { id: nat.id }
          delegations: [ { name: 'flex', properties: { serviceName: 'Microsoft.App/environments' } } ]
        }
      }
      {
        name: names.endpointSubnet
        properties: {
          addressPrefix: '10.80.0.64/27'
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
}

var funcSubnetId = '${vnet.id}/subnets/${names.functionSubnet}'
var peSubnetId = '${vnet.id}/subnets/${names.endpointSubnet}'

var privateZones = [
  'privatelink.blob.${environment().suffixes.storage}'
  'privatelink.queue.${environment().suffixes.storage}'
  'privatelink.table.${environment().suffixes.storage}'
  'privatelink.vaultcore.azure.net'
]

resource zones 'Microsoft.Network/privateDnsZones@2020-06-01' = [for z in privateZones: {
  name: z
  location: 'global'
}]

resource zoneLinks 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = [for (z, i) in privateZones: {
  parent: zones[i]
  name: 'link-${suffix}'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: { id: vnet.id }
  }
}]

// ------------------------------------------------------------------ storage (Functions runtime)
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  sku: { name: 'Standard_ZRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    publicNetworkAccess: 'Disabled'
    networkAcls: { defaultAction: 'Deny', bypass: 'AzureServices' }
    supportsHttpsTrafficOnly: true
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource guardPackages 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'deploy-guard'
}

resource signerPackages 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'deploy-signer'
}

var storageServices = [ 'blob', 'queue', 'table' ]

resource storagePe 'Microsoft.Network/privateEndpoints@2024-01-01' = [for (svc, i) in storageServices: {
  name: 'pe-st-${svc}-${suffix}'
  location: location
  properties: {
    subnet: { id: peSubnetId }
    privateLinkServiceConnections: [ {
      name: svc
      properties: { privateLinkServiceId: storage.id, groupIds: [ svc ] }
    } ]
  }
}]

resource storagePeDns 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-01-01' = [for (svc, i) in storageServices: {
  parent: storagePe[i]
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [ { name: svc, properties: { privateDnsZoneId: zones[i].id } } ]
  }
}]

// ------------------------------------------------------------------ Key Vault
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    tenantId: tenantId
    sku: { family: 'A', name: 'premium' }
    enableRbacAuthorization: true
    enablePurgeProtection: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    publicNetworkAccess: empty(adminIpRanges) ? 'Disabled' : 'Enabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'None'
      ipRules: [for ip in adminIpRanges: { value: ip }]
    }
  }
}

resource registryKey 'Microsoft.KeyVault/vaults/keys@2023-07-01' = {
  parent: vault
  name: registryKeyName
  properties: {
    kty: 'EC-HSM'
    curveName: 'P-256'
    keyOps: [ 'sign', 'verify' ]
    attributes: { enabled: true, exportable: false }
  }
}

resource ackSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (initialiseSecrets) {
  parent: vault
  name: ackSecretName
  properties: { value: ackTokenKey, contentType: 'HMAC key for owner acknowledgement links' }
}

resource ackSecretRef 'Microsoft.KeyVault/vaults/secrets@2023-07-01' existing = {
  parent: vault
  name: ackSecretName
}

resource delegatedCache 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (initialiseSecrets) {
  parent: vault
  name: delegatedCacheSecretName
  properties: { value: '{}', contentType: 'application/json' }
}

resource delegatedCacheRef 'Microsoft.KeyVault/vaults/secrets@2023-07-01' existing = {
  parent: vault
  name: delegatedCacheSecretName
}

resource vaultPe 'Microsoft.Network/privateEndpoints@2024-01-01' = {
  name: 'pe-kv-${suffix}'
  location: location
  properties: {
    subnet: { id: peSubnetId }
    privateLinkServiceConnections: [ {
      name: 'vault'
      properties: { privateLinkServiceId: vault.id, groupIds: [ 'vault' ] }
    } ]
  }
}

resource vaultPeDns 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-01-01' = {
  parent: vaultPe
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [ { name: 'vault', properties: { privateDnsZoneId: zones[3].id } } ]
  }
}

resource vaultLock 'Microsoft.Authorization/locks@2020-05-01' = {
  name: 'lock-kv'
  scope: vault
  properties: { level: 'CanNotDelete', notes: 'Holds the ShareGuard registry signing key.' }
}

// ------------------------------------------------------------------ role assignments
var storageGrants = [
  { who: 'guard', role: roles.blobOwner }
  { who: 'guard', role: roles.queueContributor }
  { who: 'guard', role: roles.tableContributor }
  { who: 'signer', role: roles.blobOwner }
  { who: 'signer', role: roles.queueContributor }
  { who: 'signer', role: roles.tableContributor }
]

resource storageRoles 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for r in storageGrants: {
  name: guid(storage.id, r.who, r.role)
  scope: storage
  properties: {
    principalId: r.who == 'guard' ? guardId.properties.principalId : signerId.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', r.role)
  }
}]

resource insightsRoles 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for who in [ 'guard', 'signer' ]: {
  name: guid(appInsights.id, who, roles.metricsPublisher)
  scope: appInsights
  properties: {
    principalId: who == 'guard' ? guardId.properties.principalId : signerId.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.metricsPublisher)
  }
}]

// Guard: read the ack key, read and update the delegated token cache, read the
// registry key's public part. It can't sign.
resource guardAckSecretRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, 'ack', guardId.id)
  scope: ackSecretRef
  properties: {
    principalId: guardId.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.kvSecretsUser)
  }
  dependsOn: [ ackSecret ]
}

resource guardCacheRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, 'cache', guardId.id)
  scope: delegatedCacheRef
  properties: {
    principalId: guardId.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.kvSecretsOfficer)
  }
  dependsOn: [ delegatedCache ]
}

resource guardKeyReadRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, 'keyread', guardId.id)
  scope: registryKey
  properties: {
    principalId: guardId.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.kvCryptoEncryptionUser)
  }
}

// Signer: sign with the registry key, nothing else in the vault.
resource signerKeyRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, 'sign', signerId.id)
  scope: registryKey
  properties: {
    principalId: signerId.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.kvCryptoUser)
  }
}

// ------------------------------------------------------------------ Function apps
resource plan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: names.plan
  location: location
  kind: 'functionapp'
  sku: { name: 'FC1', tier: 'FlexConsumption' }
  properties: { reserved: true }
}

var commonConfig = {
  tenant_id: tenantId
  use_managed_identity: true
  storage_backend: 'sharepoint'
  sharepoint_operations_site_id: operationsSiteId
  sharepoint_registry_site_id: registrySiteId
  sharepoint_state_library: sp.stateLibrary
  sharepoint_audit_library: sp.auditLibrary
  sharepoint_registry_list: sp.registryList
  sharepoint_requests_list: sp.requestsList
  sharepoint_acks_list: sp.acknowledgementsList
  signer_audit_library: sp.signerAuditLibrary
  key_vault_url: vault.properties.vaultUri
  registry_key_name: registryKeyName
  audit_retention_label: empty(auditRetentionLabel) ? null : auditRetentionLabel
  audit_to_log: true
}

var guardConfig = union(commonConfig, {
  client_id: guardId.properties.clientId
  mail_sender: mailSender
  admin_emails: adminEmails
  policy_url: empty(policyUrl) ? null : policyUrl
  helpdesk_contact: helpdeskContact
  ack_enabled: !empty(ackFormUrl)
  ack_form_url: empty(ackFormUrl) ? null : ackFormUrl
  ack_secret_name: ackSecretName
  delegated_client_id: empty(delegatedClientId) ? null : delegatedClientId
  delegated_username: empty(delegatedUsername) ? null : delegatedUsername
  delegated_cache_secret_name: delegatedCacheSecretName
  sharepoint_archive_site_id: empty(archiveSiteId) ? null : archiveSiteId
  sharepoint_archive_library: sp.archiveLibrary
  sharepoint_templates_folder: empty(sp.templatesFolder) ? null : sp.templatesFolder
}, lifecycle, email, guardSettings)

var signerConfig = union(commonConfig, {
  client_id: signerId.properties.clientId
  approval_criteria: empty(approvalCriteria) ? null : approvalCriteria
  max_approval_days: maxApprovalDays
  signer_trusted_editors: signerTrustedEditors
})

module guardApp 'modules/functionapp.bicep' = {
  name: 'func-guard'
  params: {
    name: names.guardApp
    location: location
    planId: plan.id
    subnetId: funcSubnetId
    identityId: guardId.id
    identityClientId: guardId.properties.clientId
    storageName: storage.name
    deploymentContainerUrl: '${storage.properties.primaryEndpoints.blob}${guardPackages.name}'
    appInsightsConnectionString: appInsights.properties.ConnectionString
    deploymentIpRanges: deploymentIpRanges
    appSettings: [
      { name: 'ABSG_ROLE', value: 'guard' }
      { name: 'ABSG_DRY_RUN', value: string(dryRun) }
      { name: 'ABSG_GUARD_SCHEDULE', value: guardSchedule }
      { name: 'ABSG_VERIFY_SCHEDULE', value: auditCheckSchedule }
      { name: 'ABSG_CONFIG_JSON', value: string(guardConfig) }
    ]
  }
  dependsOn: [ storageRoles, storagePeDns, vaultPeDns, zoneLinks ]
}

module signerApp 'modules/functionapp.bicep' = {
  name: 'func-signer'
  params: {
    name: names.signerApp
    location: location
    planId: plan.id
    subnetId: funcSubnetId
    identityId: signerId.id
    identityClientId: signerId.properties.clientId
    storageName: storage.name
    deploymentContainerUrl: '${storage.properties.primaryEndpoints.blob}${signerPackages.name}'
    appInsightsConnectionString: appInsights.properties.ConnectionString
    deploymentIpRanges: deploymentIpRanges
    appSettings: [
      { name: 'ABSG_ROLE', value: 'signer' }
      { name: 'ABSG_DRY_RUN', value: string(dryRun) }
      { name: 'ABSG_SIGNER_SCHEDULE', value: signerSchedule }
      { name: 'ABSG_CONFIG_JSON', value: string(signerConfig) }
    ]
  }
  dependsOn: [ storageRoles, storagePeDns, vaultPeDns, zoneLinks ]
}

// ------------------------------------------------------------------ alerts
resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = if (!empty(alertEmail)) {
  name: names.actionGroup
  location: 'global'
  properties: {
    groupShortName: take(workload, 12)
    enabled: true
    emailReceivers: [ { name: 'admins', emailAddress: alertEmail, useCommonAlertSchema: true } ]
  }
}

var alerts = [
  {
    name: 'not-running'
    description: 'No completed guard cycle for ${notRunningAlertMinutes} minutes'
    severity: 1
    query: 'AppTraces | where Message startswith "absg cycle_end" | summarize n = count() | where n == 0'
    window: 'PT${notRunningAlertMinutes}M'
  }
  {
    name: 'audit-integrity'
    description: 'Audit chain verification failed'
    severity: 0
    query: 'AppTraces | where Message startswith "absg audit_integrity_failure"'
    window: 'PT15M'
  }
  {
    name: 'circuit-breaker'
    description: 'Circuit breaker tripped (unusual number of blocks)'
    severity: 1
    query: 'AppTraces | where Message startswith "audit " and Message has "\\"event\\": \\"circuit_breaker\\""'
    window: 'PT15M'
  }
  {
    name: 'registry-invalid'
    description: 'A registry entry failed signature verification'
    severity: 1
    query: 'AppTraces | where Message startswith "audit " and Message has "\\"event\\": \\"registry_entry_invalid\\""'
    window: 'PT15M'
  }
  {
    name: 'archive-failed'
    description: 'A retired agent could not be archived'
    severity: 2
    query: 'AppTraces | where Message startswith "audit " and Message has "\\"event\\": \\"archive_failed\\""'
    window: 'PT1H'
  }
  {
    name: 'enforcement-identity'
    description: 'Block or unblock refused: the delegated account can\'t enforce (sign-in expired or role missing?)'
    severity: 1
    query: 'AppTraces | where Message startswith "audit " and Message has "\\"event\\": \\"enforcement_identity_failed\\""'
    window: 'PT15M'
  }
  {
    name: 'delegated-expired'
    description: 'Sharing removal failed (delegated sign-in missing or expired?)'
    severity: 2
    query: 'AppTraces | where Message startswith "audit " and Message has "\\"event\\": \\"sharing_removal\\"" and Message has "\\"outcome\\": \\"failed\\""'
    window: 'PT1H'
  }
]

resource alertRules 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = [for a in alerts: if (!empty(alertEmail)) {
  name: 'alert-${a.name}-${suffix}'
  location: location
  properties: {
    displayName: 'ShareGuard: ${a.description}'
    description: a.description
    severity: a.severity
    enabled: true
    scopes: [ logs.id ]
    evaluationFrequency: 'PT5M'
    windowSize: a.window
    criteria: {
      allOf: [ {
        query: a.query
        timeAggregation: 'Count'
        operator: 'GreaterThan'
        threshold: 0
        failingPeriods: { numberOfEvaluationPeriods: 1, minFailingPeriodsToAlert: 1 }
      } ]
    }
    actions: { actionGroups: [ actionGroup.id ] }
  }
}]

// ------------------------------------------------------------------ outputs
output guardAppName string = guardApp.outputs.name
output signerAppName string = signerApp.outputs.name
output guardPrincipalId string = guardId.properties.principalId
output guardClientId string = guardId.properties.clientId
output signerPrincipalId string = signerId.properties.principalId
output signerClientId string = signerId.properties.clientId
output keyVaultName string = vault.name
output natPublicIp string = natIp.properties.ipAddress
output names object = names
output sharePointNames object = sp
