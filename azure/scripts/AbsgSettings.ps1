# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
#
# Shared by the provisioning scripts: reads the same parameters file as the Bicep
# deployment (main.parameters.<env>.json), so names are customised in one place.
# The defaults here must match those in azure/infra/main.bicep.
#
#   . "$PSScriptRoot/AbsgSettings.ps1"
#   $s = Get-AbsgSettings -ParametersFile ~/absg/main.parameters.prod.json
#   $s.Names.guardIdentity ; $s.SharePoint.auditLibrary ; $s.Parameters.mailSender

function Get-AbsgSettings {
    param([string]$ParametersFile)
    $p = @{}
    if ($ParametersFile) {
        if (-not (Test-Path $ParametersFile)) { throw "Parameters file not found: $ParametersFile" }
        $json = Get-Content $ParametersFile -Raw | ConvertFrom-Json -AsHashtable
        foreach ($k in $json.parameters.Keys) { $p[$k] = $json.parameters[$k].value }
    }
    $envName = if ($p.env) { $p.env } else { 'prod' }
    $override = if ($p.naming) { $p.naming } else { @{} }
    $w = if ($override.workload) { $override.workload.ToLower() } else { 'absg' }

    $names = [ordered]@{
        workload                 = $w
        env                      = $envName
        guardIdentity            = "id-$w-guard-$envName"
        signerIdentity           = "id-$w-signer-$envName"
        guardApp                 = "func-$w-guard-$envName"
        signerApp                = "func-$w-signer-$envName"
        # Entra ID and Exchange Online objects created by the scripts
        delegatedClientApp       = 'ShareGuard for Agent Builder - sharing removal'
        exchangeServicePrincipal = "$w guard ($envName)"
        mailboxScope             = "$w sender mailbox ($envName)"
        mailboxDisplayName       = 'ShareGuard for Agent Builder'
        reviewersGroup           = 'ABSG - Governance Reviewers'
        operatorsGroup           = 'ABSG - Operators'
    }
    foreach ($k in $override.Keys) { $names[$k] = $override[$k] }

    $sp = [ordered]@{
        stateLibrary         = 'ABSG State'
        auditLibrary         = 'ABSG Audit'
        acknowledgementsList = 'Agent Acknowledgements'
        registryList         = 'Approved Agents'
        requestsList         = 'Agent Sharing Requests'
        signerAuditLibrary   = 'ABSG Signer Audit'
        archiveLibrary       = 'Retired Agents'
        templatesFolder      = ''
    }
    if ($p.sharePointNames) { foreach ($k in $p.sharePointNames.Keys) { $sp[$k] = $p.sharePointNames[$k] } }

    [pscustomobject]@{ Parameters = $p; Names = $names; SharePoint = $sp }
}

# First non-empty value: an explicit script parameter, then the parameters file.
function Select-AbsgValue { foreach ($v in $args) { if ($v) { return $v } } return $null }

# A managed identity's service principal, by its resource name.
function Resolve-AbsgIdentity([string]$DisplayName) {
    $spn = Get-MgServicePrincipal -Filter "displayName eq '$DisplayName' and servicePrincipalType eq 'ManagedIdentity'" |
        Select-Object -First 1
    if (-not $spn) { throw "Managed identity '$DisplayName' not found. Deploy the Bicep template first, or pass the ids." }
    return $spn
}
