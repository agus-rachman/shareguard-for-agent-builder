# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
<#
.SYNOPSIS
    Gives the ShareGuard managed identities access to the ABSG SharePoint sites only
    (Sites.Selected).

.DESCRIPTION
      Guard:  write on the Operations site (state, audit, acknowledgements); read on the
              Registry site (signed entries).
      Signer: write on the Registry site (Approved Agents, Agent Sharing Requests and its
              own audit library). No access to the Operations site.
      Archive site (if separate): guard write, signer nothing.

    Site ids, identity names and client ids come from -ParametersFile unless given.

    Run as an admin who can consent to Sites.FullControl.All (needed to manage site
    permissions). Use the client ids from the Bicep outputs.

.EXAMPLE
    ./Grant-AbsgSiteAccess.ps1 -ParametersFile ~/absg/main.parameters.prod.json
.EXAMPLE
    ./Grant-AbsgSiteAccess.ps1 -OperationsSiteId 'contoso.sharepoint.com,<guid>,<guid>' `
        -RegistrySiteId 'contoso.sharepoint.com,<guid>,<guid>' -GuardClientId <guid> -SignerClientId <guid>
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ParametersFile,
    [string]$OperationsSiteId,
    [string]$RegistrySiteId,
    [string]$ArchiveSiteId,
    [string]$GuardClientId,
    [string]$SignerClientId
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications

Connect-MgGraph -Scopes 'Sites.FullControl.All', 'Application.Read.All' -NoWelcome
. "$PSScriptRoot/AbsgSettings.ps1"
$settings = Get-AbsgSettings -ParametersFile $ParametersFile
$OperationsSiteId = Select-AbsgValue $OperationsSiteId $settings.Parameters.operationsSiteId
$RegistrySiteId = Select-AbsgValue $RegistrySiteId $settings.Parameters.registrySiteId
$ArchiveSiteId = Select-AbsgValue $ArchiveSiteId $settings.Parameters.archiveSiteId
if (-not $OperationsSiteId -or -not $RegistrySiteId) { throw 'Operations and Registry site ids are needed.' }
$guardName, $signerName = $settings.Names.guardIdentity, $settings.Names.signerIdentity
if (-not $GuardClientId) { $GuardClientId = (Resolve-AbsgIdentity $guardName).AppId }
if (-not $SignerClientId) { $SignerClientId = (Resolve-AbsgIdentity $signerName).AppId }

function Grant-Site([string]$SiteId, [string]$ClientId, [string]$Name, [string]$Role) {
    $current = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/$SiteId/permissions"
    $match = $current.value | Where-Object { $_.grantedToIdentitiesV2.application.id -contains $ClientId -or
                                             $_.grantedToIdentities.application.id -contains $ClientId }
    if ($match) {
        Write-Host "  = $Name already has $($match.roles -join ',') on $SiteId"
        return
    }
    if ($PSCmdlet.ShouldProcess($SiteId, "Grant $Role to $Name")) {
        $body = @{ roles = @($Role); grantedToIdentities = @(@{ application = @{ id = $ClientId; displayName = $Name } }) }
        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/sites/$SiteId/permissions" `
            -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json' | Out-Null
        Write-Host "  + $Name : $Role on $SiteId"
    }
}

Grant-Site $OperationsSiteId $GuardClientId $guardName 'write'
Grant-Site $RegistrySiteId $GuardClientId $guardName 'read'
Grant-Site $RegistrySiteId $SignerClientId $signerName 'write'
if ($ArchiveSiteId -and $ArchiveSiteId -ne $OperationsSiteId) {
    Grant-Site $ArchiveSiteId $GuardClientId $guardName 'write'
}
Write-Host "Done."
