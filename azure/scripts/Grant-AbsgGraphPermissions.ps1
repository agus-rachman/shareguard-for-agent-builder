# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
<#
.SYNOPSIS
    Grants Microsoft Graph application permissions to the ShareGuard managed identities.

.DESCRIPTION
    Managed identities can't be given API permissions in the portal, so this script
    assigns the app roles directly. Least privilege:

      Guard  (id-absg-guard-<env>):  CopilotPackages.ReadWrite.All, User.Read.All,
                                     GroupMember.Read.All, Sites.Selected
      Signer (id-absg-signer-<env>): CopilotPackages.Read.All, User.Read.All, Sites.Selected

    Sites.Selected grants nothing by itself: Grant-AbsgSiteAccess.ps1 then gives each
    identity access to the ABSG sites only. Mail.Send is granted separately and scoped
    to one mailbox with Exchange RBAC for Applications (Grant-AbsgMailbox.ps1), never
    tenant-wide in Entra ID.

    Run as a Privileged Role Administrator or Global Administrator. Use the principal
    ids from the Bicep deployment outputs, or pass -ParametersFile and the identities are
    found by their names (naming.guardIdentity / naming.signerIdentity).

.EXAMPLE
    ./Grant-AbsgGraphPermissions.ps1 -ParametersFile ~/absg/main.parameters.prod.json
.EXAMPLE
    ./Grant-AbsgGraphPermissions.ps1 -GuardPrincipalId <guid> -SignerPrincipalId <guid>
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ParametersFile,
    [string]$GuardPrincipalId,
    [string]$SignerPrincipalId,
    # Add ReadWrite for the signer only if your tenant rejects app-only reads otherwise.
    [string[]]$GuardRoles = @('CopilotPackages.ReadWrite.All', 'User.Read.All', 'GroupMember.Read.All', 'Sites.Selected'),
    [string[]]$SignerRoles = @('CopilotPackages.Read.All', 'User.Read.All', 'Sites.Selected')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
#Requires -Modules Microsoft.Graph.Applications

. "$PSScriptRoot/AbsgSettings.ps1"
$settings = Get-AbsgSettings -ParametersFile $ParametersFile
Connect-MgGraph -Scopes 'AppRoleAssignment.ReadWrite.All', 'Application.Read.All' -NoWelcome
if (-not $GuardPrincipalId) { $GuardPrincipalId = (Resolve-AbsgIdentity $settings.Names.guardIdentity).Id }
if (-not $SignerPrincipalId) { $SignerPrincipalId = (Resolve-AbsgIdentity $settings.Names.signerIdentity).Id }
$graph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

function Grant-Roles([string]$PrincipalId, [string[]]$Roles) {
    $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $PrincipalId -All
    foreach ($name in $Roles) {
        $role = $graph.AppRoles | Where-Object { $_.Value -eq $name -and $_.AllowedMemberTypes -contains 'Application' }
        if (-not $role) { throw "Application permission $name not found on Microsoft Graph in this tenant." }
        if ($existing | Where-Object { $_.AppRoleId -eq $role.Id -and $_.ResourceId -eq $graph.Id }) {
            Write-Host "  = $name"
            continue
        }
        if ($PSCmdlet.ShouldProcess($PrincipalId, "Grant $name")) {
            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $PrincipalId -PrincipalId $PrincipalId `
                -ResourceId $graph.Id -AppRoleId $role.Id | Out-Null
            Write-Host "  + $name"
        }
    }
}

Write-Host "Guard ($GuardPrincipalId)"
Grant-Roles $GuardPrincipalId $GuardRoles
Write-Host "Signer ($SignerPrincipalId)"
Grant-Roles $SignerPrincipalId $SignerRoles
Write-Host "Done. Tokens issued before this change don't carry the new roles: restart both Function apps."
