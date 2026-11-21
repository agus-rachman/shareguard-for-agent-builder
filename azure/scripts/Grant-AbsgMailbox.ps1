# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
<#
.SYNOPSIS
    Lets the guard's managed identity send mail from one shared mailbox only
    (Exchange Online RBAC for Applications), creating the mailbox if needed.

.DESCRIPTION
    Don't grant Mail.Send in Entra ID: that allows sending as any mailbox. This script:
      1. creates the shared mailbox (if missing) and its display name;
      2. registers the managed identity as an Exchange service principal;
      3. creates a management scope matching only that mailbox;
      4. assigns the "Application Mail.Send" role with that scope;
      5. checks the result with Test-ServicePrincipalAuthorization.

.PARAMETER GuardClientId
    Client (application) id of id-absg-guard-<env> (Bicep output guardClientId).

.PARAMETER GuardPrincipalId
    Object id of its service principal (Bicep output guardPrincipalId).

.EXAMPLE
    ./Grant-AbsgMailbox.ps1 -ParametersFile ~/absg/main.parameters.prod.json -GuardClientId <guid> -GuardPrincipalId <guid>
    (mailbox from mailSender; display name and scope name from naming.mailboxDisplayName and naming.mailboxScope)
.EXAMPLE
    ./Grant-AbsgMailbox.ps1 -Mailbox shareguard@contoso.com -GuardClientId <guid> -GuardPrincipalId <guid>
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ParametersFile,
    [string]$Mailbox,
    [Parameter(Mandatory)][string]$GuardClientId,
    [Parameter(Mandatory)][string]$GuardPrincipalId,
    [string]$DisplayName,
    [string]$ScopeName
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
#Requires -Modules ExchangeOnlineManagement

. "$PSScriptRoot/AbsgSettings.ps1"
$settings = Get-AbsgSettings -ParametersFile $ParametersFile
$Mailbox = Select-AbsgValue $Mailbox $settings.Parameters.mailSender
$DisplayName = Select-AbsgValue $DisplayName $settings.Names.mailboxDisplayName
$ScopeName = Select-AbsgValue $ScopeName $settings.Names.mailboxScope
if (-not $Mailbox) { throw 'Give -Mailbox or set mailSender in the parameters file.' }
Connect-ExchangeOnline -ShowBanner:$false
if (-not (Get-Mailbox -Identity $Mailbox -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess($Mailbox, 'Create shared mailbox')) {
        New-Mailbox -Shared -Name $DisplayName -DisplayName $DisplayName -PrimarySmtpAddress $Mailbox | Out-Null
    }
}
if (-not (Get-ServicePrincipal -Identity $GuardClientId -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess($GuardClientId, 'Register service principal in Exchange Online')) {
        New-ServicePrincipal -AppId $GuardClientId -ObjectId $GuardPrincipalId -DisplayName $settings.Names.exchangeServicePrincipal | Out-Null
    }
}
if (-not (Get-ManagementScope -Identity $ScopeName -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess($ScopeName, 'Create management scope')) {
        New-ManagementScope -Name $ScopeName -RecipientRestrictionFilter "PrimarySmtpAddress -eq '$Mailbox'" | Out-Null
    }
}
$assignment = Get-ManagementRoleAssignment -RoleAssignee $GuardClientId -Role 'Application Mail.Send' -ErrorAction SilentlyContinue
if (-not $assignment -and $PSCmdlet.ShouldProcess($GuardClientId, 'Assign Application Mail.Send (scoped)')) {
    New-ManagementRoleAssignment -App $GuardClientId -Role 'Application Mail.Send' -CustomResourceScope $ScopeName | Out-Null
}
Test-ServicePrincipalAuthorization -Identity $GuardClientId -Resource $Mailbox | Format-Table
Write-Host "Done. Changes can take up to an hour to apply. Block sign-in to the shared mailbox's account in Entra ID."
