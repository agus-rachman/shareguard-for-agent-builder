# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
<#
.SYNOPSIS
    Creates the public client app the sharing-removal account signs in with, and grants
    consent for that account only.

.DESCRIPTION
    Microsoft documents the Package Management API's update operation (removing sharing)
    as delegated-only, so it runs as a dedicated cloud-only account (svc-absg@). The
    guard refreshes the account's token from a Key Vault secret; nothing else uses it.

    After running this script:
      1. absg --config local.json --login-delegated      (device code sign-in as svc-absg@)
      2. az keyvault secret set --vault-name <kv> --name delegated-token-cache --file absg_delegated_cache.json
      3. delete absg_delegated_cache.json
    Then restrict the account with Conditional Access to the NAT gateway's IP (Bicep output natPublicIp).

.EXAMPLE
    ./Register-AbsgDelegatedClient.ps1 -ParametersFile ~/absg/main.parameters.prod.json
    (account from delegatedUsername; app name from naming.delegatedClientApp)
.EXAMPLE
    ./Register-AbsgDelegatedClient.ps1 -ServiceAccount svc-absg@contoso.com
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ParametersFile,
    [string]$ServiceAccount,
    [string]$DisplayName
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
#Requires -Modules Microsoft.Graph.Applications, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users

. "$PSScriptRoot/AbsgSettings.ps1"
$settings = Get-AbsgSettings -ParametersFile $ParametersFile
$ServiceAccount = Select-AbsgValue $ServiceAccount $settings.Parameters.delegatedUsername
$DisplayName = Select-AbsgValue $DisplayName $settings.Names.delegatedClientApp
if (-not $ServiceAccount) { throw 'Give -ServiceAccount or set delegatedUsername in the parameters file.' }
$scopes = @('CopilotPackages.ReadWrite.All', 'offline_access')
Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All', 'User.Read.All' -NoWelcome
$graph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$access = foreach ($s in $scopes) {
    $p = $graph.Oauth2PermissionScopes | Where-Object Value -eq $s
    if (-not $p) { throw "Delegated permission $s not found." }
    @{ Id = $p.Id; Type = 'Scope' }
}
$app = Get-MgApplication -Filter "displayName eq '$DisplayName'" | Select-Object -First 1
if (-not $app -and $PSCmdlet.ShouldProcess($DisplayName, 'Create public client app')) {
    $app = New-MgApplication -DisplayName $DisplayName -SignInAudience AzureADMyOrg -IsFallbackPublicClient `
        -PublicClient @{ RedirectUris = @('https://login.microsoftonline.com/common/oauth2/nativeclient') } `
        -RequiredResourceAccess @(@{ ResourceAppId = $graph.AppId; ResourceAccess = $access })
}
$sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'"
if (-not $sp) { $sp = New-MgServicePrincipal -AppId $app.AppId -AppRoleAssignmentRequired }
$user = Get-MgUser -UserId $ServiceAccount
# Only the service account may sign in to this app.
if (-not (Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id | Where-Object PrincipalId -eq $user.Id)) {
    New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id -PrincipalId $user.Id -ResourceId $sp.Id `
        -AppRoleId ([Guid]::Empty) | Out-Null
}
$grant = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($sp.Id)' and principalId eq '$($user.Id)'" | Select-Object -First 1
if ($grant) { Update-MgOauth2PermissionGrant -OAuth2PermissionGrantId $grant.Id -Scope ($scopes -join ' ') }
else {
    New-MgOauth2PermissionGrant -ClientId $sp.Id -ConsentType Principal -PrincipalId $user.Id `
        -ResourceId $graph.Id -Scope ($scopes -join ' ') | Out-Null
}
Write-Host "Delegated client id: $($app.AppId)  (Bicep parameter delegatedClientId)"
Write-Host "Consent granted for $ServiceAccount only; assignment required, so no one else can use the app."
