# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
<#
.SYNOPSIS
    Creates the SharePoint libraries and lists the Azure deployment of ShareGuard for
    Agent Builder uses, on existing sites, and prints their Graph site ids.

.DESCRIPTION
    Operations site (only ABSG administrators; the guard identity gets write via Sites.Selected):
      ABSG State              library: state.json (and optional owner-map.json), versioned
      ABSG Audit              library: hash-chained audit files, one per day
      Agent Acknowledgements  list: written by the Forms + Power Automate flow

    Registry site (governance; the guard reads, the signer writes):
      Approved Agents         list: signed registry entries (read-only to people)
      Agent Sharing Requests  list: intake; requesters see only their own items
      ABSG Signer Audit       library: the signer's own audit chain

    Archive site (optional, restricted; otherwise the Operations site):
      Retired Agents          library: archived configurations of retired agents

    The list and library names come from sharePointNames in -ParametersFile (defaults as
    above), and the reviewers group from naming.reviewersGroup. Change them there, not
    here, so the guard and these lists agree. Idempotent: existing lists and columns are
    left alone.

.EXAMPLE
    ./Provision-AbsgSharePoint.ps1 -ParametersFile ~/absg/main.parameters.prod.json -PnPClientId <guid> `
        -OperationsSiteUrl https://contoso.sharepoint.com/sites/absg-operations `
        -RegistrySiteUrl https://contoso.sharepoint.com/sites/absg-registry `
        -ArchiveSiteUrl https://contoso.sharepoint.com/sites/absg-archive
.EXAMPLE
    ./Provision-AbsgSharePoint.ps1 -OperationsSiteUrl https://contoso.sharepoint.com/sites/absg-operations `
        -RegistrySiteUrl https://contoso.sharepoint.com/sites/absg-registry -PnPClientId <guid> `
        -ReviewersGroup 'ABSG - Governance Reviewers'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$OperationsSiteUrl,
    [Parameter(Mandatory)][string]$RegistrySiteUrl,
    [string]$ArchiveSiteUrl,
    [Parameter(Mandatory)][string]$PnPClientId,
    [string]$ParametersFile,
    [string]$ReviewersGroup,
    [string]$FlowAccount,
    # Who may submit sharing requests (an Entra group or user). Default: the site's members group.
    [string]$RequestersGroup
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
#Requires -Modules PnP.PowerShell
. "$PSScriptRoot/AbsgSettings.ps1"
$settings = Get-AbsgSettings -ParametersFile $ParametersFile
$n = $settings.SharePoint
$ReviewersGroup = Select-AbsgValue $ReviewersGroup $settings.Names.reviewersGroup

function Add-AbsgLibrary([string]$Title, [string]$Description) {
    if (-not (Get-PnPList -Identity $Title -ErrorAction SilentlyContinue)) {
        Write-Host "  + library $Title"
        New-PnPList -Title $Title -Template DocumentLibrary -EnableVersioning -OnQuickLaunch:$false | Out-Null
        Set-PnPList -Identity $Title -Description $Description -EnableVersioning $true -MajorVersions 500 | Out-Null
    }
}

function Add-AbsgList([string]$Title, [string]$Description, [object[]]$Fields, [string[]]$Indexed = @(), [switch]$UniqueTitle) {
    if (-not (Get-PnPList -Identity $Title -ErrorAction SilentlyContinue)) {
        Write-Host "  + list $Title"
        New-PnPList -Title $Title -Template GenericList -EnableVersioning -OnQuickLaunch:$false | Out-Null
        Set-PnPList -Identity $Title -Description $Description -EnableVersioning $true -MajorVersions 500 | Out-Null
    }
    foreach ($f in $Fields) {
        if (Get-PnPField -List $Title -Identity $f.Name -ErrorAction SilentlyContinue) { continue }
        Write-Host "    + column $($f.Name)"
        switch ($f.Type) {
            'Note' {
                Add-PnPFieldFromXml -List $Title -FieldXml ("<Field Type='Note' Name='$($f.Name)' StaticName='$($f.Name)' " +
                    "DisplayName='$($f.Name)' NumLines='6' RichText='FALSE' UnlimitedLengthInDocumentLibrary='TRUE' AppendOnly='FALSE' />") | Out-Null
            }
            'Choice' {
                Add-PnPField -List $Title -DisplayName $f.Name -InternalName $f.Name -Type Choice -Choices $f.Choices -AddToDefaultView | Out-Null
                if ($f.ContainsKey('Default')) { Set-PnPField -List $Title -Identity $f.Name -Values @{ DefaultValue = $f.Default } | Out-Null }
            }
            default { Add-PnPField -List $Title -DisplayName $f.Name -InternalName $f.Name -Type $f.Type -AddToDefaultView | Out-Null }
        }
    }
    foreach ($name in @('Title') + $Indexed) {
        $field = Get-PnPField -List $Title -Identity $name
        if (-not $field.Indexed) { Set-PnPField -List $Title -Identity $name -Values @{ Indexed = $true } | Out-Null }
    }
    if ($UniqueTitle) { Set-PnPField -List $Title -Identity 'Title' -Values @{ EnforceUniqueValues = $true } | Out-Null }
}

function Get-GraphSiteId {
    $site = Get-PnPSite -Includes Id
    $web = Get-PnPWeb -Includes Id
    return "$(([Uri]$site.Url).Host),$($site.Id),$($web.Id)"
}

# --------------------------------------------------------------------------- operations site
Write-Host "Operations site: $OperationsSiteUrl"
Connect-PnPOnline -Url $OperationsSiteUrl -Interactive -ClientId $PnPClientId
Add-AbsgLibrary $n.stateLibrary 'ShareGuard for Agent Builder: guard state (state.json) and optional owner map. Written by the guard only.'
Add-AbsgLibrary $n.auditLibrary 'ShareGuard for Agent Builder: hash-chained audit trail, one file per day. Never edit.'
Add-AbsgList -Title $n.acknowledgementsList -Description 'ShareGuard for Agent Builder: owner confirmations from Microsoft Forms. Checked by the guard before use.' -Fields @(
    @{ Name = 'Token'; Type = 'Note' }, @{ Name = 'ResponderUpn'; Type = 'Text' },
    @{ Name = 'Status'; Type = 'Choice'; Default = 'New'; Choices = @('New', 'Accepted', 'Rejected', 'Closed') },
    @{ Name = 'CaseId'; Type = 'Text' }, @{ Name = 'PackageId'; Type = 'Text' }, @{ Name = 'OwnerId'; Type = 'Text' },
    @{ Name = 'TokenId'; Type = 'Text' }, @{ Name = 'Attempts'; Type = 'Number' }, @{ Name = 'StatusReason'; Type = 'Note' }) `
    -Indexed @('Status', 'CaseId', 'PackageId')
if ($FlowAccount -and $PSCmdlet.ShouldProcess($n.acknowledgementsList, "Contribute for $FlowAccount")) {
    Set-PnPList -Identity $n.acknowledgementsList -BreakRoleInheritance -CopyRoleAssignments | Out-Null
    Set-PnPListPermission -Identity $n.acknowledgementsList -User $FlowAccount -AddRole 'Contribute' | Out-Null
}
if ($n.templatesFolder) {
    $root = (Get-PnPList -Identity $n.stateLibrary -Includes RootFolder).RootFolder.ServerRelativeUrl
    $web = (Get-PnPWeb).ServerRelativeUrl.TrimEnd('/')
    Resolve-PnPFolder -SiteRelativePath ($root.Substring($web.Length).TrimStart('/') + '/' + $n.templatesFolder) | Out-Null
    Write-Host "  + folder $($n.stateLibrary)/$($n.templatesFolder) (customised email templates go here)"
}
$opsSiteId = Get-GraphSiteId

# --------------------------------------------------------------------------- registry site
Write-Host "Registry site: $RegistrySiteUrl"
Connect-PnPOnline -Url $RegistrySiteUrl -Interactive -ClientId $PnPClientId
$criteria = @('Pass', 'Fail', 'N/A')
# The criteria columns: approvalCriteria in the parameters file, or the defaults.
$criteriaColumns = if ($settings.Parameters.approvalCriteria) { @($settings.Parameters.approvalCriteria | ForEach-Object { $_.column }) }
                   else { @('KS01', 'KS02', 'DS01', 'AU01', 'AC01') }
Add-AbsgList -Title $n.registryList -UniqueTitle -Description 'ShareGuard for Agent Builder: signed registry entries. Written by the signer only; an edited entry no longer verifies and its agent is blocked.' -Fields @(
    @{ Name = 'EntryJson'; Type = 'Note' }, @{ Name = 'Status'; Type = 'Text' }, @{ Name = 'RequestId'; Type = 'Text' },
    @{ Name = 'ExpiresAt'; Type = 'Text' }, @{ Name = 'RiskRating'; Type = 'Text' }, @{ Name = 'DisplayName'; Type = 'Text' },
    @{ Name = 'Owners'; Type = 'Text' })
$requestFields = @(
    @{ Name = 'PackageId'; Type = 'Text' }, @{ Name = 'Owners'; Type = 'Text' }, @{ Name = 'AudienceGroupIds'; Type = 'Text' },
    @{ Name = 'Justification'; Type = 'Note' },
    @{ Name = 'Evidence'; Type = 'Note' },
    @{ Name = 'RiskRating'; Type = 'Choice'; Choices = @('Low', 'Medium', 'High') }, @{ Name = 'RiskScore'; Type = 'Number' },
    @{ Name = 'ExpiresAt'; Type = 'DateTime' }, @{ Name = 'Conditions'; Type = 'Note' },
    @{ Name = 'GovernanceContacts'; Type = 'Text' }, @{ Name = 'PolicyJson'; Type = 'Note' },
    @{ Name = 'Status'; Type = 'Choice'; Default = 'Submitted'; Choices = @('Submitted', 'In review', 'Approved', 'Registered',
        'Needs criteria', 'Rejected', 'Signing failed', 'Revoke requested', 'Revoked') },
    @{ Name = 'ApprovedBy'; Type = 'Text' }, @{ Name = 'ReviewerComments'; Type = 'Note' },
    @{ Name = 'SignerComments'; Type = 'Note' }, @{ Name = 'RegisteredEntryHash'; Type = 'Text' },
    @{ Name = 'RequestedBy'; Type = 'Text' }
    ) + @($criteriaColumns | ForEach-Object { @{ Name = $_; Type = 'Choice'; Choices = $criteria } })
Add-AbsgList -Title $n.requestsList -Description 'ShareGuard for Agent Builder: requests to share an Agent Builder agent.' `
    -Fields $requestFields -Indexed @('Status', 'PackageId')
Add-AbsgLibrary $n.signerAuditLibrary "ShareGuard for Agent Builder: the registry signer's hash-chained audit trail."

# Requesters may add requests and read their own, but never edit one: the signer trusts
# Status, ApprovedBy, the criteria and PolicyJson, so only reviewers and the approval flow
# may change them. (The signer also checks each request's version history when
# signerTrustedEditors is set.)
if ($PSCmdlet.ShouldProcess($n.requestsList, 'Permissions: requesters add and read their own requests, but cannot edit them')) {
    Set-PnPList -Identity $n.requestsList -ReadSecurity 2 -WriteSecurity 2 | Out-Null
    $submitRole = 'ABSG Submit'
    if (-not (Get-PnPRoleDefinition -Identity $submitRole -ErrorAction SilentlyContinue)) {
        Add-PnPRoleDefinition -RoleName $submitRole -Clone 'Read' -Include AddListItems `
            -Description 'ShareGuard for Agent Builder: create sharing requests and read your own; no edits' | Out-Null
    }
    Set-PnPList -Identity $n.requestsList -BreakRoleInheritance -CopyRoleAssignments | Out-Null
    $members = Get-PnPGroup -AssociatedMemberGroup
    foreach ($role in @('Edit', 'Contribute')) {
        Set-PnPListPermission -Identity $n.requestsList -Group $members -RemoveRole $role -ErrorAction SilentlyContinue | Out-Null
    }
    Set-PnPListPermission -Identity $n.requestsList -Group $members -AddRole $submitRole | Out-Null
    if ($RequestersGroup) {
        Set-PnPListPermission -Identity $n.requestsList -User $RequestersGroup -AddRole $submitRole | Out-Null
    }
    if ($ReviewersGroup) {
        Set-PnPListPermission -Identity $n.requestsList -Group $ReviewersGroup -AddRole 'Full Control' | Out-Null
    }
    if ($FlowAccount) {
        Set-PnPListPermission -Identity $n.requestsList -User $FlowAccount -AddRole 'Contribute' | Out-Null
    }
    Write-Warning ("Check $($n.requestsList) > List settings > Permissions: no one but reviewers, the flow " +
        "account and site owners may hold Edit, Contribute or Full Control (look for 'Everyone except external users').")
}
if ($PSCmdlet.ShouldProcess($n.registryList, 'Read-only for site members')) {
    Set-PnPList -Identity $n.registryList -BreakRoleInheritance -CopyRoleAssignments | Out-Null
    $members = Get-PnPGroup -AssociatedMemberGroup
    Set-PnPListPermission -Identity $n.registryList -Group $members -RemoveRole 'Edit' -AddRole 'Read' -ErrorAction SilentlyContinue | Out-Null
}
$regSiteId = Get-GraphSiteId

# --------------------------------------------------------------------------- archive site
$archiveSiteId = ''
if ($ArchiveSiteUrl) {
    Write-Host "Archive site: $ArchiveSiteUrl"
    Connect-PnPOnline -Url $ArchiveSiteUrl -Interactive -ClientId $PnPClientId
    $archiveSiteId = Get-GraphSiteId
} else {
    Connect-PnPOnline -Url $OperationsSiteUrl -Interactive -ClientId $PnPClientId
}
Add-AbsgLibrary $n.archiveLibrary 'ShareGuard for Agent Builder: archived configurations of retired agents, kept after they are deleted from Microsoft 365. Restricted.'

Write-Host ""
Write-Host "Bicep parameters:"
Write-Host "  operationsSiteId = $opsSiteId"
Write-Host "  registrySiteId   = $regSiteId"
if ($archiveSiteId) { Write-Host "  archiveSiteId    = $archiveSiteId" }
