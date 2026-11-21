// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The ShareGuard for Agent Builder Authors
// One Flex Consumption Function app (Python 3.11) running as a user-assigned identity.

param name string
param location string
param planId string
param subnetId string
param identityId string
param identityClientId string
param storageName string
param deploymentContainerUrl string
param appInsightsConnectionString string
param appSettings array
param deploymentIpRanges array

resource site 'Microsoft.Web/sites@2024-04-01' = {
  name: name
  location: location
  kind: 'functionapp,linux'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${identityId}': {} }
  }
  properties: {
    serverFarmId: planId
    httpsOnly: true
    virtualNetworkSubnetId: subnetId
    keyVaultReferenceIdentity: identityId
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: deploymentContainerUrl
          authentication: { type: 'UserAssignedIdentity', userAssignedIdentityResourceId: identityId }
        }
      }
      scaleAndConcurrency: { maximumInstanceCount: 40, instanceMemoryMB: 2048 }
      runtime: { name: 'python', version: '3.11' }
    }
    siteConfig: {
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      // No HTTP triggers: inbound is only for code deployment, from the listed ranges.
      ipSecurityRestrictionsDefaultAction: 'Deny'
      ipSecurityRestrictions: [for (ip, i) in deploymentIpRanges: {
        name: 'deploy-${i}'
        ipAddress: ip
        action: 'Allow'
        priority: 100 + i
      }]
      scmIpSecurityRestrictionsUseMain: true
      appSettings: concat([
        { name: 'AzureWebJobsStorage__accountName', value: storageName }
        { name: 'AzureWebJobsStorage__credential', value: 'managedidentity' }
        { name: 'AzureWebJobsStorage__clientId', value: identityClientId }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: appInsightsConnectionString }
        { name: 'APPLICATIONINSIGHTS_AUTHENTICATION_STRING', value: 'ClientId=${identityClientId};Authorization=AAD' }
      ], appSettings)
    }
  }
}

output name string = site.name
