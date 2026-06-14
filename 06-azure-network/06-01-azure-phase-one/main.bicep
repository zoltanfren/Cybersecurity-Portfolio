// =============================================================
// Azure Cloud Security Lab — Infrastructure as Code
// Author: Zoltan Frenyo
// Description: Single-VNet segmented lab based on Cisco Packet
//              Tracer topology, built for portfolio and AZ-500 prep
// =============================================================

@description('Azure region for all resources')
param location string = 'westeurope'

@description('Admin username for VMs')
param adminUsername string = 'labadmin'

@description('SSH public key for VM authentication')
@secure()
param sshPublicKey string

@description('Your current public IP for jump box access')
param allowedSourceIP string

@description('VM size (must be available in your region)')
param vmSize string = 'Standard_B2ats_v2'

// =============================================================
// Variables
// =============================================================

var vnetName = 'vnet-lab'
var vnetPrefix = '10.0.0.0/16'

// =============================================================
// NSGs — one per subnet
// Design: default deny, explicit allow (Zero Trust)
// Azure implicit defaults: AllowVnetInBound (65000), AllowVnetOutBound (65000),
// DenyAllInBound (65500). Our deny rules at 4000-4096 override the VNet allows.
// =============================================================

// DMZ NSG
// Inbound:  SSH from operator IP only
// Outbound: SSH to IT and internal subnets only — nothing else
resource nsgDmz 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: 'nsg-dmz'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-ssh-from-operator'
        properties: {
          priority: 200
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: allowedSourceIP
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
      {
        name: 'deny-vnet-inbound'
        properties: {
          priority: 4000
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'allow-ssh-to-it'
        properties: {
          priority: 100
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '10.0.60.0/27'
          destinationPortRange: '22'
        }
      }
      {
        name: 'allow-ssh-to-internal'
        properties: {
          priority: 200
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '10.0.80.0/28'
          destinationPortRange: '22'
        }
      }
      {
        name: 'deny-vnet-outbound'
        properties: {
          priority: 4000
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '*'
        }
      }
      {
        name: 'deny-internet-outbound'
        properties: {
          priority: 4096
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'Internet'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

// IT NSG
// Inbound:  SSH from jump box (snet-dmz) only
// Outbound: All traffic to internal servers, HTTP/HTTPS to internet for updates
resource nsgIt 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: 'nsg-it'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-ssh-from-dmz'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '10.0.70.0/28'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
      {
        name: 'deny-vnet-inbound'
        properties: {
          priority: 4000
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'allow-to-internal'
        properties: {
          priority: 100
          direction: 'Outbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '10.0.80.0/28'
          destinationPortRange: '*'
        }
      }
      {
        name: 'allow-http-https-internet'
        properties: {
          priority: 200
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'Internet'
          destinationPortRanges: [ '80', '443' ]
        }
      }
      {
        name: 'deny-vnet-outbound'
        properties: {
          priority: 4096
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

// Internal servers NSG
// Inbound:  SSH from jump box, all traffic from IT subnet
// Outbound: Nothing — servers never initiate connections
resource nsgInternal 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: 'nsg-internal'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-ssh-from-dmz'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '10.0.70.0/28'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
      {
        name: 'allow-from-it'
        properties: {
          priority: 200
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: '10.0.60.0/27'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'deny-vnet-inbound'
        properties: {
          priority: 4000
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'deny-vnet-outbound'
        properties: {
          priority: 4000
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '*'
        }
      }
      {
        name: 'deny-internet-outbound'
        properties: {
          priority: 4096
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'Internet'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

// Simulated workstation subnets — no VMs, rules enforce future-proof segmentation
// Inbound:  No VNet traffic (nothing to receive)
// Outbound: HTTP/HTTPS to internet only, no VNet lateral movement
resource nsgMgmt 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: 'nsg-mgmt'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-http-https-internet'
        properties: {
          priority: 100
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'Internet'
          destinationPortRanges: [ '80', '443' ]
        }
      }
      {
        name: 'deny-vnet-inbound'
        properties: {
          priority: 4000
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'deny-vnet-outbound'
        properties: {
          priority: 4096
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

resource nsgProd 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: 'nsg-prod'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-http-https-internet'
        properties: {
          priority: 100
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'Internet'
          destinationPortRanges: [ '80', '443' ]
        }
      }
      {
        name: 'deny-vnet-inbound'
        properties: {
          priority: 4000
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'deny-vnet-outbound'
        properties: {
          priority: 4096
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

resource nsgSupport1 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: 'nsg-support1'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-http-https-internet'
        properties: {
          priority: 100
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'Internet'
          destinationPortRanges: [ '80', '443' ]
        }
      }
      {
        name: 'deny-vnet-inbound'
        properties: {
          priority: 4000
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'deny-vnet-outbound'
        properties: {
          priority: 4096
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

resource nsgSupport2 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: 'nsg-support2'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-http-https-internet'
        properties: {
          priority: 100
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'Internet'
          destinationPortRanges: [ '80', '443' ]
        }
      }
      {
        name: 'deny-vnet-inbound'
        properties: {
          priority: 4000
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'deny-vnet-outbound'
        properties: {
          priority: 4096
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

resource nsgStudy 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: 'nsg-study'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-http-https-internet'
        properties: {
          priority: 100
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'Internet'
          destinationPortRanges: [ '80', '443' ]
        }
      }
      {
        name: 'deny-vnet-inbound'
        properties: {
          priority: 4000
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'deny-vnet-outbound'
        properties: {
          priority: 4096
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

// =============================================================
// Virtual Network with all 8 subnets
// =============================================================

resource vnet 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [ vnetPrefix ]
    }
    subnets: [
      {
        name: 'snet-mgmt'
        properties: {
          addressPrefix: '10.0.10.0/27'
          networkSecurityGroup: { id: nsgMgmt.id }
        }
      }
      {
        name: 'snet-prod'
        properties: {
          addressPrefix: '10.0.20.0/27'
          networkSecurityGroup: { id: nsgProd.id }
        }
      }
      {
        name: 'snet-support1'
        properties: {
          addressPrefix: '10.0.30.0/27'
          networkSecurityGroup: { id: nsgSupport1.id }
        }
      }
      {
        name: 'snet-support2'
        properties: {
          addressPrefix: '10.0.40.0/27'
          networkSecurityGroup: { id: nsgSupport2.id }
        }
      }
      {
        name: 'snet-study'
        properties: {
          addressPrefix: '10.0.50.0/27'
          networkSecurityGroup: { id: nsgStudy.id }
        }
      }
      {
        name: 'snet-it'
        properties: {
          addressPrefix: '10.0.60.0/27'
          networkSecurityGroup: { id: nsgIt.id }
        }
      }
      {
        name: 'snet-dmz'
        properties: {
          addressPrefix: '10.0.70.0/28'
          networkSecurityGroup: { id: nsgDmz.id }
        }
      }
      {
        name: 'snet-internal'
        properties: {
          addressPrefix: '10.0.80.0/28'
          networkSecurityGroup: { id: nsgInternal.id }
        }
      }
    ]
  }
}

// =============================================================
// Public IP for jump box
// =============================================================

resource pipJumpbox 'Microsoft.Network/publicIPAddresses@2023-09-01' = {
  name: 'pip-jumpbox'
  location: location
  sku: { name: 'Standard' }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

// =============================================================
// Network interfaces
// =============================================================

resource nicJumpbox 'Microsoft.Network/networkInterfaces@2023-09-01' = {
  name: 'nic-jumpbox-01'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig-jumpbox'
        properties: {
          subnet: {
            id: '${vnet.id}/subnets/snet-dmz'
          }
          publicIPAddress: { id: pipJumpbox.id }
          privateIPAllocationMethod: 'Dynamic'
        }
      }
    ]
    networkSecurityGroup: { id: nsgDmz.id }
  }
}

resource nicIt 'Microsoft.Network/networkInterfaces@2023-09-01' = {
  name: 'nic-it-01'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig-it'
        properties: {
          subnet: {
            id: '${vnet.id}/subnets/snet-it'
          }
          privateIPAllocationMethod: 'Dynamic'
        }
      }
    ]
    networkSecurityGroup: { id: nsgIt.id }
  }
}

// =============================================================
// Virtual Machines
// =============================================================

// Jump box — DMZ subnet, public IP, SSH key auth only
resource vmJumpbox 'Microsoft.Compute/virtualMachines@2023-09-01' = {
  name: 'vm-jumpbox-01'
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    hardwareProfile: { vmSize: vmSize }
    storageProfile: {
      imageReference: {
        publisher: 'canonical'
        offer: 'ubuntu-24_04-lts'
        sku: 'server'
        version: 'latest'
      }
      osDisk: {
        name: 'disk-jumpbox-01'
        createOption: 'FromImage'
        managedDisk: { storageAccountType: 'Standard_LRS' }
      }
    }
    osProfile: {
      computerName: 'vm-jumpbox-01'
      adminUsername: adminUsername
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: sshPublicKey
            }
          ]
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        { id: nicJumpbox.id }
      ]
    }
  }
}

// IT VM — snet-it, no public IP, SSH key auth only
resource vmIt 'Microsoft.Compute/virtualMachines@2023-09-01' = {
  name: 'vm-it-01'
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    hardwareProfile: { vmSize: vmSize }
    storageProfile: {
      imageReference: {
        publisher: 'canonical'
        offer: 'ubuntu-24_04-lts'
        sku: 'server'
        version: 'latest'
      }
      osDisk: {
        name: 'disk-it-01'
        createOption: 'FromImage'
        managedDisk: { storageAccountType: 'Standard_LRS' }
      }
    }
    osProfile: {
      computerName: 'vm-it-01'
      adminUsername: adminUsername
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: sshPublicKey
            }
          ]
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        { id: nicIt.id }
      ]
    }
  }
}

// =============================================================
// Auto-shutdown schedules (19:00 UTC = 21:00 Brussels summer)
// =============================================================

resource shutdownJumpbox 'microsoft.devtestlab/schedules@2018-09-15' = {
  name: 'shutdown-computevm-vm-jumpbox-01'
  location: location
  properties: {
    status: 'Enabled'
    taskType: 'ComputeVmShutdownTask'
    dailyRecurrence: { time: '1900' }
    timeZoneId: 'UTC'
    targetResourceId: vmJumpbox.id
  }
}

resource shutdownIt 'microsoft.devtestlab/schedules@2018-09-15' = {
  name: 'shutdown-computevm-vm-it-01'
  location: location
  properties: {
    status: 'Enabled'
    taskType: 'ComputeVmShutdownTask'
    dailyRecurrence: { time: '1900' }
    timeZoneId: 'UTC'
    targetResourceId: vmIt.id
  }
}

// =============================================================
// Log Analytics Workspace
// =============================================================

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'law-lab-portfolio'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
    workspaceCapping: { dailyQuotaGb: -1 }
  }
}

// =============================================================
// Outputs
// =============================================================

output jumpboxPublicIP string = pipJumpbox.properties.ipAddress
output vnetId string = vnet.id
output logAnalyticsWorkspaceId string = logAnalytics.id
