// =============================================================
// Azure Cloud Security Lab — Phase 2b: Hub and Spoke + NVA
// Author: Zoltan Kamkar
// Description: Hub and spoke architecture with VNet peering.
//              Hub contains shared management access (jump box)
//              and a dedicated NVA for spoke-to-spoke inspection.
//              Three spokes: corporate workstations, IT + internal
//              servers, and DMZ. NSGs enforce Zero Trust segmentation.
//              UDRs force spoke-to-spoke traffic through the NVA.
// =============================================================

@description('Azure region for all resources')
param location string = 'westeurope'

@description('Admin username for VMs')
param adminUsername string = 'labadmin'

@description('SSH public key for VM authentication')
@secure()
param sshPublicKey string

@description('Your current public IP for jump box access — update when IP changes')
param allowedSourceIP string

@description('VM size (must be available in your region)')
param vmSize string = 'Standard_B2ats_v2'

// =============================================================
// NSGs
// Design: default deny, explicit allow (Zero Trust)
// Deny rules at 4000-4096 override Azure implicit AllowVnetInBound
// and AllowVnetOutBound defaults at 65000.
// =============================================================

// Hub management NSG
// Inbound:  SSH from operator IP only
// Outbound: SSH to IT subnet and internal servers, HTTPS to Azure endpoints
resource nsgHubMgmt 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: 'nsg-hub-mgmt'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-ssh-from-operator'
        properties: {
          priority: 100
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
        // Explicit allow for return traffic from IT and internal spoke.
        // Required because UDRs on spoke subnets interfere with NSG
        // connection tracking, preventing stateful return traffic.
        name: 'allow-return-from-it'
        properties: {
          priority: 200
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: '10.2.0.0/24'
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
        name: 'allow-ssh-to-it'
        properties: {
          priority: 100
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '10.2.0.0/27'
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
          destinationAddressPrefix: '10.2.0.32/28'
          destinationPortRange: '22'
        }
      }
      {
        name: 'allow-ssh-to-nva'
        properties: {
          priority: 300
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '10.0.0.64/27'
          destinationPortRange: '22'
        }
      }
      {
        // Allow HTTPS to Azure platform endpoints only (Monitor/AMA, updates).
        // Scoped to the AzureCloud service tag rather than open internet.
        name: 'allow-https-azure'
        properties: {
          priority: 400
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'AzureCloud'
          destinationPortRange: '443'
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

// NVA NSG — selective spoke-to-spoke rules
// Inbound:  SSH from hub-mgmt (management), SSH from IT spoke and
//           HTTP/HTTPS from corporate spoke (forwarded transit traffic)
// Outbound: SSH to corporate spoke, HTTP/HTTPS to IT spoke, ICMP both ways
// The NVA enforces which protocols are permitted between spokes.
resource nsgHubNva 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: 'nsg-hub-nva'
  location: location
  properties: {
    securityRules: [
      {
        // Management: jump box SSH into NVA for configuration
        name: 'allow-ssh-from-hub-mgmt'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '10.0.0.0/27'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
      {
        // Transit: IT admins SSH-ing to corporate workstations via NVA
        name: 'allow-ssh-from-it-spoke'
        properties: {
          priority: 200
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '10.2.0.0/24'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
      {
        // Transit: corporate workstations accessing IT-hosted services via NVA
        name: 'allow-http-https-from-corporate-spoke'
        properties: {
          priority: 300
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '10.1.0.0/24'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRanges: [ '80', '443' ]
        }
      }
      {
        // ICMP for troubleshooting and monitoring across spokes
        name: 'allow-icmp-from-spokes'
        properties: {
          priority: 400
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Icmp'
          sourceAddressPrefix: 'VirtualNetwork'
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
        // Forward SSH to corporate spoke (IT admins managing workstations)
        name: 'allow-ssh-to-corporate-spoke'
        properties: {
          priority: 100
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '10.1.0.0/24'
          destinationPortRange: '22'
        }
      }
      {
        // Forward HTTP/HTTPS to IT spoke (corporate workstations accessing IT services)
        name: 'allow-http-https-to-it-spoke'
        properties: {
          priority: 200
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '10.2.0.0/24'
          destinationPortRanges: [ '80', '443' ]
        }
      }
      {
        // ICMP outbound for monitoring
        name: 'allow-icmp-to-spokes'
        properties: {
          priority: 300
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Icmp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '*'
        }
      }
      {
        // Allow HTTPS to Azure platform endpoints only (Monitor/AMA).
        // Scoped to AzureCloud service tag — NVA does not need open internet.
        name: 'allow-https-azure'
        properties: {
          priority: 400
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'AzureCloud'
          destinationPortRange: '443'
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
// Inbound:  SSH from hub management subnet only
// Outbound: All traffic to internal servers, HTTP/HTTPS to internet for updates
resource nsgIt 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: 'nsg-it'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-ssh-from-hub'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '10.0.0.0/27'
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
        // Explicit allow for return traffic to hub.
        // Required because UDRs on this subnet interfere with NSG
        // connection tracking, preventing stateful return traffic.
        name: 'allow-return-to-hub'
        properties: {
          priority: 100
          direction: 'Outbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '10.0.0.0/24'
          destinationPortRange: '*'
        }
      }
      {
        name: 'allow-to-internal'
        properties: {
          priority: 150
          direction: 'Outbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '10.2.0.32/28'
          destinationPortRange: '*'
        }
      }
      {
        // Route to corporate spoke goes via NVA (UDR handles redirect)
        // This rule allows the outbound initiation toward corporate
        name: 'allow-ssh-to-corporate-via-nva'
        properties: {
          priority: 200
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '10.1.0.0/24'
          destinationPortRange: '22'
        }
      }
      {
        name: 'allow-http-https-internet'
        properties: {
          priority: 300
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
// Inbound:  SSH from hub management subnet, all traffic from IT subnet
// Outbound: Nothing — servers never initiate connections
resource nsgInternal 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: 'nsg-internal'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-ssh-from-hub'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '10.0.0.0/27'
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
          sourceAddressPrefix: '10.2.0.0/27'
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

// DMZ NSG
// Inbound:  Nothing — no public services yet (simulated)
// Outbound: Nothing — DMZ is isolated until public services are added
resource nsgDmz 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: 'nsg-dmz'
  location: location
  properties: {
    securityRules: [
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

// Corporate workstation subnets NSG (exec, prod, support1, support2, study)
// Inbound:  No VNet traffic
// Outbound: HTTP/HTTPS to internet, SSH/HTTP/HTTPS to IT spoke via NVA
resource nsgCorporate 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: 'nsg-corporate'
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
        // Route to IT spoke goes via NVA (UDR handles redirect)
        name: 'allow-http-https-to-it-via-nva'
        properties: {
          priority: 200
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '10.2.0.0/24'
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
// Hub VNet (10.0.0.0/24)
// Contains: jump box subnet, NVA subnet, GatewaySubnet (reserved)
// =============================================================

resource vnetHub 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name: 'vnet-hub'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [ '10.0.0.0/24' ]
    }
    subnets: [
      {
        name: 'snet-hub-mgmt'
        properties: {
          addressPrefix: '10.0.0.0/27'
          networkSecurityGroup: { id: nsgHubMgmt.id }
        }
      }
      {
        // Reserved for future VPN Gateway — cannot have an NSG
        name: 'GatewaySubnet'
        properties: {
          addressPrefix: '10.0.0.32/27'
        }
      }
      {
        // Dedicated NVA subnet — isolated from jump box for separation of duties
        name: 'snet-hub-nva'
        properties: {
          addressPrefix: '10.0.0.64/27'
          networkSecurityGroup: { id: nsgHubNva.id }
          routeTable: { id: rtNva.id }
        }
      }
    ]
  }
}

// =============================================================
// Spoke 1 VNet (10.1.0.0/24) — Corporate workstations
// All subnets simulated — no VMs deployed
// =============================================================

resource vnetSpoke1 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name: 'vnet-spoke-corporate'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [ '10.1.0.0/24' ]
    }
    subnets: [
      {
        name: 'snet-exec'
        properties: {
          addressPrefix: '10.1.0.0/27'
          networkSecurityGroup: { id: nsgCorporate.id }
          routeTable: { id: rtSpokeCorporate.id }
        }
      }
      {
        name: 'snet-prod'
        properties: {
          addressPrefix: '10.1.0.32/27'
          networkSecurityGroup: { id: nsgCorporate.id }
          routeTable: { id: rtSpokeCorporate.id }
        }
      }
      {
        name: 'snet-support1'
        properties: {
          addressPrefix: '10.1.0.64/27'
          networkSecurityGroup: { id: nsgCorporate.id }
          routeTable: { id: rtSpokeCorporate.id }
        }
      }
      {
        name: 'snet-support2'
        properties: {
          addressPrefix: '10.1.0.96/27'
          networkSecurityGroup: { id: nsgCorporate.id }
          routeTable: { id: rtSpokeCorporate.id }
        }
      }
      {
        name: 'snet-study'
        properties: {
          addressPrefix: '10.1.0.128/27'
          networkSecurityGroup: { id: nsgCorporate.id }
          routeTable: { id: rtSpokeCorporate.id }
        }
      }
    ]
  }
}

// =============================================================
// Spoke 2 VNet (10.2.0.0/24) — IT + Internal servers
// IT admins and internal servers in the same spoke — avoids
// spoke-to-spoke routing which would bypass the NVA.
// Segmentation enforced at subnet level via NSGs.
// =============================================================

resource vnetSpoke2 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name: 'vnet-spoke-it'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [ '10.2.0.0/24' ]
    }
    subnets: [
      {
        name: 'snet-it'
        properties: {
          addressPrefix: '10.2.0.0/27'
          networkSecurityGroup: { id: nsgIt.id }
          routeTable: { id: rtSpokeIt.id }
        }
      }
      {
        name: 'snet-internal'
        properties: {
          addressPrefix: '10.2.0.32/28'
          networkSecurityGroup: { id: nsgInternal.id }
        }
      }
    ]
  }
}

// =============================================================
// Spoke 3 VNet (10.3.0.0/24) — DMZ
// Public-facing perimeter — simulated for now, locked down.
// Will host public services in a future phase.
// =============================================================

resource vnetSpoke3 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name: 'vnet-spoke-dmz'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [ '10.3.0.0/24' ]
    }
    subnets: [
      {
        name: 'snet-dmz'
        properties: {
          addressPrefix: '10.3.0.0/28'
          networkSecurityGroup: { id: nsgDmz.id }
        }
      }
    ]
  }
}

// =============================================================
// VNet Peerings — hub and spoke
// allowForwardedTraffic: true required so the hub NVA can
// forward traffic between spokes across peering boundaries.
// Each peering requires two resources: one on each side.
// =============================================================

// Hub → Spoke 1
resource peeringHubToSpoke1 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2023-09-01' = {
  name: 'peering-hub-to-corporate'
  parent: vnetHub
  properties: {
    remoteVirtualNetwork: { id: vnetSpoke1.id }
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
    allowGatewayTransit: false
    useRemoteGateways: false
  }
}

// Spoke 1 → Hub
resource peeringSpoke1ToHub 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2023-09-01' = {
  name: 'peering-corporate-to-hub'
  parent: vnetSpoke1
  properties: {
    remoteVirtualNetwork: { id: vnetHub.id }
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
    allowGatewayTransit: false
    useRemoteGateways: false
  }
}

// Hub → Spoke 2
resource peeringHubToSpoke2 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2023-09-01' = {
  name: 'peering-hub-to-it'
  parent: vnetHub
  properties: {
    remoteVirtualNetwork: { id: vnetSpoke2.id }
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
    allowGatewayTransit: false
    useRemoteGateways: false
  }
}

// Spoke 2 → Hub
resource peeringSpoke2ToHub 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2023-09-01' = {
  name: 'peering-it-to-hub'
  parent: vnetSpoke2
  properties: {
    remoteVirtualNetwork: { id: vnetHub.id }
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
    allowGatewayTransit: false
    useRemoteGateways: false
  }
}

// Hub → Spoke 3
resource peeringHubToSpoke3 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2023-09-01' = {
  name: 'peering-hub-to-dmz'
  parent: vnetHub
  properties: {
    remoteVirtualNetwork: { id: vnetSpoke3.id }
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
    allowGatewayTransit: false
    useRemoteGateways: false
  }
}

// Spoke 3 → Hub
resource peeringSpoke3ToHub 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2023-09-01' = {
  name: 'peering-dmz-to-hub'
  parent: vnetSpoke3
  properties: {
    remoteVirtualNetwork: { id: vnetHub.id }
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
    allowGatewayTransit: false
    useRemoteGateways: false
  }
}

// =============================================================
// Route Tables (UDRs)
// Force spoke-to-spoke traffic through the NVA (10.0.0.68)
// =============================================================

// NVA subnet route table
// Prevents routing loops — NVA itself must not route its own traffic via UDR
resource rtNva 'Microsoft.Network/routeTables@2023-09-01' = {
  name: 'rt-hub-nva'
  location: location
  properties: {
    disableBgpRoutePropagation: false
  }
}

// Corporate spoke route table
// Traffic destined for IT spoke is redirected to NVA for inspection
resource rtSpokeCorporate 'Microsoft.Network/routeTables@2023-09-01' = {
  name: 'rt-spoke-corporate'
  location: location
  properties: {
    disableBgpRoutePropagation: false
    routes: [
      {
        name: 'route-to-it-via-nva'
        properties: {
          addressPrefix: '10.2.0.0/24'
          nextHopType: 'VirtualAppliance'
          nextHopIpAddress: '10.0.0.68'
        }
      }
    ]
  }
}

// IT spoke route table
// Traffic destined for corporate spoke is redirected to NVA for inspection
resource rtSpokeIt 'Microsoft.Network/routeTables@2023-09-01' = {
  name: 'rt-spoke-it'
  location: location
  properties: {
    disableBgpRoutePropagation: false
    routes: [
      {
        name: 'route-to-corporate-via-nva'
        properties: {
          addressPrefix: '10.1.0.0/24'
          nextHopType: 'VirtualAppliance'
          nextHopIpAddress: '10.0.0.68'
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
            id: '${vnetHub.id}/subnets/snet-hub-mgmt'
          }
          publicIPAddress: { id: pipJumpbox.id }
          privateIPAllocationMethod: 'Dynamic'
        }
      }
    ]
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
            id: '${vnetSpoke2.id}/subnets/snet-it'
          }
          privateIPAllocationMethod: 'Dynamic'
        }
      }
    ]
  }
}

// NVA NIC — static private IP so UDRs always point to the right address
// enableIPForwarding: true required for Azure to pass forwarded packets to this NIC
resource nicNva 'Microsoft.Network/networkInterfaces@2023-09-01' = {
  name: 'nic-nva-01'
  location: location
  properties: {
    enableIPForwarding: true
    ipConfigurations: [
      {
        name: 'ipconfig-nva'
        properties: {
          subnet: {
            id: '${vnetHub.id}/subnets/snet-hub-nva'
          }
          privateIPAllocationMethod: 'Static'
          privateIPAddress: '10.0.0.68'
        }
      }
    ]
  }
}

// =============================================================
// Virtual Machines
// =============================================================

// Jump box — hub management subnet, public IP, SSH key auth only
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
        deleteOption: 'Delete'
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
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
        // No storageUri — uses Azure-managed storage (free, no account needed)
      }
    }
  }
}

// IT VM — spoke 2, no public IP, SSH key auth only
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
        deleteOption: 'Delete'
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
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
      }
    }
  }
}

// NVA VM — hub NVA subnet, no public IP, SSH key auth only
// After deployment: enable ip_forward in Linux OS and configure iptables logging
resource vmNva 'Microsoft.Compute/virtualMachines@2023-09-01' = {
  name: 'vm-nva-01'
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
        name: 'disk-nva-01'
        createOption: 'FromImage'
        deleteOption: 'Delete'
        managedDisk: { storageAccountType: 'Standard_LRS' }
      }
    }
    osProfile: {
      computerName: 'vm-nva-01'
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
        { id: nicNva.id }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
      }
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

resource shutdownNva 'microsoft.devtestlab/schedules@2018-09-15' = {
  name: 'shutdown-computevm-vm-nva-01'
  location: location
  properties: {
    status: 'Enabled'
    taskType: 'ComputeVmShutdownTask'
    dailyRecurrence: { time: '1900' }
    timeZoneId: 'UTC'
    targetResourceId: vmNva.id
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
output nvaPrivateIP string = nicNva.properties.ipConfigurations[0].properties.privateIPAddress
output vnetHubId string = vnetHub.id
output vnetSpoke1Id string = vnetSpoke1.id
output vnetSpoke2Id string = vnetSpoke2.id
output vnetSpoke3Id string = vnetSpoke3.id
output logAnalyticsWorkspaceId string = logAnalytics.id
