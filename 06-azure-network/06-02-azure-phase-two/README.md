# Azure network implementation project - Phase 2

## Overview

Phase two adds the following to the project:
- 2.1 Hub-and spoke-architecture using multiple, peered VNets instead of a single one
- 2.2 A Network Virtual Appliance (NVA) for spoke-to-spoke traffic inspection
- 2.3 Private DNS
- 2.4 Azure Key Vault for secret management
- 2.5 Cloud services using a containerised application that retrieves secrets from the Key Vault at runtime

The entire infrastructure was redeployed from the updated `main.bicep`, demonstrating IaC working as intended when architectural changes require a full rebuild.

## 2.1 : New Architecture

```
Hub VNet (10.0.0.0/24) — shared management and routing
├── snet-hub-mgmt  (10.0.0.0/27)  — vm-jumpbox-01 (public IP)
├── GatewaySubnet  (10.0.0.32/27) — reserved for future VPN Gateway
└── snet-hub-nva   (10.0.0.64/27) — vm-nva-01 (NVA, static IP 10.0.0.68)

Spoke 1 VNet (10.1.0.0/24) — corporate workstations (simulated)
├── snet-exec      (10.1.0.0/27)
├── snet-prod      (10.1.0.32/27)
├── snet-support1  (10.1.0.64/27)
├── snet-support2  (10.1.0.96/27)
└── snet-study     (10.1.0.128/27)

Spoke 2 VNet (10.2.0.0/24) — IT operations
├── snet-it        (10.2.0.0/27)  — vm-it-01 (no public IP)
└── snet-internal  (10.2.0.32/28) — internal servers (simulated)

Spoke 3 VNet (10.3.0.0/24) — DMZ / perimeter (simulated)
└── snet-dmz       (10.3.0.0/28)
```

VNet peering: hub ↔ spoke 1, hub ↔ spoke 2, hub ↔ spoke 3.  
Spokes are not directly peered —> spoke-to-spoke traffic routes through the hub NVA.

### 2.1.1 : What Changed from Phase 1

| Component | Phase 1 | Phase 2 |
|---|---|---|
| Architecture | Single VNet, 8 subnets | Hub + 3 spoke VNets + NVA |
| Jump box location | snet-dmz | Hub (snet-hub-mgmt) |
| DMZ role | Jump box + perimeter | Perimeter only (simulated) |
| Corporate subnets | snet-mgmt | snet-exec (renamed for clarity) |
| NSGs | 8 individual NSGs | 5 NSGs + nsg-hub-nva |
| Spoke-to-spoke routing | No route | Via NVA (UDRs) |

## 2.2 : NVA Configuration

The NVA is a Linux VM (Ubuntu 24.04) with IP forwarding enabled at both the Azure NIC level and the OS kernel level.

**Azure level** — `enableIPForwarding: true` on `nic-nva-01` allows Azure to pass forwarded packets to the NIC rather than dropping them.

**OS level** — kernel IP forwarding enabled and persisted:

```bash
sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sudo sysctl -p
```

**Packet logging** — all forwarded packets are logged via iptables:

```bash
sudo iptables -A FORWARD -j LOG --log-prefix "NVA-FORWARD: " --log-level 4
```

Rules are persisted across reboots via a custom systemd service (`iptables-restore.service`) since `netfilter-persistent` is not available in the default Ubuntu 24.04 package repositories without internet access.

**Selective routing policy** — `nsg-hub-nva` enforces which protocols are permitted between spokes:

| Direction | Protocol | Port | Purpose |
|---|---|---|---|
| IT → Corporate | TCP | 22 | IT admins managing workstations |
| Corporate → IT | TCP | 80, 443 | Workstations accessing IT services |
| Both | ICMP | * | Monitoring and troubleshooting |

### 2.2.1 : User Defined Routes

Two route tables redirect spoke-to-spoke traffic through the NVA:

| Route table | Associated to | Route | Next hop |
|---|---|---|---|
| rt-spoke-it | snet-it | 10.1.0.0/24 | 10.0.0.68 (NVA) |
| rt-spoke-corporate | All corporate subnets | 10.2.0.0/24 | 10.0.0.68 (NVA) |

### 2.2.2 : Known Issue: NSG Statefulness with UDRs

When a UDR is attached to a subnet, Azure's NSG connection tracking can break for return traffic. This means stateful TCP return traffic is not automatically allowed and explicit outbound rules are required.

In this lab this manifested as SSH connections establishing at the TCP level but hanging during the SSH banner exchange. The fix was adding explicit outbound rules on `nsg-it` and inbound rules on `nsg-hub-mgmt` to allow return traffic between the hub and IT spoke.

## 2.3 : Private DNS (lab.internal)

A private DNS zone `lab.internal` linked to all four VNets, replacing IP-based addressing with hostnames across the lab network.

### 2.3.1 : Architecture

| VNet link | Auto-registration | Purpose |
|---|---|---|
| `link-hub` | ✅ Enabled | Jump box and NVA register automatically |
| `link-spoke-it` | ✅ Enabled | vm-it-01 registers automatically |
| `link-spoke-corporate` | ❌ Disabled | No VMs, resolution only |
| `link-spoke-dmz` | ❌ Disabled | No VMs, resolution only |

### 2.3.2 : Registered hostnames

| Hostname | Resolves to |
|---|---|
| `vm-jumpbox-01.lab.internal` | 10.0.0.4 |
| `vm-nva-01.lab.internal` | 10.0.0.68 |
| `vm-it-01.lab.internal` | 10.2.0.4 |

## 2.4 : Key Vault

Azure Key Vault `kv-lab-portfolio` using the RBAC permission model. 
A simulated database connection string is stored as a secret and retrieved by VMs and containers using their managed identities.

### 2.4.1 : Access model

| Principal | Role | Scope |
|---|---|---|
| Admin account | Key Vault Secrets Officer | Can create/update/delete secrets |
| `vm-it-01` (system-assigned identity) | Key Vault Secrets User | Can read secrets |
| `mi-lab-app` (user-assigned identity) | Key Vault Secrets User | Can read secrets |

## 2.5 : Containerised Application (ACI)

An Azure Container Instance `aci-lab-app` running a Python HTTP server that authenticates to Key Vault using a user-assigned managed identity and retrieves a secret at startup. 
The page confirms successful retrieval without exposing the secret value.

### 2.5.1 : Architecture

```
Browser / curl
    ↓ HTTP :80
aci-lab-app (Public IP, mcr.microsoft.com/azure-cli)
    ↓ az login --identity --client-id
Azure AD → token scoped to vault.azure.net
    ↓ az keyvault secret show
kv-lab-portfolio → secret value
    ↓
python3 -m http.server (serves confirmation page)
```

### 2.5.2 : Deployment

Deployed from `aci-lab-app.yaml` rather than inline CLI flags — avoids shell quoting issues with complex startup commands and produces a reusable, version-controlled artifact:

```powershell
az container create --resource-group rg-lab-portfolio --file aci-lab-app.yaml
```

### 2.5.3 : Startup sequence (inside the container)

```bash
mkdir -p /web
az login --identity --client-id $MI_CLIENT_ID
SECRET=$(az keyvault secret show --vault-name $VAULT_NAME --name $SECRET_NAME --query value -o tsv)
LEN=$(printf %s "$SECRET" | wc -c)
echo "<html>...<p>Secret retrieved. Length: $LEN chars.</p>...</html>" > /web/index.html
cd /web && python3 -m http.server 80
```

### 2.5.4 : Design tradeoffs

| Decision | Lab choice | Production equivalent |
|---|---|---|
| Network | Public IP | ACI in DMZ spoke behind Application Gateway (HTTPS) |
| Protocol | HTTP | HTTPS with TLS termination at Application Gateway |
| Image registry | MCR (public) | Azure Container Registry (private) |
| Outbound connectivity | Direct internet | NAT Gateway (required for VNet-integrated ACI) |

## Phase 3 — Planned

- Microsoft Sentinel with KQL detection rules (leveraging existing Log Analytics workspace)
- Azure Policy assignments for governance and compliance
- NVA log-based alerting in Log Analytics
- Azure Backup; Recovery Services Vault
- Storage Account; blob storage, lifecycle policies & access tiers
