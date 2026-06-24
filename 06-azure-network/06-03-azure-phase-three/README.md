# Azure Network Implementation Project - Phase 3

## Overview

Phase 3 introduces cloud-native services and a second IaC tool; Terraform, to complement the Bicep used in Phases 1 and 2. 

Phase 3 covers five areas:

- **3.1** Storage Account — Terraform remote state backend + blob lifecycle management
- **3.2** Azure Policy — governance and compliance enforcement
- **3.3** Recovery Services Vault — VM backup and protection
- **3.4** Microsoft Sentinel — SIEM with KQL-based detection rules
- **3.5** Terraform — project structure, remote state, import workflow

---

## 3.1 : Storage Account

A storage account `stlabterraform` serves dual purpose: it hosts the Terraform remote state backend and demonstrates blob lifecycle management.

### Terraform remote state

Terraform tracks deployed infrastructure in a state file. Storing it remotely rather than locally means state is not lost if the workstation is unavailable, and is accessible from any machine. The `tfstate` container holds `phase3.terraform.tfstate`.

The storage account access key is passed via environment variable, never hardcoded in any file:

```powershell
$env:ARM_ACCESS_KEY = "<storage-account-key>"
terraform init
```

### Blob lifecycle policy

Blobs automatically transition to the cool access tier after 30 days of inactivity and are deleted after 365 days. 

```hcl
actions {
  base_blob {
    tier_to_cool_after_days_since_modification_greater_than = 30
    delete_after_days_since_modification_greater_than       = 365
  }
}
```

### Security configuration

| Setting | Value | Rationale |
|---|---|---|
| Minimum TLS version | 1.2 | Rejects older, vulnerable TLS versions |
| Allow nested items to be public | false | No anonymous blob access |
| Cross-tenant replication | false | Prevents data replication to external tenants |
| Redundancy | LRS | Cost-appropriate for non-critical state storage |

---

## 3.2 : Azure Policy

Three audit-mode policy assignments scoped to `rg-lab-portfolio`, enforcing governance without blocking deployments.

| Policy | Effect | Built-in definition |
|---|---|---|
| Storage accounts should use HTTPS only | Audit | `404c3081-...` |
| Allowed VM SKUs | Audit | `cccc23c7-...` |
| Require environment tag | Audit | `871b6d14-...` |

### Compliance findings

On first evaluation, 39 resources showed non-compliant for the environment tag policy; all resources deployed in Phases 1 and 2 via Bicep and the portal carried no tags. 

Terraform-managed resources in Phase 3 are tagged at deployment time:

```hcl
tags = {
  environment = "lab"
  project     = "cybersecurity-portfolio"
  phase       = "3"
  managed_by  = "terraform"
}
```

Remediating the Phase 1 and 2 resources would require adding tags to the Bicep files and redeploying.

---

## 3.3 : Recovery Services Vault

VM backup configured for `vm-it-01`; the only VM running services. The jump box and NVA are stateless (no data that cannot be recreated from IaC), so backing them up would add cost without meaningful recovery value.

### Configuration

| Setting | Value | Rationale |
|---|---|---|
| Vault SKU | Standard | Supports IaaS VM backup |
| Storage redundancy | LocallyRedundant | Halves storage cost vs GeoRedundant; appropriate for a lab |
| Soft delete | Enabled | Protects against accidental backup deletion |
| Backup frequency | Daily at 23:00 UTC | Outside lab usage hours |
| Retention | 7 days | Minimum retention — minimises storage cost |

---

## 3.4 : Microsoft Sentinel

Microsoft Sentinel enabled on the existing `law-lab-portfolio` Log Analytics workspace. No additional infrastructure required; Sentinel layers directly on top of existing log ingestion.

### Detection rules

Two scheduled KQL alert rules using real ingested data:

**Rule 1 — Multiple Failed SSH Login Attempts**
- Severity: Medium
- Frequency: every 5 minutes
- Logic: 5 or more authentication failures on the same host within a 5-minute window
- Data source: Syslog `auth` facility, already ingested via Azure Monitor Agent

```kql
Syslog
| where Facility == "auth"
| where SyslogMessage contains "Failed password"
    or SyslogMessage contains "Invalid user"
| summarize FailedAttempts = count() by Computer, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
```

**Rule 2 — NVA Forwarded Traffic Spike**
- Severity: Low
- Frequency: every 5 minutes
- Logic: NVA forwards 100+ packets in a 5-minute window; potential lateral movement or scanning
- Data source: Syslog from `vm-nva-01` with `NVA-FORWARD` iptables log prefix

```kql
Syslog
| where Computer == "vm-nva-01"
| where SyslogMessage contains "NVA-FORWARD"
| summarize PacketCount = count() by bin(TimeGenerated, 5m)
| where PacketCount >= 100
```

---

## 3.5 : Terraform

### Project structure

```
06-03-azure-phase-three/
└── terraform/
    ├── providers.tf    — AzureRM provider, version constraints
    ├── backend.tf      — Remote state on Azure Storage
    ├── variables.tf    — Location, resource group, workspace ID, tags
    ├── storage.tf      — Storage account + lifecycle policy
    ├── policy.tf       — Azure Policy assignments
    ├── backup.tf       — Recovery Services Vault + backup policy + protected VM
    ├── sentinel.tf     — Sentinel onboarding + detection rules
    └── outputs.tf      — Storage account name, vault name, workspace ID
```

### Import workflow

The storage account was created via the portal before Terraform existed in this project. Rather than recreating it, it was imported into Terraform state:

```powershell
terraform import azurerm_storage_account.lab /subscriptions/.../storageAccounts/stlabterraform
```

### Remote state backend

```hcl
terraform {
  backend "azurerm" {
    resource_group_name  = "rg-lab-portfolio"
    storage_account_name = "stlabterraform"
    container_name       = "tfstate"
    key                  = "phase3.terraform.tfstate"
  }
}
```

Access key is passed via `$env:ARM_ACCESS_KEY`.

---

## Phase 4 — Planned

- NVA log-based alerting with action groups (email notifications on detection)
- Sentinel workbook for lab-wide security overview
- Azure Defender for Servers integration with Sentinel
- Tag remediation across Phase 1 and 2 resources via Bicep update
