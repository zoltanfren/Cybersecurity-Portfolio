# Recovery Services Vault
# LRS chosen over GRS to minimise standing storage cost — appropriate for a lab
resource "azurerm_recovery_services_vault" "lab" {
  name                = "rsv-lab-portfolio"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "Standard"
  soft_delete_enabled = true
  storage_mode_type = "LocallyRedundant"
  tags                = var.tags
}

# Backup policy — daily backup, 7-day retention
# Short retention minimises backup storage cost while demonstrating the pattern
resource "azurerm_backup_policy_vm" "daily" {
  name                = "policy-daily-7day"
  resource_group_name = var.resource_group_name
  recovery_vault_name = azurerm_recovery_services_vault.lab.name

  backup {
    frequency = "Daily"
    time      = "23:00"
  }

  retention_daily {
    count = 7
  }
}

# Protect vm-it-01 only — demonstrates the pattern without the cost of 3 instances
data "azurerm_virtual_machine" "vm_it" {
  name                = "vm-it-01"
  resource_group_name = var.resource_group_name
}

resource "azurerm_backup_protected_vm" "vm_it" {
  resource_group_name = var.resource_group_name
  recovery_vault_name = azurerm_recovery_services_vault.lab.name
  source_vm_id        = data.azurerm_virtual_machine.vm_it.id
  backup_policy_id    = azurerm_backup_policy_vm.daily.id
}