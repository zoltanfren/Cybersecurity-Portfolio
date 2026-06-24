output "storage_account_name" {
  description = "Name of the Terraform state and lab storage account"
  value       = azurerm_storage_account.lab.name
}

output "recovery_vault_name" {
  description = "Name of the Recovery Services Vault"
  value       = azurerm_recovery_services_vault.lab.name
}

output "sentinel_workspace_id" {
  description = "Log Analytics workspace ID where Sentinel is enabled"
  value       = azurerm_sentinel_log_analytics_workspace_onboarding.lab.workspace_id
}