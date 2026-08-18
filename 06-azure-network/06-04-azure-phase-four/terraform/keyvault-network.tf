# Reference the existing Key Vault and hub VNet subnet
data "azurerm_key_vault" "lab" {
  name                = "kv-lab-portfolio"
  resource_group_name = var.resource_group_name
}

data "azurerm_subnet" "hub_mgmt" {
  name                 = "snet-hub-mgmt"
  resource_group_name  = var.resource_group_name
  virtual_network_name = "vnet-hub"
}

data "azurerm_virtual_network" "hub" {
  name                = "vnet-hub"
  resource_group_name = var.resource_group_name
}

data "azurerm_virtual_network" "spoke_it" {
  name                = "vnet-spoke-it"
  resource_group_name = var.resource_group_name
}

# Private DNS zone for Key Vault private link resolution
resource "azurerm_private_dns_zone" "keyvault" {
  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

# Link 1 — hub VNet, where the private endpoint physically lives
resource "azurerm_private_dns_zone_virtual_network_link" "keyvault_hub" {
  name                  = "3s2ocbybsci5e"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.keyvault.name
  virtual_network_id    = data.azurerm_virtual_network.hub.id
  registration_enabled  = false
  tags                  = var.tags
}

# Link 2 — spoke-it VNet, where vm-it-01 lives and needs to resolve the private IP
# Critical lesson: DNS zone links do NOT follow VNet peering. Each VNet that
# needs to resolve a private DNS zone requires its own explicit link, even if
# it is already peered with a VNet that has the link.
resource "azurerm_private_dns_zone_virtual_network_link" "keyvault_spoke_it" {
  name                  = "link-spoke-it"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.keyvault.name
  virtual_network_id    = data.azurerm_virtual_network.spoke_it.id
  registration_enabled  = false
  tags                  = var.tags
}

# Private endpoint for Key Vault — gives it a private IP inside the hub subnet
resource "azurerm_private_endpoint" "keyvault" {
  name                           = "pe-keyvault"
  location                       = var.location
  resource_group_name            = var.resource_group_name
  subnet_id                      = data.azurerm_subnet.hub_mgmt.id
  custom_network_interface_name  = "pe-keyvault-nic"
  tags                           = var.tags

  private_service_connection {
    name                           = "pe-keyvault"
    private_connection_resource_id = data.azurerm_key_vault.lab.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "default"
    private_dns_zone_ids = [azurerm_private_dns_zone.keyvault.id]
  }
}