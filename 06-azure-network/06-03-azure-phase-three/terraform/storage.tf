# Storage account — serves dual purpose:
# 1. Terraform remote state backend for Phase 3
# 2. Portfolio demonstration of blob storage, lifecycle policies, and access tiers

resource "azurerm_storage_account" "lab" {
  name                     = "stlabterraform"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
  
  # Keep portal security defaults explicit in code
  allow_nested_items_to_be_public  = false
  cross_tenant_replication_enabled = false
  tags                             = var.tags

  blob_properties {
    # Soft delete gives a recovery window if blobs are accidentally deleted
    delete_retention_policy {
      days = 7
    }
  }
}

# Lifecycle policy — moves blobs to cool tier after 30 days, deletes after 365
# Demonstrates cost optimization through automated tiering
resource "azurerm_storage_management_policy" "lab" {
  storage_account_id = azurerm_storage_account.lab.id

  rule {
    name    = "lifecycle-policy"
    enabled = true

    filters {
      blob_types = ["blockBlob"]
    }

    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than    = 30
        delete_after_days_since_modification_greater_than          = 365
      }
    }
  }
}