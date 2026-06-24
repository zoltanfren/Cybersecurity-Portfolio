# Data sources to reference existing scope
data "azurerm_resource_group" "lab" {
  name = var.resource_group_name
}

data "azurerm_subscription" "current" {}

# Policy 1 — Audit storage accounts not using HTTPS
resource "azurerm_resource_group_policy_assignment" "https_storage" {
  name                 = "audit-https-storage"
  resource_group_id    = data.azurerm_resource_group.lab.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9"
  description          = "Audits storage accounts that do not enforce HTTPS traffic"
  display_name         = "Audit - Storage accounts should use HTTPS only"
  enforce              = false
}

# Policy 2 — Audit allowed VM SKUs
resource "azurerm_resource_group_policy_assignment" "allowed_vm_skus" {
  name                 = "audit-allowed-vm-skus"
  resource_group_id    = data.azurerm_resource_group.lab.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/cccc23c7-8427-4f53-ad12-b6a63eb452b3"
  description          = "Audits VM deployments that use SKUs outside the approved list"
  display_name         = "Audit - Allowed VM SKUs"
  enforce              = false

  parameters = jsonencode({
    listOfAllowedSKUs = {
      value = [
        "Standard_B2ats_v2",
        "Standard_B2als_v2"
      ]
    }
  })
}

# Policy 3 — Audit resources missing environment tag
resource "azurerm_resource_group_policy_assignment" "require_env_tag" {
  name                 = "audit-require-env-tag"
  resource_group_id    = data.azurerm_resource_group.lab.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/871b6d14-10aa-478d-b590-94f262ecfa99"
  description          = "Audits resources that do not have an environment tag"
  display_name         = "Audit - Require environment tag on resources"
  enforce              = false

  parameters = jsonencode({
    tagName = {
      value = "environment"
    }
  })
}