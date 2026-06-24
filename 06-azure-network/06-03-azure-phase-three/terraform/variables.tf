variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "westeurope"
}

variable "resource_group_name" {
  description = "Existing resource group containing the lab infrastructure"
  type        = string
  default     = "rg-lab-portfolio"
}

variable "law_workspace_id" {
  description = "Resource ID of the existing Log Analytics workspace"
  type        = string
  default     = "/subscriptions/9f74ed1b-ba68-4724-b229-1599aa32fadb/resourceGroups/rg-lab-portfolio/providers/Microsoft.OperationalInsights/workspaces/law-lab-portfolio"
}

variable "tags" {
  description = "Tags applied to all Terraform-managed resources"
  type        = map(string)
  default = {
    environment = "lab"
    project     = "cybersecurity-portfolio"
    phase       = "3"
    managed_by  = "terraform"
  }
}