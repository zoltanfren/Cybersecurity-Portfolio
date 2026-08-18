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

variable "tags" {
  description = "Tags applied to all Terraform-managed resources"
  type        = map(string)
  default = {
    environment = "lab"
    project     = "cybersecurity-portfolio"
    phase       = "4"
    managed_by  = "terraform"
  }
}