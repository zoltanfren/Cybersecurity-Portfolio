terraform {
  backend "azurerm" {
    resource_group_name  = "rg-lab-portfolio"
    storage_account_name = "stlabterraform"
    container_name       = "tfstate"
    key                  = "phase3.terraform.tfstate"
  }
}