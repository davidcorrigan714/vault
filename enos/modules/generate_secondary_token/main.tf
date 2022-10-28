terraform {
  required_providers {
    enos = {
      source = "app.terraform.io/hashicorp-qti/enos"
    }
  }
}

variable "vault_install_dir" {
  type        = string
  description = "The directory where the Vault binary will be installed"
}

variable "primary_leader_public_ip" {
  type        = string
  description = "Vault primary cluster leader Public IP address"
}

variable "vault_root_token" {
  type        = string
  description = "The vault root token"
}

resource "enos_remote_exec" "fetch_secondary_token" {
  environment = {
    VAULT_ADDR        = "http://127.0.0.1:8200"
    VAULT_TOKEN       = var.vault_root_token
    vault_install_dir = var.vault_install_dir
  }

  scripts = ["${path.module}/scripts/fetch_secondary_token.sh"]

  transport = {
    ssh = {
      host = var.primary_leader_public_ip
    }
  }
}

output "secondary_token" {
  value = enos_remote_exec.fetch_secondary_token.stdout
}
