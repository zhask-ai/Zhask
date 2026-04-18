# HashiCorp Vault — dev-mode container for POC; swap to production config for prod deploy.
#
# Dev mode:  single unsealed node, in-memory storage, root token = M06_VAULT_TOKEN.
# Prod note: replace with HA cluster + AWS KMS auto-unseal (add aws_kms_key resource).

terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

variable "vault_root_token" {
  type        = string
  description = "Root token for Vault dev-mode container. Set via TF_VAR_vault_root_token."
  sensitive   = true
  default     = "integrishield-dev-root-token"
}

variable "vault_port" {
  type    = number
  default = 8200
}

resource "docker_image" "vault" {
  name         = "hashicorp/vault:1.17"
  keep_locally = true
}

resource "docker_container" "vault_dev" {
  name  = "integrishield-vault-dev"
  image = docker_image.vault.image_id

  # dev mode: -dev flag enables in-memory storage + auto-unseal
  command = ["vault", "server", "-dev", "-dev-root-token-id=${var.vault_root_token}"]

  env = [
    "VAULT_DEV_ROOT_TOKEN_ID=${var.vault_root_token}",
    "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
  ]

  ports {
    internal = 8200
    external = var.vault_port
  }

  capabilities {
    add = ["IPC_LOCK"]
  }

  labels {
    label = "project"
    value = "integrishield-poc"
  }

  restart = "unless-stopped"
}

# Enable KV v2 secrets engine at "integrishield/" mount via local-exec provisioner.
# Runs once after the container starts; idempotent (vault secrets enable errors are ignored).
resource "null_resource" "vault_kv_init" {
  depends_on = [docker_container.vault_dev]

  provisioner "local-exec" {
    command = <<-EOT
      sleep 3
      VAULT_ADDR=http://localhost:${var.vault_port} \
      VAULT_TOKEN=${var.vault_root_token} \
      vault secrets enable -path=integrishield kv-v2 || true
    EOT
  }
}

output "vault_addr" {
  value       = "http://localhost:${var.vault_port}"
  description = "Set M06_VAULT_ADDR to this value."
}

output "vault_token" {
  value       = var.vault_root_token
  sensitive   = true
  description = "Set M06_VAULT_TOKEN to this value."
}
