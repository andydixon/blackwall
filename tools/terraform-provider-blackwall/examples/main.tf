# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025-2026 Andy Dixon

# Example: drive BlackWall claim defaults and webhook endpoints from
# Terraform. Run with:
#
#     export BLACKWALL_HOST=https://auth.example.com
#     export BLACKWALL_TOKEN=bw_admin_...
#     terraform init
#     terraform plan
#     terraform apply
#
# The `project_uuid` values below are placeholders — look them up in the
# BlackWall admin UI or via `curl /api/v1/projects`.

terraform {
  required_providers {
    blackwall = {
      source = "blackwall.io/identity/blackwall"
    }
  }
}

provider "blackwall" {
  # host  = "https://auth.example.com"   # or via BLACKWALL_HOST
  # token = "bw_admin_..."               # or via BLACKWALL_TOKEN
}

data "blackwall_organization" "acme" {
  slug = "acme"
}

# Per-project default claims — applied to every token issued for the
# Grafana project unless a per-user override exists.
resource "blackwall_claim_default" "grafana_preferred_username" {
  project_uuid = "REPLACE-WITH-PROJECT-UUID"
  key          = "preferred_username"
  value        = "team-grafana"
}

resource "blackwall_claim_default" "grafana_groups" {
  project_uuid = "REPLACE-WITH-PROJECT-UUID"
  key          = "groups"
  # JSON literal — emitted as a real array in the token.
  value = jsonencode(["editors", "viewers"])
}

# Audit-event webhook receiver.
resource "blackwall_webhook_endpoint" "audit_sink" {
  project_uuid = "REPLACE-WITH-PROJECT-UUID"
  target_url   = "https://audit.example.com/blackwall"
  description  = "Production audit sink"
  events       = ["*"]
}

output "webhook_secret_keep_safe" {
  value     = blackwall_webhook_endpoint.audit_sink.secret
  sensitive = true
}
