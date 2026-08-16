# terraform-provider-blackwall

Terraform provider for the BlackWall identity platform. Resources are driven through the bearer-token-authenticated admin API at `/api/v1/*`.

## Status

| Surface                       | Resource / data source              | Status      |
|-------------------------------|-------------------------------------|-------------|
| Organisation lookup           | `data.blackwall_organization`       | implemented |
| Project                       | `blackwall_project`                 | implemented |
| OAuth client                  | `blackwall_oauth_client`            | implemented |
| Per-project default OIDC claim| `blackwall_claim_default`           | implemented |
| Outbound webhook endpoint     | `blackwall_webhook_endpoint`        | implemented |
| SAML service provider         | `blackwall_saml_service_provider`   | implemented (create/read/delete; updates trigger recreate) |
| Admin API token               | `blackwall_admin_token`             | next        |

## Configuration

```hcl
provider "blackwall" {
  host  = "https://auth.example.com"   # or env BLACKWALL_HOST
  token = "bw_admin_..."               # or env BLACKWALL_TOKEN
}
```

Tokens are minted at `/admin/api-tokens` in the BlackWall admin UI.

## Build + install locally

```sh
cd tools/terraform-provider-blackwall
go mod tidy
go build -o terraform-provider-blackwall .

# Install into the user's plugin cache for local terraform runs:
PLUGIN_DIR="$HOME/.terraform.d/plugins/blackwall.io/identity/blackwall/0.1.0/$(go env GOOS)_$(go env GOARCH)"
mkdir -p "$PLUGIN_DIR"
cp terraform-provider-blackwall "$PLUGIN_DIR/"
```

## Example

See `examples/main.tf`.
