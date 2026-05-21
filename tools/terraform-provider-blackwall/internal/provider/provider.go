// Package provider hosts the terraform-plugin-framework provider definition
// for BlackWall, the resources it exposes, and the data sources for read-
// only lookups.
//
// Resources implemented in this initial cut:
//   - blackwall_claim_default — manage a per-project default OIDC claim
//   - blackwall_webhook_endpoint — register a webhook receiver
//
// Data sources:
//   - blackwall_organization — look up an organisation by slug
//
// More resources (blackwall_project, blackwall_oauth_client,
// blackwall_saml_sp) are stubbed out below for the next iteration; the
// pattern is identical so a future contributor can copy the existing
// resources and swap the API verb.
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/blackwall/terraform-provider-blackwall/internal/client"
)

type bwProvider struct {
	version string
}

type bwProviderModel struct {
	Host  types.String `tfsdk:"host"`
	Token types.String `tfsdk:"token"`
}

// New returns the provider factory function. The version is baked in at
// build time so the plugin protocol can negotiate compatibility properly.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &bwProvider{version: version}
	}
}

func (p *bwProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "blackwall"
	resp.Version = p.version
}

func (p *bwProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "BlackWall identity platform provider. Reads BLACKWALL_HOST and BLACKWALL_TOKEN env vars if the corresponding block attributes are unset.",
		Attributes: map[string]schema.Attribute{
			"host": schema.StringAttribute{
				Optional:    true,
				Description: "BlackWall server base URL, e.g. https://auth.example.com. May also be set via BLACKWALL_HOST.",
			},
			"token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Admin API bearer token (bw_admin_...). May also be set via BLACKWALL_TOKEN.",
			},
		},
	}
}

func (p *bwProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data bwProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	host := data.Host.ValueString()
	if host == "" {
		host = os.Getenv("BLACKWALL_HOST")
	}
	token := data.Token.ValueString()
	if token == "" {
		token = os.Getenv("BLACKWALL_TOKEN")
	}
	if host == "" {
		resp.Diagnostics.AddError("Missing host", "Set provider.host or BLACKWALL_HOST.")
		return
	}
	if token == "" {
		resp.Diagnostics.AddError("Missing token", "Set provider.token or BLACKWALL_TOKEN.")
		return
	}
	c := client.New(host, token)
	resp.DataSourceData = c
	resp.ResourceData = c
}

func (p *bwProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewClaimDefaultResource,
		NewWebhookEndpointResource,
		NewProjectResource,
		NewOAuthClientResource,
		NewSAMLSPResource,
	}
}

func (p *bwProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewOrganizationDataSource,
	}
}
