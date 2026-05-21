package provider

import (
	"context"
	"errors"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/blackwall/terraform-provider-blackwall/internal/client"
)

// organizationDataSource lets a Terraform config look up an org's UUID by
// its human-readable slug. Useful as the upstream value for resources that
// need an organization_uuid attribute.
type organizationDataSource struct {
	client *client.Client
}

type organizationDataSourceModel struct {
	Slug   types.String `tfsdk:"slug"`
	UUID   types.String `tfsdk:"uuid"`
	Name   types.String `tfsdk:"name"`
	Status types.String `tfsdk:"status"`
}

func NewOrganizationDataSource() datasource.DataSource { return &organizationDataSource{} }

func (d *organizationDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_organization"
}

func (d *organizationDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	d.client = req.ProviderData.(*client.Client)
}

func (d *organizationDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Look up a BlackWall organization by slug.",
		Attributes: map[string]schema.Attribute{
			"slug": schema.StringAttribute{
				Required:    true,
				Description: "Human-readable slug, e.g. 'acme'.",
			},
			"uuid":   schema.StringAttribute{Computed: true, Description: "UUID — pass into resources needing organization_uuid."},
			"name":   schema.StringAttribute{Computed: true},
			"status": schema.StringAttribute{Computed: true},
		},
	}
}

func (d *organizationDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg organizationDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	orgs, err := d.client.ListOrganizations(ctx)
	if err != nil {
		resp.Diagnostics.AddError("List organizations failed", err.Error())
		return
	}
	want := cfg.Slug.ValueString()
	for _, o := range orgs {
		if o.Slug == want {
			cfg.UUID = types.StringValue(o.UUID)
			cfg.Name = types.StringValue(o.Name)
			cfg.Status = types.StringValue(o.Status)
			resp.Diagnostics.Append(resp.State.Set(ctx, cfg)...)
			return
		}
	}
	resp.Diagnostics.AddError("Organization not found", "No organization with slug "+want+" visible to this token.")
}

// errFromDiags collapses a Diagnostics slice into a single error for the
// (small number of) places we want classic err returns.
func errFromDiags(d diag.Diagnostics) error {
	if !d.HasError() {
		return nil
	}
	msg := ""
	for _, e := range d.Errors() {
		if msg != "" {
			msg += "; "
		}
		msg += e.Summary()
	}
	return errors.New(msg)
}
