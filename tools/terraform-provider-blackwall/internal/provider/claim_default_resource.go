package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/blackwall/terraform-provider-blackwall/internal/client"
)

// claimDefaultResource manages a single (project, key) default OIDC claim.
// The remote system upserts on PUT, so Create and Update collapse to the
// same call. Read confirms the value still matches what state expects
// (drift detection).
type claimDefaultResource struct {
	client *client.Client
}

type claimDefaultModel struct {
	ID          types.String `tfsdk:"id"`
	ProjectUUID types.String `tfsdk:"project_uuid"`
	Key         types.String `tfsdk:"key"`
	Value       types.String `tfsdk:"value"`
}

func NewClaimDefaultResource() resource.Resource { return &claimDefaultResource{} }

func (r *claimDefaultResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_claim_default"
}

func (r *claimDefaultResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*client.Client)
}

func (r *claimDefaultResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A per-project default OIDC claim. Merged into every token issued for the project unless a narrower (user-level) claim overrides.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Synthetic ID of the form <project_uuid>/<key>.",
			},
			"project_uuid": schema.StringAttribute{
				Required:    true,
				Description: "UUID of the BlackWall project.",
			},
			"key": schema.StringAttribute{
				Required:    true,
				Description: "Claim name (e.g. preferred_username, groups).",
			},
			"value": schema.StringAttribute{
				Required:    true,
				Sensitive:   false,
				Description: `Claim value. May be a string, or a JSON literal (number, boolean, array, object) — JSON literals are round-tripped with their original type in the token.`,
			},
		},
	}
}

func (r *claimDefaultResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan claimDefaultModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpsertClaimDefault(ctx, plan.ProjectUUID.ValueString(), plan.Key.ValueString(), plan.Value.ValueString()); err != nil {
		resp.Diagnostics.AddError("Create claim default failed", err.Error())
		return
	}
	plan.ID = types.StringValue(plan.ProjectUUID.ValueString() + "/" + plan.Key.ValueString())
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *claimDefaultResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state claimDefaultModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	claims, err := r.client.ListClaimDefaults(ctx, state.ProjectUUID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Read claim defaults failed", err.Error())
		return
	}
	wanted := state.Key.ValueString()
	for _, c := range claims {
		if c.Key == wanted {
			state.Value = types.StringValue(c.Value)
			resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
			return
		}
	}
	// No matching key — treat as deleted upstream.
	resp.State.RemoveResource(ctx)
}

func (r *claimDefaultResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan claimDefaultModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpsertClaimDefault(ctx, plan.ProjectUUID.ValueString(), plan.Key.ValueString(), plan.Value.ValueString()); err != nil {
		resp.Diagnostics.AddError("Update claim default failed", err.Error())
		return
	}
	plan.ID = types.StringValue(plan.ProjectUUID.ValueString() + "/" + plan.Key.ValueString())
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *claimDefaultResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state claimDefaultModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteClaimDefault(ctx, state.ProjectUUID.ValueString(), state.Key.ValueString()); err != nil {
		if !client.IsNotFound(err) {
			resp.Diagnostics.AddError("Delete claim default failed", err.Error())
		}
		// 404 is fine: the row was already gone, the desired post-state is met.
	}
}
