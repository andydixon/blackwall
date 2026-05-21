package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/blackwall/terraform-provider-blackwall/internal/client"
)

// oauthClientResource manages an OAuth/OIDC client registered under a
// project. The client_secret is returned ONCE at create time and stored in
// Terraform state thereafter — Terraform state files must be encrypted.
type oauthClientResource struct {
	client *client.Client
}

type oauthClientModel struct {
	ID                   types.String `tfsdk:"id"`
	ProjectUUID          types.String `tfsdk:"project_uuid"`
	Name                 types.String `tfsdk:"name"`
	ClientType           types.String `tfsdk:"client_type"`
	Status               types.String `tfsdk:"status"`
	OIDCEnabled          types.Bool   `tfsdk:"oidc_enabled"`
	AccessTokenType      types.String `tfsdk:"access_token_type"`
	AccessTokenLifetime  types.Int64  `tfsdk:"access_token_lifetime"`
	RefreshTokenLifetime types.Int64  `tfsdk:"refresh_token_lifetime"`
	RedirectURIs         types.List   `tfsdk:"redirect_uris"`
	Grants               types.List   `tfsdk:"grants"`
	Scopes               types.List   `tfsdk:"scopes"`
	ClientSecret         types.String `tfsdk:"client_secret"`
}

func NewOAuthClientResource() resource.Resource { return &oauthClientResource{} }

func (r *oauthClientResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oauth_client"
}

func (r *oauthClientResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*client.Client)
}

func (r *oauthClientResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Registers an OAuth/OIDC client against a BlackWall project. PKCE is required by the platform; client_type chooses between a confidential client (with a secret) and a public client.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Server-assigned client_id.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"project_uuid": schema.StringAttribute{
				Required:    true,
				Description: "Owning project.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Required: true,
			},
			"client_type": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: `"confidential" (default — secret generated) or "public" (no secret).`,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"status": schema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"oidc_enabled":           schema.BoolAttribute{Optional: true, Computed: true},
			"access_token_type":      schema.StringAttribute{Optional: true, Computed: true, Description: `"jwt" (default) or "opaque".`},
			"access_token_lifetime":  schema.Int64Attribute{Optional: true, Computed: true, Description: "Seconds. Default 3600."},
			"refresh_token_lifetime": schema.Int64Attribute{Optional: true, Computed: true, Description: "Seconds. Default 2592000 (30 days)."},
			"redirect_uris":          schema.ListAttribute{Optional: true, Computed: true, ElementType: types.StringType},
			"grants":                 schema.ListAttribute{Optional: true, Computed: true, ElementType: types.StringType},
			"scopes":                 schema.ListAttribute{Optional: true, Computed: true, ElementType: types.StringType},
			"client_secret": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "Returned at create time only. Empty for public clients.",
			},
		},
	}
}

func (r *oauthClientResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan oauthClientModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	redir, _ := stringListFrom(plan.RedirectURIs)
	grants, _ := stringListFrom(plan.Grants)
	scopes, _ := stringListFrom(plan.Scopes)

	in := client.CreateOAuthClientInput{
		Name:                 plan.Name.ValueString(),
		ClientType:           plan.ClientType.ValueString(),
		RedirectURIs:         redir,
		Grants:               grants,
		Scopes:               scopes,
		AccessTokenType:      plan.AccessTokenType.ValueString(),
		AccessTokenLifetime:  int(plan.AccessTokenLifetime.ValueInt64()),
		RefreshTokenLifetime: int(plan.RefreshTokenLifetime.ValueInt64()),
		OIDCEnabled:          plan.OIDCEnabled.ValueBool(),
	}
	c, err := r.client.CreateOAuthClient(ctx, plan.ProjectUUID.ValueString(), in)
	if err != nil {
		resp.Diagnostics.AddError("Create OAuth client failed", err.Error())
		return
	}
	plan.ID = types.StringValue(c.ClientID)
	plan.Status = types.StringValue(c.Status)
	plan.OIDCEnabled = types.BoolValue(c.OIDCEnabled)
	plan.AccessTokenType = types.StringValue(c.AccessTokenType)
	plan.AccessTokenLifetime = types.Int64Value(int64(c.AccessTokenLifetime))
	plan.RefreshTokenLifetime = types.Int64Value(int64(c.RefreshTokenLifetime))
	plan.ClientSecret = types.StringValue(c.ClientSecret)
	plan.ClientType = types.StringValue(coalesceString(plan.ClientType.ValueString(), "confidential"))
	plan.RedirectURIs = mustStringList(ctx, c.RedirectURIs)
	plan.Grants = mustStringList(ctx, c.Grants)
	plan.Scopes = mustStringList(ctx, c.Scopes)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *oauthClientResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state oauthClientModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	c, err := r.client.GetOAuthClient(ctx, state.ID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Read OAuth client failed", err.Error())
		return
	}
	state.Name = types.StringValue(c.Name)
	state.Status = types.StringValue(c.Status)
	state.OIDCEnabled = types.BoolValue(c.OIDCEnabled)
	state.AccessTokenType = types.StringValue(c.AccessTokenType)
	state.AccessTokenLifetime = types.Int64Value(int64(c.AccessTokenLifetime))
	state.RefreshTokenLifetime = types.Int64Value(int64(c.RefreshTokenLifetime))
	state.RedirectURIs = mustStringList(ctx, c.RedirectURIs)
	state.Grants = mustStringList(ctx, c.Grants)
	state.Scopes = mustStringList(ctx, c.Scopes)
	// client_secret stays whatever we captured at create time.
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *oauthClientResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state oauthClientModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := client.PatchOAuthClientInput{}
	if plan.Name.ValueString() != state.Name.ValueString() {
		n := plan.Name.ValueString()
		in.Name = &n
	}
	if plan.Status.ValueString() != state.Status.ValueString() && !plan.Status.IsNull() {
		s := plan.Status.ValueString()
		in.Status = &s
	}
	if plan.AccessTokenType.ValueString() != state.AccessTokenType.ValueString() && !plan.AccessTokenType.IsNull() {
		t := plan.AccessTokenType.ValueString()
		in.AccessTokenType = &t
	}
	if plan.AccessTokenLifetime.ValueInt64() != state.AccessTokenLifetime.ValueInt64() {
		v := int(plan.AccessTokenLifetime.ValueInt64())
		in.AccessTokenLifetime = &v
	}
	if plan.RefreshTokenLifetime.ValueInt64() != state.RefreshTokenLifetime.ValueInt64() {
		v := int(plan.RefreshTokenLifetime.ValueInt64())
		in.RefreshTokenLifetime = &v
	}
	if plan.OIDCEnabled.ValueBool() != state.OIDCEnabled.ValueBool() {
		v := plan.OIDCEnabled.ValueBool()
		in.OIDCEnabled = &v
	}
	if !plan.RedirectURIs.Equal(state.RedirectURIs) {
		in.RedirectURIs, _ = stringListFrom(plan.RedirectURIs)
	}
	if !plan.Grants.Equal(state.Grants) {
		in.Grants, _ = stringListFrom(plan.Grants)
	}
	if !plan.Scopes.Equal(state.Scopes) {
		in.Scopes, _ = stringListFrom(plan.Scopes)
	}
	if err := r.client.PatchOAuthClient(ctx, state.ID.ValueString(), in); err != nil {
		resp.Diagnostics.AddError("Update OAuth client failed", err.Error())
		return
	}
	plan.ID = state.ID
	plan.ClientSecret = state.ClientSecret // preserve
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *oauthClientResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state oauthClientModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteOAuthClient(ctx, state.ID.ValueString()); err != nil {
		if !client.IsNotFound(err) {
			resp.Diagnostics.AddError("Delete OAuth client failed", err.Error())
		}
	}
}

func coalesceString(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func mustStringList(ctx context.Context, in []string) types.List {
	if in == nil {
		in = []string{}
	}
	l, _ := types.ListValueFrom(ctx, types.StringType, in)
	return l
}
