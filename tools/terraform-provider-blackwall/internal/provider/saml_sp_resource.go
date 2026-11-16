// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

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

// samlSPResource registers a SAML 2.0 Service Provider against a project.
// The current admin API only exposes Create / Read / Delete — updates
// require recreate. This is intentional for now: SPs are sparse, mutation
// is rare, and a recreate is observable in `terraform plan`.
type samlSPResource struct {
	client *client.Client
}

type samlSPModel struct {
	ID             types.String `tfsdk:"id"`
	ProjectUUID    types.String `tfsdk:"project_uuid"`
	EntityID       types.String `tfsdk:"entity_id"`
	ACSURL         types.String `tfsdk:"acs_url"`
	SLOURL         types.String `tfsdk:"slo_url"`
	NameIDFormat   types.String `tfsdk:"name_id_format"`
	Audience       types.String `tfsdk:"audience"`
	SignAssertions types.Bool   `tfsdk:"sign_assertions"`
	SignResponse   types.Bool   `tfsdk:"sign_response"`
	SPCertPEM      types.String `tfsdk:"sp_cert_pem"`
	AttributeMap   types.Map    `tfsdk:"attribute_map"`
	Status         types.String `tfsdk:"status"`
}

func NewSAMLSPResource() resource.Resource { return &samlSPResource{} }

func (r *samlSPResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_saml_service_provider"
}

func (r *samlSPResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*client.Client)
}

// Every mutable attribute is RequiresReplace today because the admin JSON
// API doesn't yet expose a SAML SP PATCH. When it does, drop the modifiers
// and add Update logic — same pattern as oauth_client.
func (r *samlSPResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Registers a SAML 2.0 Service Provider with BlackWall. Mutating any attribute triggers recreate until the admin API exposes a PATCH endpoint for SAML SPs.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Server-assigned public_id.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"project_uuid": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"entity_id": schema.StringAttribute{
				Required:    true,
				Description: "The SP's SAML Entity ID — used to find the SP for an inbound AuthnRequest.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"acs_url": schema.StringAttribute{
				Required:    true,
				Description: "Assertion Consumer Service URL where the signed Response is POSTed.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"slo_url": schema.StringAttribute{
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name_id_format": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: `Defaults to emailAddress.`,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"audience": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Defaults to entity_id.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"sign_assertions": schema.BoolAttribute{Computed: true},
			"sign_response":   schema.BoolAttribute{Computed: true},
			"sp_cert_pem": schema.StringAttribute{
				Optional:    true,
				Description: "PEM-encoded SP certificate for verifying signed AuthnRequests.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"attribute_map": schema.MapAttribute{
				Required:    true,
				ElementType: types.StringType,
				Description: "saml_attr → source map. Source may be display_label or any custom OIDC claim name.",
			},
			"status": schema.StringAttribute{Computed: true},
		},
	}
}

func (r *samlSPResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan samlSPModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	attrMap := map[string]string{}
	if !plan.AttributeMap.IsNull() && !plan.AttributeMap.IsUnknown() {
		d := plan.AttributeMap.ElementsAs(ctx, &attrMap, false)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	sp, err := r.client.CreateSAMLSP(ctx, plan.ProjectUUID.ValueString(), client.CreateSAMLSPInput{
		EntityID:     plan.EntityID.ValueString(),
		ACSURL:       plan.ACSURL.ValueString(),
		SLOURL:       plan.SLOURL.ValueString(),
		NameIDFormat: plan.NameIDFormat.ValueString(),
		Audience:     plan.Audience.ValueString(),
		AttributeMap: attrMap,
		SPCertPEM:    plan.SPCertPEM.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Create SAML SP failed", err.Error())
		return
	}
	r.applyServerState(ctx, &plan, sp)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *samlSPResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state samlSPModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	sp, err := r.client.GetSAMLSP(ctx, state.ID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Read SAML SP failed", err.Error())
		return
	}
	r.applyServerState(ctx, &state, sp)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *samlSPResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError(
		"SAML SP update should not be reachable",
		"Every mutable attribute is RequiresReplace today; if you see this error, the admin API has gained a PATCH endpoint and the resource schema should be updated.",
	)
}

func (r *samlSPResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state samlSPModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteSAMLSP(ctx, state.ID.ValueString()); err != nil {
		if !client.IsNotFound(err) {
			resp.Diagnostics.AddError("Delete SAML SP failed", err.Error())
		}
	}
}

// applyServerState copies the server view into the supplied model, leaving
// the ProjectUUID field (which the server doesn't echo back on the SAML
// endpoints) intact from the caller's plan/state.
func (r *samlSPResource) applyServerState(ctx context.Context, m *samlSPModel, sp *client.SAMLSP) {
	m.ID = types.StringValue(sp.PublicID)
	m.EntityID = types.StringValue(sp.EntityID)
	m.ACSURL = types.StringValue(sp.ACSURL)
	m.SLOURL = types.StringValue(sp.SLOURL)
	m.NameIDFormat = types.StringValue(sp.NameIDFormat)
	m.Audience = types.StringValue(sp.Audience)
	m.SignAssertions = types.BoolValue(sp.SignAssertions)
	m.SignResponse = types.BoolValue(sp.SignResponse)
	m.SPCertPEM = types.StringValue(sp.SPCertPEM)
	m.Status = types.StringValue(sp.Status)
	attrMap, _ := types.MapValueFrom(ctx, types.StringType, sp.AttributeMap)
	m.AttributeMap = attrMap
}
