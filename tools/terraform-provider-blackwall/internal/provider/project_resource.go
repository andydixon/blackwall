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

// projectResource manages BlackWall projects via the JSON admin API.
// Organisation membership is set at create time and is treated as
// immutable — moving a project between orgs touches privilege ladders,
// role assignments, and audit lineage and isn't something we want to do
// implicitly from Terraform.
type projectResource struct {
	client *client.Client
}

type projectModel struct {
	UUID             types.String `tfsdk:"uuid"`
	Name             types.String `tfsdk:"name"`
	Status           types.String `tfsdk:"status"`
	OrganizationUUID types.String `tfsdk:"organization_uuid"`
}

func NewProjectResource() resource.Resource { return &projectResource{} }

func (r *projectResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_project"
}

func (r *projectResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*client.Client)
}

func (r *projectResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A BlackWall project. Projects own OAuth clients, claim defaults, webhooks, and per-user assignments.",
		Attributes: map[string]schema.Attribute{
			"uuid": schema.StringAttribute{
				Computed:    true,
				Description: "Server-assigned UUID — also the resource ID.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Human-readable project name.",
			},
			"status": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "active or disabled. Defaults to active on create.",
			},
			"organization_uuid": schema.StringAttribute{
				Required:    true,
				Description: "Owning organisation. Immutable — destroying and recreating the resource is the only way to move a project across organisations.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (r *projectResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan projectModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p, err := r.client.CreateProject(ctx, client.CreateProjectInput{
		Name:             plan.Name.ValueString(),
		OrganizationUUID: plan.OrganizationUUID.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Create project failed", err.Error())
		return
	}
	plan.UUID = types.StringValue(p.UUID)
	plan.Status = types.StringValue(p.Status)
	// If the caller asked for status=disabled on create, follow up with a
	// PATCH; the create endpoint always returns active.
	if !plan.Status.IsNull() && plan.Status.ValueString() == "disabled" {
		s := "disabled"
		if err := r.client.PatchProject(ctx, p.UUID, client.PatchProjectInput{Status: &s}); err != nil {
			resp.Diagnostics.AddError("Set initial status failed", err.Error())
			return
		}
		plan.Status = types.StringValue("disabled")
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *projectResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state projectModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p, err := r.client.GetProject(ctx, state.UUID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Read project failed", err.Error())
		return
	}
	state.Name = types.StringValue(p.Name)
	state.Status = types.StringValue(p.Status)
	state.OrganizationUUID = types.StringValue(p.OrganizationUUID)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *projectResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state projectModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := client.PatchProjectInput{}
	if plan.Name.ValueString() != state.Name.ValueString() {
		n := plan.Name.ValueString()
		in.Name = &n
	}
	if plan.Status.ValueString() != state.Status.ValueString() {
		s := plan.Status.ValueString()
		in.Status = &s
	}
	if in.Name != nil || in.Status != nil {
		if err := r.client.PatchProject(ctx, state.UUID.ValueString(), in); err != nil {
			resp.Diagnostics.AddError("Update project failed", err.Error())
			return
		}
	}
	plan.UUID = state.UUID
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *projectResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state projectModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteProject(ctx, state.UUID.ValueString()); err != nil {
		if !client.IsNotFound(err) {
			resp.Diagnostics.AddError("Delete project failed", err.Error())
		}
	}
	// Note: the server treats DELETE as "set status=disabled" so the row
	// remains for audit lineage; from Terraform's perspective the resource
	// is gone, which is the right contract for `terraform destroy`.
}
