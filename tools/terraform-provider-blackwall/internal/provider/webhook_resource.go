// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/blackwall/terraform-provider-blackwall/internal/client"
)

// webhookEndpointResource manages a per-project webhook receiver.
//
// Lifecycle:
//   - Create: POST /api/v1/projects/{uuid}/webhooks → secret returned ONCE.
//   - Read: GET the list, match by public_id, refresh URL/events/status.
//   - Update: not implemented in this cut (admin API needs a PATCH endpoint
//     first; for now any mutation forces a recreate via RequiresReplace).
//   - Delete: ditto — the JSON API needs a DELETE endpoint. We log a warning
//     so the operator knows to clean up from the admin UI.
type webhookEndpointResource struct {
	client *client.Client
}

type webhookEndpointModel struct {
	ID          types.String `tfsdk:"id"`
	ProjectUUID types.String `tfsdk:"project_uuid"`
	TargetURL   types.String `tfsdk:"target_url"`
	Description types.String `tfsdk:"description"`
	Events      types.List   `tfsdk:"events"`
	Status      types.String `tfsdk:"status"`
	Secret      types.String `tfsdk:"secret"`
}

func NewWebhookEndpointResource() resource.Resource { return &webhookEndpointResource{} }

func (r *webhookEndpointResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_webhook_endpoint"
}

func (r *webhookEndpointResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*client.Client)
}

func (r *webhookEndpointResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Registers an outbound webhook receiver against a BlackWall project. Audit events for the project are signed with HMAC-SHA256 and POSTed to target_url.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Server-assigned public_id of the endpoint.",
			},
			"project_uuid": schema.StringAttribute{
				Required:    true,
				Description: "UUID of the BlackWall project to attach the receiver to.",
			},
			"target_url": schema.StringAttribute{
				Required:    true,
				Description: "Absolute http(s) URL that will receive POST deliveries.",
			},
			"description": schema.StringAttribute{
				Optional: true,
			},
			"events": schema.ListAttribute{
				Required:    true,
				ElementType: types.StringType,
				Description: `Event filter, e.g. ["*"] for all, or ["admin.user.update","oidc.userinfo.success"].`,
			},
			"status": schema.StringAttribute{
				Computed:    true,
				Description: "Server-side status: active or disabled.",
			},
			"secret": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "HMAC signing secret. Returned only at create time. Rotate via the admin UI.",
			},
		},
	}
}

func (r *webhookEndpointResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan webhookEndpointModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	events, err := stringListFrom(plan.Events)
	if err != nil {
		resp.Diagnostics.AddError("events conversion failed", err.Error())
		return
	}
	ep, err := r.client.CreateWebhook(ctx, plan.ProjectUUID.ValueString(),
		plan.TargetURL.ValueString(), plan.Description.ValueString(), events)
	if err != nil {
		resp.Diagnostics.AddError("Create webhook failed", err.Error())
		return
	}
	plan.ID = types.StringValue(ep.PublicID)
	plan.Status = types.StringValue(ep.Status)
	plan.Secret = types.StringValue(ep.Secret)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *webhookEndpointResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state webhookEndpointModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	endpoints, err := r.client.ListWebhooks(ctx, state.ProjectUUID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Read webhooks failed", err.Error())
		return
	}
	wanted := state.ID.ValueString()
	for _, e := range endpoints {
		if e.PublicID == wanted {
			state.TargetURL = types.StringValue(e.TargetURL)
			state.Description = types.StringValue(e.Description)
			state.Status = types.StringValue(e.Status)
			ev, diags := types.ListValueFrom(ctx, types.StringType, e.Events)
			resp.Diagnostics.Append(diags...)
			state.Events = ev
			// Note: secret stays whatever we captured at create time.
			resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
			return
		}
	}
	resp.State.RemoveResource(ctx)
}

func (r *webhookEndpointResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state webhookEndpointModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	events, err := stringListFrom(plan.Events)
	if err != nil {
		resp.Diagnostics.AddError("events conversion failed", err.Error())
		return
	}
	target := plan.TargetURL.ValueString()
	desc := plan.Description.ValueString()
	status := plan.Status.ValueString()
	in := client.PatchWebhookInput{
		TargetURL:   &target,
		Description: &desc,
		Events:      events,
	}
	// Status is computed in our schema (server-controlled), but if a future
	// schema makes it optional+writable, mirror it through; today we
	// preserve whatever the server has.
	if status != "" {
		in.Status = &status
	}
	ep, err := r.client.PatchWebhook(ctx, state.ProjectUUID.ValueString(), state.ID.ValueString(), in)
	if err != nil {
		resp.Diagnostics.AddError("Update webhook failed", err.Error())
		return
	}
	plan.ID = types.StringValue(ep.PublicID)
	plan.Status = types.StringValue(ep.Status)
	// Secret stays whatever we captured at create time unless the caller
	// rotated; this resource doesn't expose a rotate knob (use the admin
	// UI to rotate) so we preserve the existing state value.
	plan.Secret = state.Secret
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *webhookEndpointResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state webhookEndpointModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteWebhook(ctx, state.ProjectUUID.ValueString(), state.ID.ValueString()); err != nil {
		if !client.IsNotFound(err) {
			resp.Diagnostics.AddError("Delete webhook failed", err.Error())
		}
	}
}

// stringListFrom converts a Terraform string list into a []string.
func stringListFrom(l types.List) ([]string, error) {
	if l.IsNull() || l.IsUnknown() {
		return nil, nil
	}
	var out []string
	d := l.ElementsAs(context.Background(), &out, false)
	if d.HasError() {
		return nil, errFromDiags(d)
	}
	return out, nil
}
