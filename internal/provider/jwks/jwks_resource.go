// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jwks

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &JWKSResource{}

func NewJWKSResource() resource.Resource {
	return &JWKSResource{}
}

// JWKSResource defines the resource implementation.
type JWKSResource struct{}

func (r *JWKSResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_jwks"
}

func (r *JWKSResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "JSON Web Key Set (JWKS) as a resource",
		Attributes: map[string]schema.Attribute{
			"keys": schema.ListNestedAttribute{
				MarkdownDescription: "List of keys to include in the JWKS",
				Optional:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"private_key": schema.StringAttribute{
							MarkdownDescription: "PEM-encoded private key (RSA or EC)",
							Required:            true,
							Sensitive:           true,
						},
						"certificate": schema.StringAttribute{
							MarkdownDescription: "PEM-encoded certificate",
							Optional:            true,
						},
						"certificate_chain": schema.ListAttribute{
							MarkdownDescription: "List of PEM-encoded certificates forming the certificate chain",
							Optional:            true,
							ElementType:         types.StringType,
						},
						"key_id": schema.StringAttribute{
							MarkdownDescription: "Key ID (kid) for this key. If not provided, a random ID will be generated",
							Optional:            true,
						},
						"algorithm": schema.StringAttribute{
							MarkdownDescription: "Algorithm intended for use with this key (e.g., RS256, ES256)",
							Optional:            true,
						},
						"use": schema.StringAttribute{
							MarkdownDescription: "Public key use parameter (sig or enc)",
							Optional:            true,
						},
					},
				},
			},
			"jwks": schema.StringAttribute{
				MarkdownDescription: "JSON Web Key Set content",
				Computed:            true,
				Sensitive:           true,
			},
			"base_jwks": schema.StringAttribute{
				MarkdownDescription: "Optional base JWKS JSON content to use as the initial key set",
				Optional:            true,
				Sensitive:           true,
			},
			"id": schema.StringAttribute{
				MarkdownDescription: "Resource identifier",
				Computed:            true,
			},
		},
	}
}

func (r *JWKSResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// No configuration needed for this resource
}

// createOrUpdateJWKS handles the common logic for creating and updating a JWKS resource.
func (r *JWKSResource) createOrUpdateJWKS(ctx context.Context, data *JWKSModel, diagnostics *diag.Diagnostics, operation string) {
	createJWKS(ctx, data, diagnostics, operation+" resource")
}

func (r *JWKSResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data JWKSModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Handle creation
	r.createOrUpdateJWKS(ctx, &data, &resp.Diagnostics, "create")

	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *JWKSResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data JWKSModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// No need to re-read anything as all data is stored in the state
	// The JWKS content is deterministic based on the inputs

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *JWKSResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data JWKSModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Just regenerate the JWKS if there's a change
	r.createOrUpdateJWKS(ctx, &data, &resp.Diagnostics, "update")

	if resp.Diagnostics.HasError() {
		// On error, keep the prior state
		var priorData JWKSModel
		resp.Diagnostics.Append(req.State.Get(ctx, &priorData)...)
		resp.Diagnostics.Append(resp.State.Set(ctx, &priorData)...)
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *JWKSResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data JWKSModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// No actual cleanup needed as we don't persist anything externally
}
