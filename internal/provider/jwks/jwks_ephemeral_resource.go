// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jwks

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ ephemeral.EphemeralResource = &JWKSEphemeralResource{}

func NewJWKSEphemeralResource() ephemeral.EphemeralResource {
	return &JWKSEphemeralResource{}
}

// JWKSEphemeralResource defines the ephemeral resource implementation.
type JWKSEphemeralResource struct{}

func (r *JWKSEphemeralResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_jwks"
}

func (r *JWKSEphemeralResource) Schema(ctx context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "JSON Web Key Set (JWKS) as an ephemeral resource",
		Attributes: map[string]schema.Attribute{
			"keys": schema.ListNestedAttribute{
				MarkdownDescription: "List of keys to include in the JWKS",
				Required:            true,
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

// createJWKS handles the logic for creating a JWKS ephemeral resource.
func (r *JWKSEphemeralResource) createJWKS(ctx context.Context, data *JWKSModel, diagnostics *diag.Diagnostics) {
	createJWKS(ctx, data, diagnostics, "created ephemeral resource")
}

func (r *JWKSEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data JWKSModel

	// Read Terraform config data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create the JWKS
	r.createJWKS(ctx, &data, &resp.Diagnostics)

	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into ephemeral result data
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
