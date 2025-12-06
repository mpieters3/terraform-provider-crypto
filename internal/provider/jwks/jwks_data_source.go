// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jwks

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &JWKSDataSource{}

func NewJWKSDataSource() datasource.DataSource {
	return &JWKSDataSource{}
}

// JWKSDataSource defines the data source implementation.
type JWKSDataSource struct{}

// JWKSDataSourceModel describes the data source model for reading JWKS.
type JWKSDataSourceModel struct {
	JWKS types.String `tfsdk:"jwks"`
	Keys types.List   `tfsdk:"keys"`
	Id   types.String `tfsdk:"id"`
}

// JWKSDataSourceKey describes a key entry in the data source output.
type JWKSDataSourceKey struct {
	KeyID            types.String `tfsdk:"key_id"`
	Algorithm        types.String `tfsdk:"algorithm"`
	Use              types.String `tfsdk:"use"`
	KeyType          types.String `tfsdk:"key_type"`
	PrivateKey       types.String `tfsdk:"private_key"`
	PublicKey        types.String `tfsdk:"public_key"`
	CertificateChain types.List   `tfsdk:"certificate_chain"`
}

func (d *JWKSDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_jwks"
}

func (d *JWKSDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads a JSON Web Key Set (JWKS) and exposes its contents",
		Attributes: map[string]schema.Attribute{
			"jwks": schema.StringAttribute{
				MarkdownDescription: "JWKS JSON content to read",
				Required:            true,
				Sensitive:           true,
			},
			"keys": schema.ListNestedAttribute{
				MarkdownDescription: "List of keys extracted from the JWKS",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"key_id": schema.StringAttribute{
							MarkdownDescription: "Key ID (kid)",
							Computed:            true,
						},
						"algorithm": schema.StringAttribute{
							MarkdownDescription: "Algorithm (alg)",
							Computed:            true,
						},
						"use": schema.StringAttribute{
							MarkdownDescription: "Public key use (sig or enc)",
							Computed:            true,
						},
						"key_type": schema.StringAttribute{
							MarkdownDescription: "Key type (RSA or EC)",
							Computed:            true,
						},
						"private_key": schema.StringAttribute{
							MarkdownDescription: "PEM-encoded private key (if available)",
							Computed:            true,
							Sensitive:           true,
						},
						"public_key": schema.StringAttribute{
							MarkdownDescription: "PEM-encoded public key",
							Computed:            true,
						},
						"certificate_chain": schema.ListAttribute{
							MarkdownDescription: "List of PEM-encoded certificates from the x5c field",
							Computed:            true,
							ElementType:         types.StringType,
						},
					},
				},
			},
			"id": schema.StringAttribute{
				MarkdownDescription: "Resource identifier",
				Computed:            true,
			},
		},
	}
}

func (d *JWKSDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// No configuration needed for this data source
}

func (d *JWKSDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data JWKSDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Parse JWKS JSON
	var jwks JWKS
	err := json.Unmarshal([]byte(data.JWKS.ValueString()), &jwks)
	if err != nil {
		resp.Diagnostics.AddError("JWKS Parse Error", fmt.Sprintf("Unable to parse JWKS JSON: %s", err))
		return
	}

	tflog.Debug(ctx, "Parsed JWKS", map[string]any{
		"key_count": len(jwks.Keys),
	})

	// Extract keys
	var keys []JWKSDataSourceKey

	for _, jwk := range jwks.Keys {
		var privateKeyPEM string
		var publicKeyPEM string

		// Convert JWK to PEM format
		if jwk.D != "" {
			// Has private key
			privateKeyPEM, err = jwkToPrivateKeyPEM(jwk)
			if err != nil {
				resp.Diagnostics.AddError("Key Conversion Error",
					fmt.Sprintf("Unable to convert JWK to private key PEM for kid %s: %s", jwk.Kid, err))
				return
			}
		}

		// Get public key - for now, we'll extract it from the private key or create a public-only key
		publicKeyPEM, err = jwkToPrivateKeyPEM(jwk)
		if err != nil {
			resp.Diagnostics.AddError("Key Conversion Error",
				fmt.Sprintf("Unable to convert JWK to public key PEM for kid %s: %s", jwk.Kid, err))
			return
		}

		// Convert x5c certificates to PEM
		var certChainPEMs []types.String
		if len(jwk.X5c) > 0 {
			certs, err := jwkToCertificatesPEM(jwk)
			if err != nil {
				resp.Diagnostics.AddError("Certificate Conversion Error",
					fmt.Sprintf("Unable to convert certificates for kid %s: %s", jwk.Kid, err))
				return
			}
			for _, cert := range certs {
				certChainPEMs = append(certChainPEMs, types.StringValue(cert))
			}
		}

		certChainList, diags := types.ListValueFrom(ctx, types.StringType, certChainPEMs)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		// Determine key ID, algorithm, and use
		kid := jwk.Kid
		alg := jwk.Alg
		use := jwk.Use

		key := JWKSDataSourceKey{
			KeyID:            types.StringValue(kid),
			Algorithm:        types.StringValue(alg),
			Use:              types.StringValue(use),
			KeyType:          types.StringValue(jwk.Kty),
			PrivateKey:       types.StringValue(privateKeyPEM),
			PublicKey:        types.StringValue(publicKeyPEM),
			CertificateChain: certChainList,
		}

		keys = append(keys, key)

		tflog.Debug(ctx, "Extracted key", map[string]any{
			"key_id":      kid,
			"key_type":    jwk.Kty,
			"has_private": jwk.D != "",
			"cert_count":  len(jwk.X5c),
		})
	}

	// Convert keys to List
	keysList, diags := types.ListValueFrom(ctx, types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"key_id":            types.StringType,
			"algorithm":         types.StringType,
			"use":               types.StringType,
			"key_type":          types.StringType,
			"private_key":       types.StringType,
			"public_key":        types.StringType,
			"certificate_chain": types.ListType{ElemType: types.StringType},
		},
	}, keys)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.Keys = keysList

	// Generate identifier based on the JWKS content
	hash := sha256.Sum256([]byte(data.JWKS.ValueString()))
	data.Id = types.StringValue(fmt.Sprintf("jwks-%x", hash))

	tflog.Trace(ctx, "Read JWKS data source", map[string]any{
		"keys_count": len(keys),
	})

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
