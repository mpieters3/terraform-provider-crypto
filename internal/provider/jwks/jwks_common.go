// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// JWK represents a JSON Web Key.
type JWK struct {
	Kty string   `json:"kty"`           // Key Type (RSA, EC, oct)
	Use string   `json:"use,omitempty"` // Public Key Use (sig, enc)
	Kid string   `json:"kid,omitempty"` // Key ID
	Alg string   `json:"alg,omitempty"` // Algorithm
	X5c []string `json:"x5c,omitempty"` // X.509 Certificate Chain

	// RSA specific
	N  string `json:"n,omitempty"`  // Modulus
	E  string `json:"e,omitempty"`  // Exponent
	D  string `json:"d,omitempty"`  // Private Exponent
	P  string `json:"p,omitempty"`  // First Prime Factor
	Q  string `json:"q,omitempty"`  // Second Prime Factor
	Dp string `json:"dp,omitempty"` // First Factor CRT Exponent
	Dq string `json:"dq,omitempty"` // Second Factor CRT Exponent
	Qi string `json:"qi,omitempty"` // First CRT Coefficient

	// EC specific
	Crv string `json:"crv,omitempty"` // Curve
	X   string `json:"x,omitempty"`   // X Coordinate
	Y   string `json:"y,omitempty"`   // Y Coordinate
	// D already defined above for private key
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// KeyEntry describes a single private key, certificate and chain entry for JWKS.
type KeyEntry struct {
	PrivateKey       types.String `tfsdk:"private_key"`
	Certificate      types.String `tfsdk:"certificate"`
	CertificateChain types.List   `tfsdk:"certificate_chain"`
	KeyID            types.String `tfsdk:"key_id"`
	Algorithm        types.String `tfsdk:"algorithm"`
	Use              types.String `tfsdk:"use"`
}

// JWKSModel describes the common data model for JWKS resources, data sources, and ephemeral resources.
type JWKSModel struct {
	Keys     types.List   `tfsdk:"keys"`
	BaseJWKS types.String `tfsdk:"base_jwks"`
	JWKS     types.String `tfsdk:"jwks"`
	Id       types.String `tfsdk:"id"`
}

// hashString calculates a SHA-256 hash of the input string.
func hashString(input string) []byte {
	h := sha256.New()
	h.Write([]byte(input))
	return h.Sum(nil)
}

// decodePEMBlock decodes a PEM-encoded string into a pem.Block.
func decodePEMBlock(pemStr string) (*pem.Block, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return block, nil
}

// generateRandomKID generates a random Key ID for JWKS entries.
func generateRandomKID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random key ID: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// base64URLEncode encodes bytes to base64 URL encoding without padding.
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// base64URLDecode decodes base64 URL encoded string.
func base64URLDecode(data string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(data)
}

// rsaPrivateKeyToJWK converts an RSA private key to JWK format.
func rsaPrivateKeyToJWK(key *rsa.PrivateKey, kid, alg, use string, certs []string) JWK {
	jwk := JWK{
		Kty: "RSA",
		Kid: kid,
		Alg: alg,
		Use: use,
		N:   base64URLEncode(key.N.Bytes()),
		E:   base64URLEncode(big.NewInt(int64(key.E)).Bytes()),
		X5c: certs,
	}

	// Add private key components
	jwk.D = base64URLEncode(key.D.Bytes())
	jwk.P = base64URLEncode(key.Primes[0].Bytes())
	jwk.Q = base64URLEncode(key.Primes[1].Bytes())
	jwk.Dp = base64URLEncode(key.Precomputed.Dp.Bytes())
	jwk.Dq = base64URLEncode(key.Precomputed.Dq.Bytes())
	jwk.Qi = base64URLEncode(key.Precomputed.Qinv.Bytes())

	return jwk
}

// ecPrivateKeyToJWK converts an EC private key to JWK format.
func ecPrivateKeyToJWK(key *ecdsa.PrivateKey, kid, alg, use string, certs []string) JWK {
	crv := ""
	switch key.Curve.Params().Name {
	case "P-256":
		crv = "P-256"
	case "P-384":
		crv = "P-384"
	case "P-521":
		crv = "P-521"
	default:
		crv = key.Curve.Params().Name
	}

	jwk := JWK{
		Kty: "EC",
		Kid: kid,
		Alg: alg,
		Use: use,
		Crv: crv,
		X:   base64URLEncode(key.X.Bytes()),
		Y:   base64URLEncode(key.Y.Bytes()),
		X5c: certs,
	}

	// Add private key component
	jwk.D = base64URLEncode(key.D.Bytes())

	return jwk
}

// createJWKS handles the common logic for creating a JWKS from the model data.
// This function is used by resources, data sources, and ephemeral resources.
func createJWKS(ctx context.Context, data *JWKSModel, diagnostics *diag.Diagnostics, operation string) {
	var jwks JWKS

	// If base JWKS is provided, use it as the initial set
	if !data.BaseJWKS.IsNull() {
		baseJWKSStr := data.BaseJWKS.ValueString()

		err := json.Unmarshal([]byte(baseJWKSStr), &jwks)
		if err != nil {
			diagnostics.AddError("Base JWKS Error", fmt.Sprintf("Unable to parse base JWKS: %s", err))
			return
		}
	} else {
		// Create a new JWKS if no base is provided
		jwks = JWKS{Keys: []JWK{}}
	}

	// Get keys from the model
	var keys []KeyEntry
	diagnostics.Append(data.Keys.ElementsAs(ctx, &keys, false)...)
	if diagnostics.HasError() {
		return
	}

	// Process each key entry
	for _, entry := range keys {
		// Decode the private key
		privateKeyBlock, err := decodePEMBlock(entry.PrivateKey.ValueString())
		if err != nil {
			diagnostics.AddError("Private Key Error", fmt.Sprintf("Unable to decode private key: %s", err))
			return
		}

		// Parse the private key
		var privateKey interface{}
		var parseErr error

		// Try PKCS8 first
		privateKey, parseErr = x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
		if parseErr != nil {
			// Try PKCS1 RSA
			rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
			if rsaErr != nil {
				// Try EC
				ecKey, ecErr := x509.ParseECPrivateKey(privateKeyBlock.Bytes)
				if ecErr != nil {
					diagnostics.AddError("Private Key Error",
						fmt.Sprintf("Unable to parse private key (tried PKCS8, PKCS1, and EC): %s", parseErr))
					return
				}
				privateKey = ecKey
			} else {
				privateKey = rsaKey
			}
		}

		// Process certificate chain
		var certChain []types.String
		diagnostics.Append(entry.CertificateChain.ElementsAs(ctx, &certChain, false)...)
		if diagnostics.HasError() {
			return
		}

		// Build x5c array with certificate and chain
		x5cCerts := []string{}

		// Add the main certificate first
		if !entry.Certificate.IsNull() && entry.Certificate.ValueString() != "" {
			certBlock, err := decodePEMBlock(entry.Certificate.ValueString())
			if err != nil {
				diagnostics.AddError("Certificate Error", fmt.Sprintf("Unable to decode certificate: %s", err))
				return
			}
			x5cCerts = append(x5cCerts, base64.StdEncoding.EncodeToString(certBlock.Bytes))
		}

		// Add certificate chain
		for _, certStr := range certChain {
			certBlock, err := decodePEMBlock(certStr.ValueString())
			if err != nil {
				diagnostics.AddError("Certificate Chain Error", fmt.Sprintf("Unable to decode certificate chain: %s", err))
				return
			}
			x5cCerts = append(x5cCerts, base64.StdEncoding.EncodeToString(certBlock.Bytes))
		}

		// Determine the key ID to use
		kid := entry.KeyID.ValueString()
		if kid == "" {
			generatedKID, err := generateRandomKID()
			if err != nil {
				diagnostics.AddError("Key ID Generation Error", fmt.Sprintf("Unable to generate key ID: %s", err))
				return
			}
			kid = generatedKID
			tflog.Debug(ctx, "Generated random key ID for entry", map[string]any{
				"key_id": kid,
			})
		}

		// Get algorithm and use
		alg := entry.Algorithm.ValueString()
		use := entry.Use.ValueString()

		// Convert to JWK based on key type
		var jwk JWK
		switch key := privateKey.(type) {
		case *rsa.PrivateKey:
			jwk = rsaPrivateKeyToJWK(key, kid, alg, use, x5cCerts)
		case *ecdsa.PrivateKey:
			jwk = ecPrivateKeyToJWK(key, kid, alg, use, x5cCerts)
		default:
			diagnostics.AddError("Unsupported Key Type",
				fmt.Sprintf("Private key type %T is not supported", privateKey))
			return
		}

		jwks.Keys = append(jwks.Keys, jwk)
	}

	// Marshal JWKS to JSON
	jwksJSON, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		diagnostics.AddError("JWKS Error", fmt.Sprintf("Unable to marshal JWKS to JSON: %s", err))
		return
	}

	data.JWKS = types.StringValue(string(jwksJSON))

	// Generate identifier based on the content
	data.Id = types.StringValue(fmt.Sprintf("jwks-%x", hashString(string(jwksJSON))))

	// Write logs using the tflog package
	tflog.Trace(ctx, operation+" a JWKS")
}

// jwkToPrivateKeyPEM converts a JWK to a PEM-encoded private key.
func jwkToPrivateKeyPEM(jwk JWK) (string, error) {
	var privateKey interface{}
	var err error

	switch jwk.Kty {
	case "RSA":
		// Decode RSA components
		n, err := base64URLDecode(jwk.N)
		if err != nil {
			return "", fmt.Errorf("failed to decode N: %w", err)
		}
		e, err := base64URLDecode(jwk.E)
		if err != nil {
			return "", fmt.Errorf("failed to decode E: %w", err)
		}

		// Build public key
		pubKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}

		// If D is present, it's a private key
		if jwk.D != "" {
			d, err := base64URLDecode(jwk.D)
			if err != nil {
				return "", fmt.Errorf("failed to decode D: %w", err)
			}
			p, err := base64URLDecode(jwk.P)
			if err != nil {
				return "", fmt.Errorf("failed to decode P: %w", err)
			}
			q, err := base64URLDecode(jwk.Q)
			if err != nil {
				return "", fmt.Errorf("failed to decode Q: %w", err)
			}

			rsaPrivKey := &rsa.PrivateKey{
				PublicKey: *pubKey,
				D:         new(big.Int).SetBytes(d),
				Primes:    []*big.Int{new(big.Int).SetBytes(p), new(big.Int).SetBytes(q)},
			}

			// Precompute values
			rsaPrivKey.Precompute()
			privateKey = rsaPrivKey
		} else {
			// Public key only
			privateKey = pubKey
		}

	case "EC":
		// Decode EC components
		x, err := base64URLDecode(jwk.X)
		if err != nil {
			return "", fmt.Errorf("failed to decode X: %w", err)
		}
		y, err := base64URLDecode(jwk.Y)
		if err != nil {
			return "", fmt.Errorf("failed to decode Y: %w", err)
		}

		// Determine curve
		var curve elliptic.Curve
		switch jwk.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return "", fmt.Errorf("unsupported curve: %s", jwk.Crv)
		}

		// Build public key
		pubKey := &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}

		// If D is present, it's a private key
		if jwk.D != "" {
			d, err := base64URLDecode(jwk.D)
			if err != nil {
				return "", fmt.Errorf("failed to decode D: %w", err)
			}

			privateKey = &ecdsa.PrivateKey{
				PublicKey: *pubKey,
				D:         new(big.Int).SetBytes(d),
			}
		} else {
			// Public key only
			privateKey = pubKey
		}

	default:
		return "", fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}

	// Marshal to PKCS8
	var keyBytes []byte
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		keyBytes, err = x509.MarshalPKCS8PrivateKey(key)
	case *ecdsa.PrivateKey:
		keyBytes, err = x509.MarshalPKCS8PrivateKey(key)
	case *rsa.PublicKey:
		keyBytes, err = x509.MarshalPKIXPublicKey(key)
	case *ecdsa.PublicKey:
		keyBytes, err = x509.MarshalPKIXPublicKey(key)
	default:
		return "", fmt.Errorf("unsupported key type for marshaling: %T", privateKey)
	}

	if err != nil {
		return "", fmt.Errorf("failed to marshal key: %w", err)
	}

	// Create PEM block
	blockType := "PRIVATE KEY"
	switch privateKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		blockType = "PUBLIC KEY"
	}

	pemBlock := &pem.Block{
		Type:  blockType,
		Bytes: keyBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

// jwkToCertificatesPEM converts the x5c field from a JWK to PEM-encoded certificates.
func jwkToCertificatesPEM(jwk JWK) ([]string, error) {
	certs := []string{}

	for _, certB64 := range jwk.X5c {
		certBytes, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode certificate: %w", err)
		}

		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		}

		certs = append(certs, string(pem.EncodeToMemory(pemBlock)))
	}

	return certs, nil
}
