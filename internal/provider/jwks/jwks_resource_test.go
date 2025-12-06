// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jwks_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/mpieters3/terraform-provider-crypto/internal/provider"
	"github.com/mpieters3/terraform-provider-crypto/internal/provider/jwks"
)

func TestAccJWKSResource(t *testing.T) {
	privateKey, cert, chainCert := jwks.GenerateJWKSTestCertAndKey(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccJWKSResourceConfig(privateKey, cert, chainCert),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("crypto_jwks.test", tfjsonpath.New("jwks"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("crypto_jwks.test", tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
			// Update testing
			{
				Config: testAccJWKSResourceConfigWithKID(privateKey, cert, chainCert, "test-key-1"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("crypto_jwks.test", tfjsonpath.New("jwks"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("crypto_jwks.test", tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
		},
	})
}

func TestAccJWKSResource_RSA(t *testing.T) {
	privateKey, cert, chainCert := jwks.GenerateJWKSTestRSACertAndKey(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing with RSA key
			{
				Config: testAccJWKSResourceConfigRSA(privateKey, cert, chainCert),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("crypto_jwks.test_rsa", tfjsonpath.New("jwks"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("crypto_jwks.test_rsa", tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
		},
	})
}

func TestAccJWKSResource_MultipleKeys(t *testing.T) {
	privateKey1, cert1, chainCert1 := jwks.GenerateJWKSTestCertAndKey(t)
	privateKey2, cert2, chainCert2 := jwks.GenerateJWKSTestRSACertAndKey(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with multiple keys
			{
				Config: testAccJWKSResourceConfigMultiple(privateKey1, cert1, chainCert1, privateKey2, cert2, chainCert2),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("crypto_jwks.test_multiple", tfjsonpath.New("jwks"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("crypto_jwks.test_multiple", tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
		},
	})
}

func testAccJWKSResourceConfig(privateKey, cert, chainCert string) string {
	return fmt.Sprintf(`
resource "crypto_jwks" "test" {
  keys = [
    {
      private_key       = %[1]q
      certificate       = %[2]q
      certificate_chain = [%[3]q]
      algorithm         = "ES256"
      use               = "sig"
    }
  ]
}
`, privateKey, cert, chainCert)
}

func testAccJWKSResourceConfigWithKID(privateKey, cert, chainCert, kid string) string {
	return fmt.Sprintf(`
resource "crypto_jwks" "test" {
  keys = [
    {
      private_key       = %[1]q
      certificate       = %[2]q
      certificate_chain = [%[3]q]
      key_id            = %[4]q
      algorithm         = "ES256"
      use               = "sig"
    }
  ]
}
`, privateKey, cert, chainCert, kid)
}

func testAccJWKSResourceConfigRSA(privateKey, cert, chainCert string) string {
	return fmt.Sprintf(`
resource "crypto_jwks" "test_rsa" {
  keys = [
    {
      private_key       = %[1]q
      certificate       = %[2]q
      certificate_chain = [%[3]q]
      algorithm         = "RS256"
      use               = "sig"
    }
  ]
}
`, privateKey, cert, chainCert)
}

func testAccJWKSResourceConfigMultiple(privateKey1, cert1, chainCert1, privateKey2, cert2, chainCert2 string) string {
	return fmt.Sprintf(`
resource "crypto_jwks" "test_multiple" {
  keys = [
    {
      private_key       = %[1]q
      certificate       = %[2]q
      certificate_chain = [%[3]q]
      key_id            = "ec-key-1"
      algorithm         = "ES256"
      use               = "sig"
    },
    {
      private_key       = %[4]q
      certificate       = %[5]q
      certificate_chain = [%[6]q]
      key_id            = "rsa-key-1"
      algorithm         = "RS256"
      use               = "enc"
    }
  ]
}
`, privateKey1, cert1, chainCert1, privateKey2, cert2, chainCert2)
}
