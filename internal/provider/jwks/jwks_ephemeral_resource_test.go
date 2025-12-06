// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jwks_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/mpieters3/terraform-provider-crypto/internal/provider"
	"github.com/mpieters3/terraform-provider-crypto/internal/provider/jwks"
)

func TestAccJWKSEphemeralResource(t *testing.T) {
	privateKey, cert, chainCert := jwks.GenerateJWKSTestCertAndKey(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactoriesWithEcho,
		Steps: []resource.TestStep{
			{
				Config: testAccJWKSEphemeralResourceConfig(privateKey, cert, chainCert),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownOutputValue("jwks_output", knownvalue.NotNull()),
				},
			},
		},
	})
}

func TestAccJWKSEphemeralResource_RSA(t *testing.T) {
	privateKey, cert, chainCert := jwks.GenerateJWKSTestRSACertAndKey(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactoriesWithEcho,
		Steps: []resource.TestStep{
			{
				Config: testAccJWKSEphemeralResourceConfigRSA(privateKey, cert, chainCert),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownOutputValue("jwks_rsa_output", knownvalue.NotNull()),
				},
			},
		},
	})
}

func testAccJWKSEphemeralResourceConfig(privateKey, cert, chainCert string) string {
	return fmt.Sprintf(`
ephemeral "crypto_jwks" "test" {
  keys = [
    {
      private_key       = %[1]q
      certificate       = %[2]q
      certificate_chain = [%[3]q]
      key_id            = "ephemeral-key-1"
      algorithm         = "ES256"
      use               = "sig"
    }
  ]
}

provider "echo" {
  data = ephemeral.crypto_jwks.test
}

resource "echo" "test" {}

output "jwks_output" {
  value     = echo.test.data.jwks
  sensitive = true
}
`, privateKey, cert, chainCert)
}

func testAccJWKSEphemeralResourceConfigRSA(privateKey, cert, chainCert string) string {
	return fmt.Sprintf(`
ephemeral "crypto_jwks" "test_rsa" {
  keys = [
    {
      private_key       = %[1]q
      certificate       = %[2]q
      certificate_chain = [%[3]q]
      key_id            = "ephemeral-rsa-key-1"
      algorithm         = "RS256"
      use               = "sig"
    }
  ]
}

provider "echo" {
  data = ephemeral.crypto_jwks.test_rsa
}

resource "echo" "test_rsa" {}

output "jwks_rsa_output" {
  value     = echo.test_rsa.data.jwks
  sensitive = true
}
`, privateKey, cert, chainCert)
}
