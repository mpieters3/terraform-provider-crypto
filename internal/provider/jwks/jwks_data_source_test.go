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

func TestAccJWKSDataSource(t *testing.T) {
	privateKey, cert, chainCert := jwks.GenerateJWKSTestCertAndKey(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccJWKSDataSourceConfig(privateKey, cert, chainCert),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.crypto_jwks.test", tfjsonpath.New("keys"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("data.crypto_jwks.test", tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
		},
	})
}

func TestAccJWKSDataSource_MultipleKeys(t *testing.T) {
	privateKey1, cert1, chainCert1 := jwks.GenerateJWKSTestCertAndKey(t)
	privateKey2, cert2, chainCert2 := jwks.GenerateJWKSTestRSACertAndKey(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing with multiple keys
			{
				Config: testAccJWKSDataSourceConfigMultiple(privateKey1, cert1, chainCert1, privateKey2, cert2, chainCert2),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.crypto_jwks.test_multiple", tfjsonpath.New("keys"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("data.crypto_jwks.test_multiple", tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
		},
	})
}

func testAccJWKSDataSourceConfig(privateKey, cert, chainCert string) string {
	return fmt.Sprintf(`
resource "crypto_jwks" "source" {
  keys = [
    {
      private_key       = %[1]q
      certificate       = %[2]q
      certificate_chain = [%[3]q]
      key_id            = "test-key-1"
      algorithm         = "ES256"
      use               = "sig"
    }
  ]
}

data "crypto_jwks" "test" {
  jwks = crypto_jwks.source.jwks
}
`, privateKey, cert, chainCert)
}

func testAccJWKSDataSourceConfigMultiple(privateKey1, cert1, chainCert1, privateKey2, cert2, chainCert2 string) string {
	return fmt.Sprintf(`
resource "crypto_jwks" "source_multiple" {
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

data "crypto_jwks" "test_multiple" {
  jwks = crypto_jwks.source_multiple.jwks
}
`, privateKey1, cert1, chainCert1, privateKey2, cert2, chainCert2)
}
