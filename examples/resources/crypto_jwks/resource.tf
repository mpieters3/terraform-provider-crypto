resource "crypto_jwks" "example" {
  keys = [
    {
      private_key       = file("${path.module}/ec-key.pem")
      certificate       = file("${path.module}/ec-cert.pem")
      certificate_chain = []
      key_id            = "ec-signing-key"
      algorithm         = "ES256"
      use               = "sig"
    },
    {
      private_key       = file("${path.module}/rsa-key.pem")
      certificate       = file("${path.module}/rsa-cert.pem")
      certificate_chain = []
      key_id            = "rsa-encryption-key"
      algorithm         = "RS256"
      use               = "enc"
    }
  ]
}

output "jwks_content" {
  value     = crypto_jwks.example.jwks
  sensitive = true
}

# Example with base JWKS
resource "crypto_jwks" "with_base" {
  base_jwks = file("${path.module}/base-jwks.json")

  keys = [
    {
      private_key = file("${path.module}/new-key.pem")
      key_id      = "new-key"
      algorithm   = "ES256"
      use         = "sig"
    }
  ]
}
