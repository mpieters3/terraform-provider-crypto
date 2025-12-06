ephemeral "crypto_jwks" "example" {
  keys = [
    {
      private_key       = file("${path.module}/ec-key.pem")
      certificate       = file("${path.module}/ec-cert.pem")
      certificate_chain = []
      key_id            = "ephemeral-signing-key"
      algorithm         = "ES256"
      use               = "sig"
    }
  ]
}

output "jwks_content" {
  value     = ephemeral.crypto_jwks.example.jwks
  sensitive = true
}
