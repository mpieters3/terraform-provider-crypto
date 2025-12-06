data "crypto_jwks" "example" {
  jwks = file("${path.module}/jwks.json")
}

output "keys" {
  value     = data.crypto_jwks.example.keys
  sensitive = true
}

# Extract specific key information
output "key_ids" {
  value = [for key in data.crypto_jwks.example.keys : key.key_id]
}
