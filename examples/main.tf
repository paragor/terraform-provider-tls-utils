terraform {
  required_providers {
    tls = {
      source  = "hashicorp/tls"
      version = "~> 3.1.0"
    }
    tlsutils = {
      source  = "hashicorp.com/paragor/tlsutils"
      version = "= 0.2.0"
    }
  }
}

provider "tlsutils" {
}

resource "tls_private_key" "this" {
  algorithm = "ECDSA"
}

resource "tlsutils_encrypted_pem" "this" {
  pem = tls_private_key.this.private_key_pem
  password = "none"
}

output "encrypted_pem" {
  value = tlsutils_encrypted_pem.this.encrypted_pem
}
