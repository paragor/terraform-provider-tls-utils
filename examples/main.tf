terraform {
  required_providers {
    tls = {
      source  = "hashicorp/tls"
      version = "4.0.5"
    }
    tlsutils = {
      source  = "hashicorp.com/paragor/tlsutils"
      version = "= 0.3.0"
    }
  }
}

provider "tlsutils" {
}

resource "tlsutils_x509_crl" "one" {
  certificate_pem = tls_self_signed_cert.ca.cert_pem
  private_key_pem = tls_private_key.ca.private_key_pem
  revocation_list = [
    tls_locally_signed_cert.cert.cert_pem
  ]
}

output "one" {
  value = tlsutils_x509_crl.one.crl_pem
}

resource "tlsutils_x509_crl" "empty" {
  certificate_pem = tls_self_signed_cert.ca.cert_pem
  private_key_pem = tls_private_key.ca.private_key_pem
  revocation_list = []
}

output "empty" {
  value = tlsutils_x509_crl.empty.crl_pem
}

resource "tls_private_key" "ca" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem = tls_private_key.ca.private_key_pem
  subject {
    common_name  = "paragor.ru"
    organization = "T. Paragor Inc."
  }

  validity_period_hours = 10 * 365 * 24

  is_ca_certificate = true
  allowed_uses      = ["cert_signing", "crl_signing"]
}

resource "tls_private_key" "cert" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_cert_request" "cert" {
  private_key_pem = tls_private_key.cert.private_key_pem
  subject {
    common_name  = "cert.paragor.ru"
    organization = "T. Paragor Inc."
  }
}

resource "tls_locally_signed_cert" "cert" {
  cert_request_pem   = tls_cert_request.cert.cert_request_pem
  ca_private_key_pem = tls_private_key.ca.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.ca.cert_pem

  validity_period_hours = 1 * 365 * 24

  is_ca_certificate = false
  allowed_uses      = ["digital_signature", "client_auth", "key_agreement", "key_encipherment"]
}
