package tlsutils

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"math/big"
	"time"
)

func resourceX509Crl() *schema.Resource {
	return &schema.Resource{
		Description:   "Generate x509 crl",
		CreateContext: resourceX509CrlCreate,
		ReadContext:   resourceX509CrlRead,
		DeleteContext: resourceX509CrlDelete,
		Schema: map[string]*schema.Schema{
			"private_key_pem": {
				Description: "private key in PEM format.",
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
			},
			"certificate_pem": {
				Description: "certificate in PEM format.",
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
			},
			"revocation_list": {
				Description: "revoked certificates in pem format.",
				Type:        schema.TypeList,
				Required:    true,
				ForceNew:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"crl_pem": {
				Description: "CRL in pem format.",
				Type:        schema.TypeString,
				Computed:    true,
			},
		},
	}
}

func resourceX509CrlCreate(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	privKey, _, err := parsePrivateKeyPEM([]byte(d.Get("private_key_pem").(string)))
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to parse private key PEM: %w", err))
	}

	cert, err := parsePEMCertificate([]byte(d.Get("certificate_pem").(string)))
	if err != nil {
		return diag.FromErr(fmt.Errorf("unable to parse certificate_pem: %w", err))
	}

	revocationList := []x509.RevocationListEntry{}
	for i, revocationCertPem := range d.Get("revocation_list").([]interface{}) {
		revocationCert, err := parsePEMCertificate([]byte(revocationCertPem.(string)))
		if err != nil {
			return diag.FromErr(fmt.Errorf("unable to parse revocation_list (element #%d): %w", i, err))
		}
		revocationList = append(revocationList, x509.RevocationListEntry{
			SerialNumber:   revocationCert.SerialNumber,
			RevocationTime: revocationCert.NotBefore,
		})
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		RevokedCertificateEntries: revocationList,
		Number:                    big.NewInt(time.Now().Unix()),
	}, cert, privKey.(crypto.Signer))
	if err != nil {
		return diag.FromErr(fmt.Errorf("unable to create crl: %w", err))
	}

	crlPem := string(pem.EncodeToMemory(&pem.Block{Type: PreambleCRL.String(), Bytes: crlBytes}))

	d.SetId(resourceX509GetHash(d))

	if err = d.Set("crl_pem", crlPem); err != nil {
		return diag.FromErr(fmt.Errorf("failed to save crl: %w", err))
	}

	return nil
}

func resourceX509CrlRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	if d.Id() != resourceX509GetHash(d) {
		return resourceX509CrlCreate(ctx, d, m)
	}
	return nil
}

func resourceX509CrlDelete(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	d.SetId("")

	return nil
}

func resourceX509GetHash(d *schema.ResourceData) string {
	idHash := sha1.New()
	idHash.Write([]byte(d.Get("private_key_pem").(string)))
	idHash.Write([]byte(d.Get("certificate_pem").(string)))
	for _, revocationCertPem := range d.Get("revocation_list").([]interface{}) {
		revocationCertPem := []byte(revocationCertPem.(string))
		idHash.Write(revocationCertPem)
	}
	hash := idHash.Sum([]byte{})
	result := make([]byte, base64.StdEncoding.EncodedLen(len(hash)))
	base64.StdEncoding.Encode(result, hash)
	return string(result)
}
