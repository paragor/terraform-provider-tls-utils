package tlsutils

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceEncryptedPem() *schema.Resource {
	return &schema.Resource{
		Description:   "Encrypt pem private key",
		CreateContext: resourceEncryptedPemCreate,
		ReadContext:   resourceEncryptedPemRead,
		DeleteContext: resourceEncryptedPemDelete,
		Schema: map[string]*schema.Schema{
			"pem": {
				Description: "private_key; in PEM format.",
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
			},
			"password": {
				Description: "Password to secure trust store. Defaults to empty string.",
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
			},
			"encrypted_pem": {
				Description: "Encrypted private key; in PEM format.",
				Type:        schema.TypeString,
				Computed:    true,
			},
		},
	}
}

func resourceEncryptedPemCreate(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	block, _ := pem.Decode([]byte(d.Get("pem").(string)))
	if block == nil {
		return diag.Errorf("error decoding PEM block")
	}

	result, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(d.Get("password").(string)), x509.PEMCipherAES128)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error encrypted PEM block: %w", err))
	}
	buffer := bytes.NewBuffer(nil)
	if err := pem.Encode(buffer, result); err != nil {
		return diag.FromErr(fmt.Errorf("error during encoding encrypted PEM block: %w", err))
	}

	idHash := crypto.SHA1.New()
	idHash.Write(buffer.Bytes())

	id := hex.EncodeToString(idHash.Sum([]byte{}))
	d.SetId(id)

	if err = d.Set("encrypted_pem", buffer.String()); err != nil {
		return diag.FromErr(fmt.Errorf("failed to save encrypted PEM block: %w", err))
	}

	return nil
}

func resourceEncryptedPemRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return resourceEncryptedPemCreate(ctx, d, m)
}

func resourceEncryptedPemDelete(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	d.SetId("")

	return diags
}
