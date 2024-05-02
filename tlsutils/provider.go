package tlsutils

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Provider -
func Provider() *schema.Provider {
	return &schema.Provider{
		ResourcesMap: map[string]*schema.Resource{
			"tlsutils_x509_crl": resourceX509Crl(),
		},
		DataSourcesMap: map[string]*schema.Resource{},
	}
}
