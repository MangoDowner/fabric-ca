package csr

import (
	"github.com/cloudflare/cfssl/csr"
)
const (
	curveP256 = 256
)
// NewGMKeyRequest returns a default BasicKeyRequest.
func NewGMKeyRequest() *csr.BasicKeyRequest {
	return &csr.BasicKeyRequest{"gmsm2", curveP256}
}
