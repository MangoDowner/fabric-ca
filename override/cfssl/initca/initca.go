// Package initca contains code to initialise a certificate authority,
// generating a new root key and certificate.
package initca

import (
	"crypto"
	"time"

	"github.com/cloudflare/cfssl/csr"
	ocsr "github.com/hyperledger/fabric-ca/override/cfssl/csr"
	olocal "github.com/hyperledger/fabric-ca/override/cfssl/signer/local"
	osigner "github.com/hyperledger/fabric-ca/override/cfssl/signer"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/helpers"
	oconfig "github.com/hyperledger/fabric-ca/override/cfssl/config"
	"github.com/cloudflare/cfssl/config"
)

// NewFromSigner creates a new root certificate from a crypto.Signer.
func NewFromSigner(req *csr.CertificateRequest, priv crypto.Signer) (cert, csrPEM []byte, err error) {
	policy := CAPolicy()
	if req.CA != nil {
		if req.CA.Expiry != "" {
			policy.Default.ExpiryString = req.CA.Expiry
			policy.Default.Expiry, err = time.ParseDuration(req.CA.Expiry)
			if err != nil {
				return nil, nil, err
			}
		}

		policy.Default.CAConstraint.MaxPathLen = req.CA.PathLength
		if req.CA.PathLength != 0 && req.CA.PathLenZero == true {
			log.Infof("ignore invalid 'pathlenzero' value")
		} else {
			policy.Default.CAConstraint.MaxPathLenZero = req.CA.PathLenZero
		}
	}

	csrPEM, err = ocsr.Generate(priv, req)
	if err != nil {
		return nil, nil, err
	}
	//TODO: branch here!
	s, err := olocal.NewSigner(priv, nil, osigner.DefaultSigAlgo(priv), policy)
	if err != nil {
		log.Errorf("failed to create signer: %v", err)
		return
	}

	signReq := signer.SignRequest{Request: string(csrPEM)}
	cert, err = s.Sign(signReq)
	return
}

// CAPolicy contains the CA issuing policy as default policy.
var CAPolicy = func() *oconfig.Signing {
	return &oconfig.Signing{
		Default: &oconfig.SigningProfile{
			Usage:        []string{"cert sign", "crl sign"},
			ExpiryString: "43800h",
			Expiry:       5 * helpers.OneYear,
			CAConstraint: config.CAConstraint{IsCA: true},
		},
	}
}
