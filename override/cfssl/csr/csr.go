package csr

import (
	"crypto"
	ohelpers "github.com/hyperledger/fabric-ca/override/cfssl/helpers"
	"net"
	"net/mail"
	"crypto/rand"
	"github.com/cloudflare/cfssl/log"
	"encoding/pem"
	"github.com/cloudflare/cfssl/csr"
	"github.com/tjfoc/gmsm/sm2"
	cferr "github.com/cloudflare/cfssl/errors"
	"encoding/asn1"
	"crypto/x509/pkix"
)

// Generate creates a new CSR from a CertificateRequest structure and
// an existing key. The KeyRequest field is ignored.
func Generate(priv crypto.Signer, req *csr.CertificateRequest) (csr []byte, err error) {
	sigAlgo := ohelpers.SignerAlgo(priv)
	if sigAlgo == sm2.UnknownSignatureAlgorithm {
		return nil, cferr.New(cferr.PrivateKeyError, cferr.Unavailable)
	}

	var tpl = sm2.CertificateRequest{
		PublicKey:          priv.Public(), //FIXED: 指定的PublicKey类型，及*sm2.PublicKey
		Subject:            req.Name(),
		SignatureAlgorithm: sigAlgo,
	}

	for i := range req.Hosts {
		if ip := net.ParseIP(req.Hosts[i]); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(req.Hosts[i]); err == nil && email != nil {
			tpl.EmailAddresses = append(tpl.EmailAddresses, email.Address)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, req.Hosts[i])
		}
	}

	if req.CA != nil {
		err = appendCAInfoToCSR(req.CA, &tpl)
		if err != nil {
			err = cferr.Wrap(cferr.CSRError, cferr.GenerationFailed, err)
			return
		}
	}

	csr, err = sm2.CreateCertificateRequest(rand.Reader, &tpl, priv)
	if err != nil {
		log.Errorf("failed to generate a CSR: %v", err)
		err = cferr.Wrap(cferr.CSRError, cferr.BadRequest, err)
		return
	}
	block := pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}

	log.Info("encoded CSR")
	csr = pem.EncodeToMemory(&block)
	return
}

//appendCAInfoToCSR将CAConfig基本限制(BasicConstraints)扩展到CSR
func appendCAInfoToCSR(reqConf *csr.CAConfig, csrReq *sm2.CertificateRequest) error {
	pathlen := reqConf.PathLength
	if pathlen == 0 && !reqConf.PathLenZero {
		pathlen = -1
	}
	val, err := asn1.Marshal(csr.BasicConstraints{true, pathlen})

	if err != nil {
		return err
	}
	//FIXME: Red line??
	csrReq.ExtraExtensions = []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
			Value:    val,
			Critical: true,
		},
	}

	return nil
}