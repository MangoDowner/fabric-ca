package helpers

import (
	"crypto"
	"crypto/sm2"
	"bytes"
	"github.com/cloudflare/cfssl/log"
	cferr "github.com/cloudflare/cfssl/errors"

	"errors"
	"encoding/pem"
)

// SignerAlgo returns an sm2 signature algorithm from a crypto.Signer.
func SignerAlgo(priv crypto.Signer) sm2.SignatureAlgorithm {
	switch pub := priv.Public().(type) {
	case *sm2.PublicKey:
		switch pub.Curve {
		case sm2.P256Sm2():
			// FIXME: 只是改这个有用么...
			// 感觉没啥用，如果使用ECDSAWithSHA256也会返回"ecdsa-with-SHA256"
			return sm2.SM2WithSM3
		default:
			return sm2.SM2WithSHA1
		}
	default:
		return sm2.UnknownSignatureAlgorithm
	}
}

// ParseCertificatePEM parses and returns a PEM-encoded certificate,
// can handle PEM encoded PKCS #7 structures.
func ParseCertificatePEM(certPEM []byte) (*sm2.Certificate, error) {
	certPEM = bytes.TrimSpace(certPEM)
	cert, rest, err := ParseOneCertificateFromPEM(certPEM)
	if err != nil {
		// Log the actual parsing error but throw a default parse error message.
		log.Debugf("Certificate parsing error: %v", err)
		return nil, cferr.New(cferr.CertificateError, cferr.ParseFailed)
	} else if cert == nil {
		return nil, cferr.New(cferr.CertificateError, cferr.DecodeFailed)
	} else if len(rest) > 0 {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.ParseFailed, errors.New("the PEM file should contain only one object"))
	} else if len(cert) > 1 {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.ParseFailed, errors.New("the PKCS7 object in the PEM file should contain only one certificate"))
	}
	return cert[0], nil
}

// ParseOneCertificateFromPEM attempts to parse one PEM encoded certificate object,
// either a raw x509 certificate or a PKCS #7 structure possibly containing
// multiple certificates, from the top of certsPEM, which itself may
// contain multiple PEM encoded certificate objects.
func ParseOneCertificateFromPEM(certsPEM []byte) ([]*sm2.Certificate, []byte, error) {
	block, rest := pem.Decode(certsPEM)
	if block == nil {
		return nil, rest, nil
	}

	cert, err := sm2.ParseCertificate(block.Bytes)
	if err != nil {
		return  []*sm2.Certificate{}, []byte{}, err
	}
	var certs = []*sm2.Certificate{cert}
	return certs, rest, nil
}
