package local

import (
	"crypto/sm2"
	"crypto"
	oconfig "github.com/hyperledger/fabric-ca/override/cfssl/config"
	"github.com/cloudflare/cfssl/certdb"
	"crypto/x509/pkix"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/signer"
	osigner "github.com/hyperledger/fabric-ca/override/cfssl/signer"
	"encoding/pem"
	"github.com/cloudflare/cfssl/log"
	"io"
	"crypto/rand"
	"math/big"
	"encoding/hex"
	"github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/pkg/errors"
	"net"
	"net/mail"
	"github.com/cloudflare/cfssl/signer/local"
	"encoding/asn1"
	"context"
	"time"
	"net/http"
	"github.com/cloudflare/cfssl/info"
	"bytes"
	ohelpers "github.com/hyperledger/fabric-ca/override/cfssl/helpers"
)

// Signer contains a signer that uses the standard library to
// support both ECDSA and RSA CA keys.
type Signer struct {
	ca         *sm2.Certificate
	priv       crypto.Signer
	policy     *oconfig.Signing
	sigAlgo    sm2.SignatureAlgorithm
	dbAccessor certdb.Accessor
}


// NewSigner creates a new Signer directly from a
// private key and certificate, with optional policy.
func NewSigner(priv crypto.Signer, cert *sm2.Certificate, sigAlgo sm2.SignatureAlgorithm, policy *oconfig.Signing) (*Signer, error) {
	if policy == nil {
		policy = &oconfig.Signing{
			Profiles: map[string]*oconfig.SigningProfile{},
			Default:  oconfig.DefaultConfig()}
	}

	//if !policy.Valid() {
	//	return nil, cferr.New(cferr.PolicyError, cferr.InvalidPolicy)
	//}

	return &Signer{
		ca:      cert,
		priv:    priv,
		sigAlgo: sigAlgo,
		policy:  policy,
	}, nil
}

// Sign signs a new certificate based on the PEM-encoded client
// certificate or certificate request with the signing profile,
// specified by profileName.
func (s *Signer) Sign(req signer.SignRequest) (cert []byte, err error) {
	profile, err := osigner.Profile(s, req.Profile)
	if err != nil {
		return
	}

	block, _ := pem.Decode([]byte(req.Request))
	if block == nil {
		return nil, cferr.New(cferr.CSRError, cferr.DecodeFailed)
	}

	if block.Type != "NEW CERTIFICATE REQUEST" && block.Type != "CERTIFICATE REQUEST" {
		return nil, cferr.Wrap(cferr.CSRError,
			cferr.BadRequest, errors.New("not a csr"))
	}

	csrTemplate, err := osigner.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Copy out only the fields from the CSR authorized by policy.
	safeTemplate := sm2.Certificate{}
	// If the profile contains no explicit whitelist, assume that all fields
	// should be copied from the CSR.
	if profile.CSRWhitelist == nil {
		safeTemplate = *csrTemplate
	} else {
		if profile.CSRWhitelist.Subject {
			safeTemplate.Subject = csrTemplate.Subject
		}
		if profile.CSRWhitelist.PublicKeyAlgorithm {
			safeTemplate.PublicKeyAlgorithm = csrTemplate.PublicKeyAlgorithm
		}
		if profile.CSRWhitelist.PublicKey {
			safeTemplate.PublicKey = csrTemplate.PublicKey
		}
		if profile.CSRWhitelist.SignatureAlgorithm {
			safeTemplate.SignatureAlgorithm = csrTemplate.SignatureAlgorithm
		}
		if profile.CSRWhitelist.DNSNames {
			safeTemplate.DNSNames = csrTemplate.DNSNames
		}
		if profile.CSRWhitelist.IPAddresses {
			safeTemplate.IPAddresses = csrTemplate.IPAddresses
		}
		if profile.CSRWhitelist.EmailAddresses {
			safeTemplate.EmailAddresses = csrTemplate.EmailAddresses
		}
	}

	if req.CRLOverride != "" {
		safeTemplate.CRLDistributionPoints = []string{req.CRLOverride}
	}

	if safeTemplate.IsCA {
		if !profile.CAConstraint.IsCA {
			log.Error("local signer policy disallows issuing CA certificate")
			return nil, cferr.New(cferr.PolicyError, cferr.InvalidRequest)
		}

		if s.ca != nil && s.ca.MaxPathLen > 0 {
			if safeTemplate.MaxPathLen >= s.ca.MaxPathLen {
				log.Error("local signer certificate disallows CA MaxPathLen extending")
				// do not sign a cert with pathlen > current
				return nil, cferr.New(cferr.PolicyError, cferr.InvalidRequest)
			}
		} else if s.ca != nil && s.ca.MaxPathLen == 0 && s.ca.MaxPathLenZero {
			log.Error("local signer certificate disallows issuing CA certificate")
			// signer has pathlen of 0, do not sign more intermediate CAs
			return nil, cferr.New(cferr.PolicyError, cferr.InvalidRequest)
		}
	}

	OverrideHosts(&safeTemplate, req.Hosts)
	safeTemplate.Subject = local.PopulateSubjectFromCSR(req.Subject, safeTemplate.Subject)

	// If there is a whitelist, ensure that both the Common Name and SAN DNSNames match
	if profile.NameWhitelist != nil {
		if safeTemplate.Subject.CommonName != "" {
			if profile.NameWhitelist.Find([]byte(safeTemplate.Subject.CommonName)) == nil {
				return nil, cferr.New(cferr.PolicyError, cferr.UnmatchedWhitelist)
			}
		}
		for _, name := range safeTemplate.DNSNames {
			if profile.NameWhitelist.Find([]byte(name)) == nil {
				return nil, cferr.New(cferr.PolicyError, cferr.UnmatchedWhitelist)
			}
		}
		for _, name := range safeTemplate.EmailAddresses {
			if profile.NameWhitelist.Find([]byte(name)) == nil {
				return nil, cferr.New(cferr.PolicyError, cferr.UnmatchedWhitelist)
			}
		}
	}

	if profile.ClientProvidesSerialNumbers {
		if req.Serial == nil {
			return nil, cferr.New(cferr.CertificateError, cferr.MissingSerial)
		}
		safeTemplate.SerialNumber = req.Serial
	} else {
		// RFC 5280 4.1.2.2:
		// Certificate users MUST be able to handle serialNumber
		// values up to 20 octets.  Conforming CAs MUST NOT use
		// serialNumber values longer than 20 octets.
		//
		// If CFSSL is providing the serial numbers, it makes
		// sense to use the max supported size.
		serialNumber := make([]byte, 20)
		_, err = io.ReadFull(rand.Reader, serialNumber)
		if err != nil {
			return nil, cferr.Wrap(cferr.CertificateError, cferr.Unknown, err)
		}

		// SetBytes interprets buf as the bytes of a big-endian
		// unsigned integer. The leading byte should be masked
		// off to ensure it isn't negative.
		serialNumber[0] &= 0x7F

		safeTemplate.SerialNumber = new(big.Int).SetBytes(serialNumber)
	}

	if len(req.Extensions) > 0 {
		for _, ext := range req.Extensions {
			oid := asn1.ObjectIdentifier(ext.ID)
			if !profile.ExtensionWhitelist[oid.String()] {
				return nil, cferr.New(cferr.CertificateError, cferr.InvalidRequest)
			}

			rawValue, err := hex.DecodeString(ext.Value)
			if err != nil {
				return nil, cferr.Wrap(cferr.CertificateError, cferr.InvalidRequest, err)
			}

			safeTemplate.ExtraExtensions = append(safeTemplate.ExtraExtensions, pkix.Extension{
				Id:       oid,
				Critical: ext.Critical,
				Value:    rawValue,
			})
		}
	}

	var certTBS = safeTemplate

	if len(profile.CTLogServers) > 0 {
		// Add a poison extension which prevents validation
		var poisonExtension = pkix.Extension{Id: signer.CTPoisonOID, Critical: true, Value: []byte{0x05, 0x00}}
		var poisonedPreCert = certTBS
		poisonedPreCert.ExtraExtensions = append(safeTemplate.ExtraExtensions, poisonExtension)
		cert, err = s.sign(&poisonedPreCert, profile, req.NotBefore, req.NotAfter)
		if err != nil {
			return
		}

		derCert, _ := pem.Decode(cert)
		prechain := []ct.ASN1Cert{{Data: derCert.Bytes}, {Data: s.ca.Raw}}
		var sctList []ct.SignedCertificateTimestamp

		for _, server := range profile.CTLogServers {
			log.Infof("submitting poisoned precertificate to %s", server)
			ctclient, err := client.New(server, nil, jsonclient.Options{})
			if err != nil {
				return nil, cferr.Wrap(cferr.CTError, cferr.PrecertSubmissionFailed, err)
			}
			var resp *ct.SignedCertificateTimestamp
			ctx := context.Background()
			resp, err = ctclient.AddPreChain(ctx, prechain)
			if err != nil {
				return nil, cferr.Wrap(cferr.CTError, cferr.PrecertSubmissionFailed, err)
			}
			sctList = append(sctList, *resp)
		}

		var serializedSCTList []byte
		serializedSCTList, err = helpers.SerializeSCTList(sctList)
		if err != nil {
			return nil, cferr.Wrap(cferr.CTError, cferr.Unknown, err)
		}

		// Serialize again as an octet string before embedding
		serializedSCTList, err = asn1.Marshal(serializedSCTList)
		if err != nil {
			return nil, cferr.Wrap(cferr.CTError, cferr.Unknown, err)
		}

		var SCTListExtension = pkix.Extension{Id: signer.SCTListOID, Critical: false, Value: serializedSCTList}
		certTBS.ExtraExtensions = append(certTBS.ExtraExtensions, SCTListExtension)
	}
	var signedCert []byte
	signedCert, err = s.sign(&certTBS, profile, req.NotBefore, req.NotAfter)
	if err != nil {
		return nil, err
	}

	// Get the AKI from signedCert.  This is required to support Go 1.9+.
	// In prior versions of Go, x509.CreateCertificate updated the
	// AuthorityKeyId of certTBS.
	parsedCert, _ := ohelpers.ParseCertificatePEM(signedCert)

	if s.dbAccessor != nil {
		var certRecord = certdb.CertificateRecord{
			Serial: certTBS.SerialNumber.String(),
			// this relies on the specific behavior of x509.CreateCertificate
			// which sets the AuthorityKeyId from the signer's SubjectKeyId
			// FIXME: chucuoi!!!!
			AKI:     hex.EncodeToString(parsedCert.AuthorityKeyId),
			CALabel: req.Label,
			Status:  "good",
			Expiry:  certTBS.NotAfter,
			PEM:     string(signedCert),
		}

		err = s.dbAccessor.InsertCertificate(certRecord)
		if err != nil {
			return nil, err
		}
		log.Debug("saved certificate with serial number ", certTBS.SerialNumber)
	}

	return signedCert, nil
}

func (s *Signer) sign(template *sm2.Certificate, profile *oconfig.SigningProfile, notBefore time.Time, notAfter time.Time) (cert []byte, err error) {
	var distPoints = template.CRLDistributionPoints
	if distPoints != nil && len(distPoints) > 0 {
		template.CRLDistributionPoints = distPoints
	}
	err = osigner.FillTemplate(template, s.policy.Default, profile, notBefore, notAfter)
	if err != nil {
		return nil, err
	}

	var initRoot bool
	if s.ca == nil {
		if !template.IsCA {
			err = cferr.New(cferr.PolicyError, cferr.InvalidRequest)
			return
		}
		template.DNSNames = nil
		template.EmailAddresses = nil
		s.ca = template
		initRoot = true
	}

	derBytes, err := sm2.CreateCertificate(rand.Reader, template, s.ca, template.PublicKey, s.priv)
	if err != nil {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.Unknown, err)
	}
	if initRoot {
		s.ca, err = sm2.ParseCertificate(derBytes)
		if err != nil {
			return nil, cferr.Wrap(cferr.CertificateError, cferr.ParseFailed, err)
		}
	}

	cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	log.Infof("signed certificate with serial number %d", template.SerialNumber)
	return
}

// OverrideHosts fills template's IPAddresses, EmailAddresses, and DNSNames with the
// content of hosts, if it is not nil.
func OverrideHosts(template *sm2.Certificate, hosts []string) {
	if hosts != nil {
		template.IPAddresses = []net.IP{}
		template.EmailAddresses = []string{}
		template.DNSNames = []string{}
	}

	for i := range hosts {
		if ip := net.ParseIP(hosts[i]); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(hosts[i]); err == nil && email != nil {
			template.EmailAddresses = append(template.EmailAddresses, email.Address)
		} else {
			template.DNSNames = append(template.DNSNames, hosts[i])
		}
	}

}

// Certificate returns the signer's certificate.
func (s *Signer) Certificate(label, profile string) (*sm2.Certificate, error) {
	cert := *s.ca
	return &cert, nil
}

// SigAlgo returns the RSA signer's signature algorithm.
func (s *Signer) SigAlgo() sm2.SignatureAlgorithm {
	return s.sigAlgo
}

// Info return a populated info.Resp struct or an error.
func (s *Signer) Info(req info.Req) (resp *info.Resp, err error) {
	cert, err := s.Certificate(req.Label, req.Profile)
	if err != nil {
		return
	}

	profile, err := osigner.Profile(s, req.Profile)
	if err != nil {
		return
	}

	resp = new(info.Resp)
	if cert.Raw != nil {
		resp.Certificate = string(bytes.TrimSpace(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
	}
	resp.Usage = profile.Usage
	resp.ExpiryString = profile.ExpiryString

	return
}

// Policy returns the signer's policy.
func (s *Signer) Policy() *oconfig.Signing {
	return s.policy
}

// SetDBAccessor sets the signers' cert db accessor
func (s *Signer) SetDBAccessor(dba certdb.Accessor) {
	s.dbAccessor = dba
}

// GetDBAccessor returns the signers' cert db accessor
func (s *Signer) GetDBAccessor() certdb.Accessor {
	return s.dbAccessor
}

// SetPolicy sets the signer's signature policy.
func (s *Signer) SetPolicy(policy *oconfig.Signing) {
	s.policy = policy
}

// SetReqModifier does nothing for local
func (s *Signer) SetReqModifier(func(*http.Request, []byte)) {
	// noop
}
