package signer

import (
	"crypto"
	"crypto/sm2"
	"github.com/cloudflare/cfssl/csr"
	cferr "github.com/cloudflare/cfssl/errors"
	"encoding/asn1"
	"errors"
	"github.com/cloudflare/cfssl/config"
	oconfig "github.com/hyperledger/fabric-ca/override/cfssl/config"
	"time"
	"crypto/sha1"
	"crypto/x509/pkix"
	"github.com/cloudflare/cfssl/info"
	"github.com/cloudflare/cfssl/certdb"
	"net/http"
	"github.com/cloudflare/cfssl/signer"
)

// A Signer contains a CA's certificate and private key for signing
// certificates, a Signing policy to refer to and a SignatureAlgorithm.
type Signer interface {
	Info(info.Req) (*info.Resp, error)
	Policy() *oconfig.Signing
	SetDBAccessor(certdb.Accessor)
	GetDBAccessor() certdb.Accessor
	SetPolicy(*oconfig.Signing)
	SigAlgo() sm2.SignatureAlgorithm
	Sign(req signer.SignRequest) (cert []byte, err error)
	SetReqModifier(func(*http.Request, []byte))
}

// DefaultSigAlgo returns an appropriate X.509 signature algorithm given
// the CA's private key.
// DefaultSigAlgo returns an appropriate X.509 signature algorithm given
// the CA's private key.
func DefaultSigAlgo(priv crypto.Signer) sm2.SignatureAlgorithm {
	pub := priv.Public()
	switch pub := pub.(type) {
	case *sm2.PublicKey:
		switch pub.Curve {
		case sm2.P256Sm2():
			return sm2.SM2WithSM3
		default:
			return sm2.SM2WithSHA1
		}
	default:
		return sm2.UnknownSignatureAlgorithm
	}
}

// Profile gets the specific profile from the signer
func Profile(s Signer, profile string) (*oconfig.SigningProfile, error) {
	var p *oconfig.SigningProfile
	policy := s.Policy()
	if policy != nil && policy.Profiles != nil && profile != "" {
		p = policy.Profiles[profile]
	}

	if p == nil && policy != nil {
		p = policy.Default
	}

	if p == nil {
		return nil, cferr.Wrap(cferr.APIClientError, cferr.ClientHTTPError, errors.New("profile must not be nil"))
	}
	return p, nil
}

// ParseCertificateRequest takes an incoming certificate request and
// builds a certificate template from it.
func ParseCertificateRequest(csrBytes []byte) (template *sm2.Certificate, err error) {
	csrv, err := sm2.ParseCertificateRequest(csrBytes)
	if err != nil {
		err = cferr.Wrap(cferr.CSRError, cferr.ParseFailed, err)
		return
	}

	err = csrv.CheckSignature()
	if err != nil {
		err = cferr.Wrap(cferr.CSRError, cferr.KeyMismatch, err)
		return
	}

	template = &sm2.Certificate{
		Subject:            csrv.Subject,
		PublicKeyAlgorithm: csrv.PublicKeyAlgorithm,
		PublicKey:          csrv.PublicKey,
		SignatureAlgorithm: csrv.SignatureAlgorithm,
		DNSNames:           csrv.DNSNames,
		IPAddresses:        csrv.IPAddresses,
		EmailAddresses:     csrv.EmailAddresses,
	}

	for _, val := range csrv.Extensions {
		// Check the CSR for the X.509 BasicConstraints (RFC 5280, 4.2.1.9)
		// extension and append to template if necessary
		if val.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19}) {
			var constraints csr.BasicConstraints
			var rest []byte

			if rest, err = asn1.Unmarshal(val.Value, &constraints); err != nil {
				return nil, cferr.Wrap(cferr.CSRError, cferr.ParseFailed, err)
			} else if len(rest) != 0 {
				return nil, cferr.Wrap(cferr.CSRError, cferr.ParseFailed, errors.New("x509: trailing data after X.509 BasicConstraints"))
			}
			template.BasicConstraintsValid = true
			template.IsCA = constraints.IsCA
			template.MaxPathLen = constraints.MaxPathLen
			template.MaxPathLenZero = template.MaxPathLen == 0
		}
	}

	return
}

// FillTemplate is a utility function that tries to load as much of
// the certificate template as possible from the profiles and current
// template. It fills in the key uses, expiration, revocation URLs
// and SKI.
func FillTemplate(template *sm2.Certificate, defaultProfile, profile *oconfig.SigningProfile, notBefore time.Time, notAfter time.Time) error {
	ski, err := ComputeSKI(template)
	if err != nil {
		return err
	}

	var (
		eku             []sm2.ExtKeyUsage
		ku              sm2.KeyUsage
		backdate        time.Duration
		expiry          time.Duration
		crlURL, ocspURL string
		issuerURL       = profile.IssuerURL
	)

	// The third value returned from Usages is a list of unknown key usages.
	// This should be used when validating the profile at load, and isn't used
	// here.
	ku, eku, _ = profile.Usages()
	if profile.IssuerURL == nil {
		issuerURL = defaultProfile.IssuerURL
	}

	if ku == 0 && len(eku) == 0 {
		return cferr.New(cferr.PolicyError, cferr.NoKeyUsages)
	}

	if expiry = profile.Expiry; expiry == 0 {
		expiry = defaultProfile.Expiry
	}

	if crlURL = profile.CRL; crlURL == "" {
		crlURL = defaultProfile.CRL
	}
	if ocspURL = profile.OCSP; ocspURL == "" {
		ocspURL = defaultProfile.OCSP
	}

	if notBefore.IsZero() {
		if !profile.NotBefore.IsZero() {
			notBefore = profile.NotBefore
		} else {
			if backdate = profile.Backdate; backdate == 0 {
				backdate = -5 * time.Minute
			} else {
				backdate = -1 * profile.Backdate
			}
			notBefore = time.Now().Round(time.Minute).Add(backdate)
		}
	}
	notBefore = notBefore.UTC()

	if notAfter.IsZero() {
		if !profile.NotAfter.IsZero() {
			notAfter = profile.NotAfter
		} else {
			notAfter = notBefore.Add(expiry)
		}
	}
	notAfter = notAfter.UTC()

	template.NotBefore = notBefore
	template.NotAfter = notAfter
	template.KeyUsage = ku
	template.ExtKeyUsage = eku
	template.BasicConstraintsValid = true
	template.IsCA = profile.CAConstraint.IsCA
	if template.IsCA {
		template.MaxPathLen = profile.CAConstraint.MaxPathLen
		if template.MaxPathLen == 0 {
			template.MaxPathLenZero = profile.CAConstraint.MaxPathLenZero
		}
		template.DNSNames = nil
		template.EmailAddresses = nil
	}
	template.SubjectKeyId = ski

	if ocspURL != "" {
		template.OCSPServer = []string{ocspURL}
	}
	if crlURL != "" {
		template.CRLDistributionPoints = []string{crlURL}
	}

	if len(issuerURL) != 0 {
		template.IssuingCertificateURL = issuerURL
	}
	if len(profile.Policies) != 0 {
		err = addPolicies(template, profile.Policies)
		if err != nil {
			return cferr.Wrap(cferr.PolicyError, cferr.InvalidPolicy, err)
		}
	}
	if profile.OCSPNoCheck {
		ocspNoCheckExtension := pkix.Extension{
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5},
			Critical: false,
			Value:    []byte{0x05, 0x00},
		}
		template.ExtraExtensions = append(template.ExtraExtensions, ocspNoCheckExtension)
	}

	return nil
}

// ComputeSKI derives an SKI from the certificate's public key in a
// standard manner. This is done by computing the SHA-1 digest of the
// SubjectPublicKeyInfo component of the certificate.
func ComputeSKI(template *sm2.Certificate) ([]byte, error) {
	pub := template.PublicKey
	encodedPub, err := sm2.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	var subPKI subjectPublicKeyInfo
	_, err = asn1.Unmarshal(encodedPub, &subPKI)
	if err != nil {
		return nil, err
	}
	pubHash := sha1.Sum(subPKI.SubjectPublicKey.Bytes)
	return pubHash[:], nil
}

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

type policyInformation struct {
	PolicyIdentifier asn1.ObjectIdentifier
	Qualifiers       []interface{} `asn1:"tag:optional,omitempty"`
}

type cpsPolicyQualifier struct {
	PolicyQualifierID asn1.ObjectIdentifier
	Qualifier         string `asn1:"tag:optional,ia5"`
}

type userNotice struct {
	ExplicitText string `asn1:"tag:optional,utf8"`
}

type userNoticePolicyQualifier struct {
	PolicyQualifierID asn1.ObjectIdentifier
	Qualifier         userNotice
}

var (
	// Per https://tools.ietf.org/html/rfc3280.html#page-106, this represents:
	// iso(1) identified-organization(3) dod(6) internet(1) security(5)
	//   mechanisms(5) pkix(7) id-qt(2) id-qt-cps(1)
	iDQTCertificationPracticeStatement = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}
	// iso(1) identified-organization(3) dod(6) internet(1) security(5)
	//   mechanisms(5) pkix(7) id-qt(2) id-qt-unotice(2)
	iDQTUserNotice = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2}

	// CTPoisonOID is the object ID of the critical poison extension for precertificates
	// https://tools.ietf.org/html/rfc6962#page-9
	CTPoisonOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}

	// SCTListOID is the object ID for the Signed Certificate Timestamp certificate extension
	// https://tools.ietf.org/html/rfc6962#page-14
	SCTListOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)


// addPolicies adds Certificate Policies and optional Policy Qualifiers to a
// certificate, based on the input config. Go's x509 library allows setting
// Certificate Policies easily, but does not support nested Policy Qualifiers
// under those policies. So we need to construct the ASN.1 structure ourselves.
func addPolicies(template *sm2.Certificate, policies []config.CertificatePolicy) error {
	asn1PolicyList := []policyInformation{}

	for _, policy := range policies {
		pi := policyInformation{
			// The PolicyIdentifier is an OID assigned to a given issuer.
			PolicyIdentifier: asn1.ObjectIdentifier(policy.ID),
		}
		for _, qualifier := range policy.Qualifiers {
			switch qualifier.Type {
			case "id-qt-unotice":
				pi.Qualifiers = append(pi.Qualifiers,
					userNoticePolicyQualifier{
						PolicyQualifierID: iDQTUserNotice,
						Qualifier: userNotice{
							ExplicitText: qualifier.Value,
						},
					})
			case "id-qt-cps":
				pi.Qualifiers = append(pi.Qualifiers,
					cpsPolicyQualifier{
						PolicyQualifierID: iDQTCertificationPracticeStatement,
						Qualifier:         qualifier.Value,
					})
			default:
				return errors.New("Invalid qualifier type in Policies " + qualifier.Type)
			}
		}
		asn1PolicyList = append(asn1PolicyList, pi)
	}

	asn1Bytes, err := asn1.Marshal(asn1PolicyList)
	if err != nil {
		return err
	}

	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 32},
		Critical: false,
		Value:    asn1Bytes,
	})
	return nil
}

