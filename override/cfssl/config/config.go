package config

import (
	"github.com/cloudflare/cfssl/auth"
	"github.com/cloudflare/cfssl/config"
	"github.com/tjfoc/gmsm/sm2"
	"regexp"
	"time"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/tjfoc/gmtls"
)

// KeyUsage contains a mapping of string names to key usages.
var KeyUsage = map[string]sm2.KeyUsage{
	"signing":             sm2.KeyUsageDigitalSignature,
	"digital signature":   sm2.KeyUsageDigitalSignature,
	"content committment": sm2.KeyUsageContentCommitment,
	"key encipherment":    sm2.KeyUsageKeyEncipherment,
	"key agreement":       sm2.KeyUsageKeyAgreement,
	"data encipherment":   sm2.KeyUsageDataEncipherment,
	"cert sign":           sm2.KeyUsageCertSign,
	"crl sign":            sm2.KeyUsageCRLSign,
	"encipher only":       sm2.KeyUsageEncipherOnly,
	"decipher only":       sm2.KeyUsageDecipherOnly,
}

// ExtKeyUsage contains a mapping of string names to extended key
// usages.
var ExtKeyUsage = map[string]sm2.ExtKeyUsage{
	"any":              sm2.ExtKeyUsageAny,
	"server auth":      sm2.ExtKeyUsageServerAuth,
	"client auth":      sm2.ExtKeyUsageClientAuth,
	"code signing":     sm2.ExtKeyUsageCodeSigning,
	"email protection": sm2.ExtKeyUsageEmailProtection,
	"s/mime":           sm2.ExtKeyUsageEmailProtection,
	"ipsec end system": sm2.ExtKeyUsageIPSECEndSystem,
	"ipsec tunnel":     sm2.ExtKeyUsageIPSECTunnel,
	"ipsec user":       sm2.ExtKeyUsageIPSECUser,
	"timestamping":     sm2.ExtKeyUsageTimeStamping,
	"ocsp signing":     sm2.ExtKeyUsageOCSPSigning,
	"microsoft sgc":    sm2.ExtKeyUsageMicrosoftServerGatedCrypto,
	"netscape sgc":     sm2.ExtKeyUsageNetscapeServerGatedCrypto,
}

// Usages parses the list of key uses in the profile, translating them
// to a list of X.509 key usages and extended key usages.  The unknown
// uses are collected into a slice that is also returned.
func (p *SigningProfile) Usages() (ku sm2.KeyUsage, eku []sm2.ExtKeyUsage, unk []string) {
	for _, keyUse := range p.Usage {
		if kuse, ok := KeyUsage[keyUse]; ok {
			ku |= kuse
		} else if ekuse, ok := ExtKeyUsage[keyUse]; ok {
			eku = append(eku, ekuse)
		} else {
			unk = append(unk, keyUse)
		}
	}
	return
}

// Signing codifies the signature configuration policy for a CA.
type Signing struct {
	Profiles map[string]*SigningProfile `json:"profiles"`
	Default  *SigningProfile            `json:"default"`
}

// A SigningProfile stores information that the CA needs to store
// signature policy.
type SigningProfile struct {
	Usage               []string            `json:"usages"`
	IssuerURL           []string            `json:"issuer_urls"`
	OCSP                string              `json:"ocsp_url"`
	CRL                 string              `json:"crl_url"`
	CAConstraint        config.CAConstraint `json:"ca_constraint"`
	OCSPNoCheck         bool                `json:"ocsp_no_check"`
	ExpiryString        string              `json:"expiry"`
	BackdateString      string              `json:"backdate"`
	AuthKeyName         string              `json:"auth_key"`
	RemoteName          string              `json:"remote"`
	NotBefore           time.Time           `json:"not_before"`
	NotAfter            time.Time           `json:"not_after"`
	NameWhitelistString string              `json:"name_whitelist"`
	AuthRemote          config.AuthRemote   `json:"auth_remote"`
	CTLogServers        []string            `json:"ct_log_servers"`
	AllowedExtensions   []config.OID        `json:"allowed_extensions"`
	CertStore           string              `json:"cert_store"`

	Policies                    []config.CertificatePolicy
	Expiry                      time.Duration
	Backdate                    time.Duration
	Provider                    auth.Provider
	RemoteProvider              auth.Provider
	RemoteServer                string
	RemoteCAs                   *sm2.CertPool
	ClientCert                  *gmtls.Certificate
	CSRWhitelist                *config.CSRWhitelist
	NameWhitelist               *regexp.Regexp
	ExtensionWhitelist          map[string]bool
	ClientProvidesSerialNumbers bool
}

// DefaultConfig returns a default configuration specifying basic key
// usage and a 1 year expiration time. The key usages chosen are
// signing, key encipherment, client auth and server auth.
func DefaultConfig() *SigningProfile {
	d := helpers.OneYear
	return &SigningProfile{
		Usage:        []string{"signing", "key encipherment", "server auth", "client auth"},
		Expiry:       d,
		ExpiryString: "8760h",
	}
}

// OverrideRemotes takes a signing configuration and updates the remote server object
// to the hostname:port combination sent by remote
func (p *Signing) OverrideRemotes(remote string) error {
	if remote != "" {
		var err error
		for _, profile := range p.Profiles {
			err = profile.updateRemote(remote)
			if err != nil {
				return err
			}
		}
		err = p.Default.updateRemote(remote)
		if err != nil {
			return err
		}
	}
	return nil
}

// updateRemote takes a signing profile and initializes the remote server object
// to the hostname:port combination sent by remote.
func (p *SigningProfile) updateRemote(remote string) error {
	if remote != "" {
		p.RemoteServer = remote
	}
	return nil
}
