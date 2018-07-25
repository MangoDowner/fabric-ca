/**
	国密证书文件
	Created by MangoDowner @ 2018-6-27 10:03:59
 */
package lib

import (
	"crypto/x509"
	"github.com/cloudflare/cfssl/csr"
	"crypto"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/gm"
	"github.com/tjfoc/gmsm/sm2"
	"encoding/pem"
	"fmt"
	"net"
	"net/mail"
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/certdb"
	"encoding/hex"
	"github.com/hyperledger/fabric-ca/util"
)

//证书签名
func SignCert(req signer.SignRequest, ca *CA) (cert []byte, err error) {
	/*csr := parseCertificateRequest()
	cert, err := sm2.CreateCertificateToMem(template, rootca, csr.pubkey, rootca.privkey)
	sm2Cert, err := sm2.parseCertificateFromMem(cert)

	var certRecord = certdb.CertificateRecord{
		Serial:  sm2Cert.SerialNumber.String(),
		AKI:     hex.EncodeToString(sm2Cert.AuthorityKeyId),
		CALabel: req.Label,
		Status:  "good",
		Expiry:  sm2Cert.NotAfter,
		PEM:     string(cert),
	}*/

	block, _ := pem.Decode([]byte(req.Request))
	if block == nil {
		return nil, fmt.Errorf("decode error")
	}
	if block.Type != "NEW CERTIFICATE REQUEST" && block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("不是一个csr")
	}
	template, err := parseCertificateRequest(block.Bytes)
	if err != nil {
		log.Infof("---[gmca:ParseCertificateRequest] 错误:[%s]", err)
		return nil, err
	}

	certFile := ca.Config.CA.Certfile
	//log.Info("---[gmca:ParseCertificateRequest]certifle是 %s", certFile)
	rootKey, _, x509cert, err := util.GetSignerFromCertFile(certFile, ca.csp)
	if err != nil {
		return nil, err
	}

	rootCa := ParseX509Certificate2Sm2(x509cert)
	cert, err = gm.CreateCertificateToMem(template, rootCa, rootKey)
	clientCert, err := sm2.ReadCertificateFromMem(cert)
	//FIXME : err不为nil的时候，要加处理
	var certRecord = certdb.CertificateRecord{
		Serial:  clientCert.SerialNumber.String(),
		AKI:     hex.EncodeToString(clientCert.AuthorityKeyId),
		CALabel: req.Label,
		Status:  "good",
		Expiry:  clientCert.NotAfter,
		PEM:     string(cert),
	}
	err = ca.certDBAccessor.InsertCertificate(certRecord)
	if err != nil {
		//log.Info("---[gmca:ParseCertificateRequest] 调用 InsertCertificate错误:" , err)
	}
	return
}

// override: cfssl/initca.go:NewFromSigner
// NewFromSigner creates a new root certificate from a crypto.Signer.
func NewFromSigner(key bccsp.Key, req *csr.CertificateRequest, priv crypto.Signer) (cert []byte, err error) {
	csrPEM, err := Generate(priv, req, key)
	if err != nil {
		log.Infof("[gmca:createGmSm2Cert]Call Generate() error :%s", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("[gmca:createGmSm2Cert] csr DecodeFailed")
	}
	if block.Type != "NEW CERTIFICATE REQUEST" && block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("[gmca:createGmSm2Cert] sm2 not a csr")
	}
	sm2Template, err := parseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	//log.Infof("PublicKey Type是 %T, sm2Template Type是 %T---", sm2Template.PublicKey, sm2Template)
	cert, err = gm.CreateCertificateToMem(sm2Template, sm2Template, key)
	return
}

/**
	cloudflare Generate() 转成支持国密
 */
// Generate从一个CertificateRequest和一个现有的Key创建一个新的CSR。
// KeyRequest字段被忽略。
func Generate(priv crypto.Signer, req *csr.CertificateRequest, key bccsp.Key) (csr []byte, err error) {
	sigAlgo := SignerAlgo(priv)
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
		err = appendCAInfoToCSRSm2(req.CA, &tpl)
		if err != nil {
			err = fmt.Errorf("sm2 GenerationFailed")
			return
		}
	}
	log.Info("encoded CSR")
	csr, err = gm.CreateSm2CertificateRequestToMem(&tpl, key)
	return
}

/**
	@override: cloudflare:signerAlgo
 */
//SignerAlgo从一个crypto.Signer返回一个x.509签名算法。
func SignerAlgo(priv crypto.Signer) sm2.SignatureAlgorithm {
	switch pub := priv.Public().(type) {
	case *sm2.PublicKey:
		switch pub.Curve {
		case sm2.P256Sm2():
			return sm2.SM2WithSHA256
		default:
			return sm2.SM2WithSHA1
		}
	default:
		return sm2.UnknownSignatureAlgorithm
	}
}

/**
	@override: cloudflare:appendCAInfoToCSR
 */
//appendCAInfoToCSR将CAConfig基本限制(BasicConstraints)扩展到CSR
func appendCAInfoToCSRSm2(reqConf *csr.CAConfig, csrReq *sm2.CertificateRequest) error {
	pathlen := reqConf.PathLength
	if pathlen == 0 && !reqConf.PathLenZero {
		pathlen = -1
	}
	val, err := asn1.Marshal(csr.BasicConstraints{true, pathlen})

	if err != nil {
		return err
	}

	csrReq.ExtraExtensions = []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
			Value:    val,
			Critical: true,
		},
	}

	return nil
}

//证书请求转换成证书  参数为  block .Bytes
func parseCertificateRequest(csrBytes []byte) (template *sm2.Certificate, err error) {
	csrv, err := sm2.ParseCertificateRequest(csrBytes)
	if err != nil {
		return
	}
	err = csrv.CheckSignature()
	//log.Infof("[gmca:parseCertificateRequest]---%T---", csrv.PublicKey)
	template = &sm2.Certificate{
		Subject:            csrv.Subject,
		PublicKeyAlgorithm: csrv.PublicKeyAlgorithm,
		PublicKey:          csrv.PublicKey,
		SignatureAlgorithm: csrv.SignatureAlgorithm,
		DNSNames:           csrv.DNSNames,
		IPAddresses:        csrv.IPAddresses,
		EmailAddresses:     csrv.EmailAddresses,
	}

	//log.Infof("---[gmca:parseCertificateRequest]加密算法是 %v, 公钥类型是 :%T---",
	//	template.SignatureAlgorithm, template.PublicKey)

	template.NotBefore = time.Now()
	template.NotAfter = time.Now().Add(time.Hour * 1000)
	for _, val := range csrv.Extensions {
		// Check the CSR for the X.509 BasicConstraints (RFC 5280, 4.2.1.9)
		// extension and append to template if necessary
		if val.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19}) {
			var constraints csr.BasicConstraints
			var rest []byte

			if rest, err = asn1.Unmarshal(val.Value, &constraints); err != nil {
				//return nil, cferr.Wrap(cferr.CSRError, cferr.ParseFailed, err)
			} else if len(rest) != 0 {
				//return nil, cferr.Wrap(cferr.CSRError, cferr.ParseFailed, errors.New("x509: trailing data after X.509 BasicConstraints"))
			}

			template.BasicConstraintsValid = true
			template.IsCA = constraints.IsCA
			template.MaxPathLen = constraints.MaxPathLen
			template.MaxPathLenZero = template.MaxPathLen == 0
		}
	}
	//随机生成序列号
	template.SerialNumber = gm.GetRandBigInt()
	log.Infof("signed certificate with serial number %d", template.SerialNumber)
	return
}

// 将x509证书转为sm2证书
func ParseX509Certificate2Sm2(x509Cert *x509.Certificate) *sm2.Certificate {
	sm2cert := &sm2.Certificate{
		Raw:                         x509Cert.Raw,
		RawTBSCertificate:           x509Cert.RawTBSCertificate,
		RawSubjectPublicKeyInfo:     x509Cert.RawSubjectPublicKeyInfo,
		RawSubject:                  x509Cert.RawSubject,
		RawIssuer:                   x509Cert.RawIssuer,
		Signature:                   x509Cert.Signature,
		SignatureAlgorithm:          sm2.SignatureAlgorithm(x509Cert.SignatureAlgorithm),
		PublicKeyAlgorithm:          sm2.PublicKeyAlgorithm(x509Cert.PublicKeyAlgorithm),
		PublicKey:                   x509Cert.PublicKey,
		Version:                     x509Cert.Version,
		SerialNumber:                x509Cert.SerialNumber,
		Issuer:                      x509Cert.Issuer,
		Subject:                     x509Cert.Subject,
		NotBefore:                   x509Cert.NotBefore,
		NotAfter:                    x509Cert.NotAfter,
		KeyUsage:                    sm2.KeyUsage(x509Cert.KeyUsage),
		Extensions:                  x509Cert.Extensions,
		ExtraExtensions:             x509Cert.ExtraExtensions,
		UnhandledCriticalExtensions: x509Cert.UnhandledCriticalExtensions,
		//ExtKeyUsage:	[]x509.ExtKeyUsage(x509Cert.ExtKeyUsage) ,
		UnknownExtKeyUsage:    x509Cert.UnknownExtKeyUsage,
		BasicConstraintsValid: x509Cert.BasicConstraintsValid,
		IsCA:       x509Cert.IsCA,
		MaxPathLen: x509Cert.MaxPathLen,
		// MaxPathLenZero indicates that BasicConstraintsValid==true and
		// MaxPathLen==0 should be interpreted as an actual maximum path length
		// of zero. Otherwise, that combination is interpreted as MaxPathLen
		// not being set.
		MaxPathLenZero: x509Cert.MaxPathLenZero,
		SubjectKeyId:   x509Cert.SubjectKeyId,
		AuthorityKeyId: x509Cert.AuthorityKeyId,
		// RFC 5280, 4.2.2.1 (Authority Information Access)
		OCSPServer:            x509Cert.OCSPServer,
		IssuingCertificateURL: x509Cert.IssuingCertificateURL,
		// Subject Alternate Name values
		DNSNames:       x509Cert.DNSNames,
		EmailAddresses: x509Cert.EmailAddresses,
		IPAddresses:    x509Cert.IPAddresses,
		// Name constraints
		PermittedDNSDomainsCritical: x509Cert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         x509Cert.PermittedDNSDomains,
		// CRL Distribution Points
		CRLDistributionPoints: x509Cert.CRLDistributionPoints,
		PolicyIdentifiers:     x509Cert.PolicyIdentifiers,
	}
	for _, val := range x509Cert.ExtKeyUsage {
		sm2cert.ExtKeyUsage = append(sm2cert.ExtKeyUsage, sm2.ExtKeyUsage(val))
	}
	return sm2cert
}