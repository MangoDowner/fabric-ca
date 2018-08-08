/**
	国密证书文件
	Created by MangoDowner @ 2018-6-27 10:03:59
 */
package lib

import (
	"crypto/x509"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric/bccsp/gm"
	"crypto/sm2"
	"encoding/pem"
	"fmt"
	"encoding/asn1"
	"time"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/certdb"
	"encoding/hex"
	"github.com/hyperledger/fabric-ca/util"
)

// override: cfssl.local:Sign
//证书签名
func SignCert(req signer.SignRequest, ca *CA) (cert []byte, err error) {
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

	//rootCa := ParseX509Certificate2Sm2(x509cert)
	cert, err = gm.CreateCertificateToMem(template, x509cert, rootKey)
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
	//TODO: KeyUsage未定义
	template.KeyUsage = sm2.KeyUsage(96)
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
