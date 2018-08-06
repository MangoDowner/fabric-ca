package helpers

import (
	"crypto"
	"github.com/tjfoc/gmsm/sm2"
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
