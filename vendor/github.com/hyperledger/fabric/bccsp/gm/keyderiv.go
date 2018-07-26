/*
	密钥派生
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package gm

import (
	"errors"

	"fmt"
	"math/big"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/tjfoc/gmsm/sm2"
	"reflect"
)

type gmsm2PrivateKeyKeyDeriver struct {
	bccsp *impl
}

// sm2私钥派生
func (kd *gmsm2PrivateKeyKeyDeriver) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error) {
	// Validate opts
	if opts == nil {
		return nil, errors.New("Invalid opts parameter. It must not be nil.")
	}

	gmsm2K := k.(*gmsm2PrivateKey)
	fmt.Println(reflect.TypeOf(opts)) //*bccsp.HMACDeriveKeyOpts
	switch opts.(type) {
	// Re-randomized an ECDSA private key
	case *bccsp.GMSM2ReRandKeyOpts:
		reRandOpts := opts.(*bccsp.GMSM2ReRandKeyOpts)
		tempSK := &sm2.PrivateKey{
			PublicKey: sm2.PublicKey{
				Curve: gmsm2K.privKey.Curve,
				X:     new(big.Int),
				Y:     new(big.Int),
			},
			D: new(big.Int),
		}

		var k = new(big.Int).SetBytes(reRandOpts.ExpansionValue())
		var one = new(big.Int).SetInt64(1)
		n := new(big.Int).Sub(gmsm2K.privKey.Params().N, one)
		k.Mod(k, n)
		k.Add(k, one)

		tempSK.D.Add(gmsm2K.privKey.D, k)
		tempSK.D.Mod(tempSK.D, gmsm2K.privKey.PublicKey.Params().N)

		// Compute temporary public key
		tempX, tempY := gmsm2K.privKey.PublicKey.ScalarBaseMult(k.Bytes())
		tempSK.PublicKey.X, tempSK.PublicKey.Y =
			tempSK.PublicKey.Add(
				gmsm2K.privKey.PublicKey.X, gmsm2K.privKey.PublicKey.Y,
				tempX, tempY,
			)

		// Verify temporary public key is a valid point on the reference curve
		isOn := tempSK.Curve.IsOnCurve(tempSK.PublicKey.X, tempSK.PublicKey.Y)
		if !isOn {
			return nil, errors.New("Failed temporary public key IsOnCurve check.")
		}
		return &gmsm2PrivateKey{tempSK}, nil
	default:
		return nil, fmt.Errorf("Unsupported 'KeyDerivOpts' provided [%v]", opts)
	}
}
