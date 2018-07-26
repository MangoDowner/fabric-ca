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
	"github.com/hyperledger/fabric/bccsp"
	"crypto/hmac"
	"reflect"
)

type gmsm4PrivateKeyKeyDeriver struct {
	bccsp *impl
}

// sm2私钥派生
func (kd *gmsm4PrivateKeyKeyDeriver) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error) {
	// Validate opts
	if opts == nil {
		return nil, errors.New("Invalid opts parameter. It must not be nil.")
	}

	aesK := k.(*gmsm4PrivateKey)
	fmt.Println(reflect.TypeOf(opts)) //*bccsp.HMACDeriveKeyOpts
	switch opts.(type) {
	case *bccsp.HMACDeriveKeyOpts:
		hmacOpts := opts.(*bccsp.HMACDeriveKeyOpts)
		mac := hmac.New(kd.bccsp.conf.hashFunction, aesK.privKey)
		mac.Write(hmacOpts.Argument())
		return &gmsm4PrivateKey{mac.Sum(nil), true}, nil
	default:
		return nil, fmt.Errorf("Unsupported 'KeyDerivOpts' provided [%v]", opts)
	}
}
