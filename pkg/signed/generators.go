// Copyright (c) 2021 Furkan Türkal
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package signed

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/Dentrax/cocert/pkg/password"

	"github.com/hashicorp/vault/shamir"
	"github.com/theupdateframework/go-tuf/encrypted"
)

func GenerateECDSAEllipticP521() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
}

func GenerateTUFEncryptedKeys(pf PassFunc) (*Keys, error) {
	ellipticP521, err := GenerateECDSAEllipticP521()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA from elliptic.P521(): %v", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(ellipticP521)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PKCS8 key: %v", err)
	}

	pkix, err := x509.MarshalPKIXPublicKey(&ellipticP521.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PKIX key: %v", err)
	}

	password, err := pf(true, password.CreateNewPasswordMsg, true)
	if err != nil {
		return nil, err
	}

	encBytes, err := encrypted.Encrypt(pkcs8, password)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt PKCS8: %v", err)
	}

	pkixPEMBytes := pem.EncodeToMemory(&pem.Block{
		Type:  string(PemTypePublic),
		Bytes: pkix,
	})

	return &Keys{
		PrivateBytesPlain: ellipticP521.D.Bytes(),
		PrivateBytes:      encBytes,
		PublicBytes:       pkixPEMBytes,
	}, nil
}

func GenerateShamirPEMsToMemAsArray(pf PassFunc, parts, threshold int) (*Keys, error) {
	keys, err := GenerateTUFEncryptedKeys(pf)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TUF: %v", err)
	}

	bytes, err := shamir.Split(keys.PrivateBytes, parts, threshold)
	if err != nil {
		return nil, fmt.Errorf("shamir splitting error: %v", err)
	}

	keys.PrivatePEMBytes = bytes

	return keys, nil
}

func GenerateShamirPEMsToMemAsArrayFromCustomPrivateKey(path string, parts, threshold int) (*Keys, error) {
	bytes, err := ReadCustomPrivateKeyFileAndDecodePEMFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("failed to decode pem: %v", err)
	}

	splitted, err := shamir.Split(bytes, parts, threshold)
	if err != nil {
		return nil, fmt.Errorf("shamir splitting error: %v", err)
	}

	return &Keys{
		PrivateBytesPlain: nil,
		PrivatePEMBytes:   splitted,
		PrivateBytes:      nil,
		PublicBytes:       nil,
	}, nil
}
