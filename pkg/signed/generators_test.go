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
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/hashicorp/vault/shamir"
	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/encrypted"
)

var (
	pf = func(bool, string, bool) ([]byte, error) {
		return []byte("test"), nil
	}
)

func TestGenerateECDSAEllipticP521(t *testing.T) {
	assert := assert.New(t)

	got, err := GenerateECDSAEllipticP521()
	assert.NoError(err)
	assert.NotNil(got)
	assert.NotEmpty(got.D.Bytes())
	assert.NotEmpty(got.X.Bytes())
	assert.NotEmpty(got.Y.Bytes())
}

func TestGenerateTUFEncryptedKeys(t *testing.T) {
	assert := assert.New(t)

	got, err := GenerateTUFEncryptedKeys(pf)
	assert.NoError(err)
	assert.NotNil(got)

	p, pr := pem.Decode(got.PublicBytes)
	assert.NotNil(p)
	assert.Empty(pr)

	d, err := encrypted.Decrypt(got.PrivateBytes, []byte("test"))
	assert.NoError(err)
	assert.NotEmpty(d)

	pkix, err := x509.ParsePKIXPublicKey(p.Bytes)
	assert.NoError(err)
	assert.NotNil(pkix)

	pkcs8, err := x509.ParsePKCS8PrivateKey(d)
	assert.NoError(err)
	assert.NotNil(pkcs8)

	if pk, ok := pkcs8.(*ecdsa.PrivateKey); ok {
		assert.True(ok)
		assert.NotNil(pk)
		assert.Equal(got.PrivateBytesPlain, pk.D.Bytes())
	} else {
		assert.Fail("could not parse PKIX to ecdsa.PrivateKey")
	}
}

func TestGenerateShamirPEMsToMemAsArray(t *testing.T) {
	assert := assert.New(t)

	got, err := GenerateShamirPEMsToMemAsArray(pf, 5, 2)
	assert.NoError(err)
	assert.NotNil(got)

	e1 := got.PrivatePEMBytes[2]
	e2 := got.PrivatePEMBytes[4]

	var s [][]byte
	s = append(s, e1)
	s = append(s, e2)

	c, err := shamir.Combine(s)
	assert.NoError(err)
	assert.NotNil(c)
}
