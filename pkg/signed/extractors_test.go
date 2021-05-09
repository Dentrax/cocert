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
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/encrypted"
)

var (
	prf = func(string, bool) bool {
		return true
	}
)

func TestEncryptPEMsByTUF(t *testing.T) {
	assert := assert.New(t)

	got, err := GenerateShamirPEMsToMemAsArray(pf, 5, 3)
	assert.NoError(err)
	assert.NotNil(got)

	files, err := EncryptPEMsByTUF(pf, prf, got)
	assert.NoError(err)
	assert.NotNil(files)
	assert.Len(files, 5)

	for _, file := range files {
		p, _ := pem.Decode(file.Data)
		assert.NotNil(p)

		decodedBytes, err := encrypted.Decrypt(p.Bytes, []byte("test"))
		assert.NoError(err)
		assert.NotNil(decodedBytes)
	}
}

func TestParseECDSAPublicKeyFromPEM(t *testing.T) {
	assert := assert.New(t)

	got, err := GenerateTUFEncryptedKeys(pf)
	assert.NoError(err)
	assert.NotNil(got)

	pkix, err := ParsePKIXPublicKeyFromPEM(got.PublicBytes)
	assert.NoError(err)
	assert.NotNil(pkix)
}
