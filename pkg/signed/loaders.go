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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/hashicorp/vault/shamir"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/encrypted"
)

type PublicKey interface {
	signature.Verifier
	signature.PublicKeyProvider
}

func LoadPublicKey(path string) (PublicKey, error) {
	bytes, err := ioutil.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read public key: %v", err)
	}

	pk, err := ParsePKIXPublicKeyFromPEM(bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkix: %v", err)
	}

	return pk, nil
}

func LoadAndCombinePrivateKeysFromPaths(pf PassFunc, combineEncryptedFiles, combineUnEncryptedFiles []string) ([]byte, error) {
	fmt.Fprint(os.Stdout, "(Press Enter to continue without decrypt...)", "\n")

	parts, err := loadPrivateKeysFromPaths(pf, combineEncryptedFiles, combineUnEncryptedFiles)
	if err != nil {
		return nil, fmt.Errorf("load private keys error: %v", err)
	}

	c, err := shamir.Combine(parts)
	if err != nil {
		return nil, fmt.Errorf("shamir combining error: %v", err)
	}

	return c, nil
}

// loadPrivateKeysFromPaths load private keys from given paths
// combineEncryptedFiles represents -f, which is we will show password prompt
// combineUnEncryptedFiles represents -F, which is we will NOT show password prompt
func loadPrivateKeysFromPaths(pf PassFunc, combineEncryptedFiles, combineUnEncryptedFiles []string) ([][]byte, error) {
	privateParts := make([][]byte, len(combineEncryptedFiles)+len(combineUnEncryptedFiles))

	c := 0

	for i := 0; i < len(combineEncryptedFiles); i++ {
		k, err := readAndDecodePEMKeyFromPath(combineEncryptedFiles[i], pf)
		if err != nil {
			return nil, fmt.Errorf("read and decrypt pem file error: %v", err)
		}

		privateParts[c] = k
		c++
	}

	for i := 0; i < len(combineUnEncryptedFiles); i++ {
		k, err := ReadFileAndDecodePEMFromPath(combineUnEncryptedFiles[i])
		if err != nil {
			return nil, fmt.Errorf("read and decode pem file error: %v", err)
		}

		privateParts[c] = k
		c++
	}

	return privateParts, nil
}

func readAndDecodePEMKeyFromPath(path string, pf PassFunc) ([]byte, error) {
	kb, err := ioutil.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read file: %v", err)
	}

	p, err := DecodePEMFromFile(path, kb, pf, encrypted.Decrypt, false, true)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PEM from file: %v", err)
	}

	return p, nil
}
