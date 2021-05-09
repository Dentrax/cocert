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
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/Dentrax/cocert/pkg/password"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/encrypted"
)

type EncryptPEMFile struct {
	Name string
	Data []byte
}

type TUFFunc func(text, pass []byte) ([]byte, error)

func EncryptPEMsByTUF(pf PassFunc, prF PrompterFunc, keys *Keys) ([]EncryptPEMFile, error) {
	result := make([]EncryptPEMFile, len(keys.PrivatePEMBytes))

	shouldDoEncrypt := prF("Do you want to encrypt each key using TUF?", false)

	for i, b := range keys.PrivatePEMBytes {
		name := fmt.Sprintf("cocert%d.key", i)

		if shouldDoEncrypt {
			p, err := pf(true, fmt.Sprintf("Create new password for %s key:", name), true)
			if err != nil {
				return nil, err
			}
			encBytes, err := encrypted.Encrypt(b, p)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt content for %s: %v", name, err)
			}
			b = encBytes
		}

		encoded := pem.EncodeToMemory(&pem.Block{
			Bytes: b,
			Type:  string(PemTypePrivate),
		})

		result[i] = EncryptPEMFile{
			Name: name,
			Data: encoded,
		}
	}

	return result, nil
}

func ExtractPEMsToCurrentDir(pf PassFunc, prF PrompterFunc, keys *Keys) error {
	files, err := EncryptPEMsByTUF(pf, prF, keys)
	if err != nil {
		return fmt.Errorf("failed to encrypt PEMs: %v", err)
	}

	for i, file := range files {
		if err := WriteFile(file.Name, file.Data); err != nil {
			return fmt.Errorf("unable to write private key %d: %v", i, err)
		}
	}

	if keys.PublicBytes != nil {
		if err := ioutil.WriteFile("cocert.pub", keys.PublicBytes, 0600); err != nil {
			return fmt.Errorf("unable to write public key: %v", err)
		}
	}

	return nil
}

func WriteFile(filename string, data []byte) error {
	if err := ioutil.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("unable to write private key %s: %v", filename, err)
	}
	return nil
}

func EncodePEMToFileOrOutput(filename string, data []byte) error {
	return EncodePEMToFileOrOutputWithType(filename, data, string(PemTypePrivate))
}

// EncodePEMToFileOrOutputWithType encodes the given data to PEM and
// writes to file.
func EncodePEMToFileOrOutputWithType(filename string, data []byte, pemType string) error {
	encoded := pem.EncodeToMemory(&pem.Block{
		Bytes: data,
		Type:  pemType,
	})

	if filename != "" {
		err := WriteFile(filename, encoded)
		if err != nil {
			return fmt.Errorf("unable to encode to PEM: %v", err)
		}
		return nil
	}

	fmt.Fprintln(os.Stdout, string(encoded))

	return nil
}

// DecodePEMBytes decodes given PEM bytes and checks equality the PemType
func DecodePEMBytes(bytes []byte, pemType PemType) ([]byte, error) {
	p, _ := pem.Decode(bytes)
	if p == nil {
		return nil, fmt.Errorf("failed to decode PEM-encoded x509 certificate")
	}
	return p.Bytes, nil
}

func ReadFileAndDecodePEMFromPath(path string) ([]byte, error) {
	kb, err := ioutil.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read file: %v", err)
	}

	p, err := DecodePEMBytes(kb, PemTypePrivate)
	if err != nil {
		return nil, fmt.Errorf("decode pem bytes: %v", err)
	}

	return p, nil
}

func ReadCustomPrivateKeyFileAndDecodePEMFromPath(path string) ([]byte, error) {
	bytes, err := ioutil.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read file: %v", err)
	}
	p, _ := pem.Decode(bytes)
	if p == nil {
		return nil, fmt.Errorf("failed to decode PEM-encoded x509 certificate")
	}
	return p.Bytes, nil
}

func DecodePEMFromFile(name string, file []byte, pf PassFunc, tufFunc TUFFunc, passConfirm, enforceTerminal bool) ([]byte, error) {
	p, err := DecodePEMBytes(file, PemTypePrivate)
	if err != nil {
		return nil, fmt.Errorf("decode pem bytes: %v", err)
	}

	pass, err := pf(passConfirm, fmt.Sprintf("Enter your password for %s: ", name), enforceTerminal)
	if err != nil {
		return nil, err
	}

	decodedBytes, err := tufFunc(p, pass)
	if err != nil {
		e := err.Error()
		// which means PEM has not been encrypted, it is OK to continue
		if !strings.Contains(e, "invalid character") {
			return nil, fmt.Errorf("unable to decrypt PEM file: %v", err)
		}
		return p, nil
	}

	return decodedBytes, nil
}

func DecryptTUFEncryptedPrivateKey(ciphertext []byte, pf PassFunc) (*ecdsa.PrivateKey, error) {
	passphrase, err := pf(false, password.MasterPasswordMsg, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get password: %v", err)
	}

	x509Encoded, err := encrypted.Decrypt(ciphertext, passphrase)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt X509 encoded TUF: %v", err)
	}

	pk, err := ParseECDSAPrivateKeyFromANS1(x509Encoded)
	if err != nil {
		return nil, fmt.Errorf("unable to extract ECDSA: %v", err)
	}

	return pk, nil
}

func DecryptTUFEncryptedKeys(ciphertext []byte, pf PassFunc) ([]byte, error) {
	pk, err := DecryptTUFEncryptedPrivateKey(ciphertext, pf)
	if err != nil {
		return nil, fmt.Errorf("decrypt ECDSA private key: %v", err)
	}

	return pk.D.Bytes(), nil
}

// ParseECDSAPrivateKeyFromANS1 parses given bytes to x509 PKCS8 and
// returns *ecdsa.PrivateKey.
func ParseECDSAPrivateKeyFromANS1(bytes []byte) (*ecdsa.PrivateKey, error) {
	pk, err := x509.ParsePKCS8PrivateKey(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 certificate: %v", err)
	}

	epk, ok := pk.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid private key")
	}

	return epk, nil
}

// ParseECDSAPublicKeyFromPEM parses given PEM bytes to x509 Certificate,
// casts to *ecdsa.PublicKey and returns ECDSAVerifier.
func ParseECDSAPublicKeyFromPEM(bytes []byte) (PublicKey, error) {
	b, err := DecodePEMBytes(bytes, PemTypeCertificate)
	if err != nil {
		return nil, fmt.Errorf("decode pem bytes: %v", err)
	}

	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %v", err)
	}

	pk, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid public key format")
	}

	return signature.ECDSAVerifier{
		Key:     pk,
		HashAlg: crypto.SHA3_512,
	}, nil
}

// ParsePKIXPublicKeyFromPEM parses given PEM bytes to x509 PKIX,
// casts to *ecdsa.PublicKey and returns ECDSAVerifier.
func ParsePKIXPublicKeyFromPEM(bytes []byte) (PublicKey, error) {
	p, err := DecodePEMBytes(bytes, PemTypePublic)
	if err != nil {
		return nil, fmt.Errorf("decode pem: %v", err)
	}

	pkix, err := x509.ParsePKIXPublicKey(p)
	if err != nil {
		return nil, fmt.Errorf("parse pkix: %v", err)
	}

	pk, ok := pkix.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid public key format")
	}

	return signature.ECDSAVerifier{
		Key:     pk,
		HashAlg: crypto.SHA3_512,
	}, nil
}
