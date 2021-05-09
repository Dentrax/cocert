package signed

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"

	"github.com/sigstore/sigstore/pkg/signature"
)

func NewVerifier(publicKeyFile, publicCertFile string) (PublicKey, error) {

	getVerifier := func(pub, cert string) (PublicKey, error) {
		switch {
		case cert != "":
			bytes, err := ioutil.ReadFile(cert)
			if err != nil {
				return nil, fmt.Errorf("read cert file: %v", err)
			}

			pk, err := ParseECDSAPublicKeyFromPEM(bytes)
			if err != nil {
				return nil, fmt.Errorf("extract public key from ECDSA PEM: %v", err)
			}

			return pk, nil

		case pub != "":
			pk, err := LoadPublicKey(pub)
			if err != nil {
				return nil, fmt.Errorf("load public key: %v", err)
			}

			return pk, nil
		}

		return nil, fmt.Errorf("no pub or cert provided")
	}

	pk, err := getVerifier(publicKeyFile, publicCertFile)
	if err != nil {
		return signature.ECDSAVerifier{}, fmt.Errorf("could not get verifier: %v", err)
	}

	return pk, nil
}

func VerifyKey(ctx context.Context, verifier PublicKey, rawPayload []byte, base64Signature []byte) error {
	sig, err := base64.StdEncoding.DecodeString(string(base64Signature))
	if err != nil {
		return fmt.Errorf("decode base64: %v", err)
	}

	return verifier.Verify(ctx, rawPayload, sig)
}
