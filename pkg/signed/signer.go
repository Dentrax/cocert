package signed

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/Dentrax/cocert/pkg/password"

	"github.com/sigstore/cosign/pkg/cosign/fulcio"
	"github.com/sigstore/sigstore/pkg/signature"
	_ "golang.org/x/crypto/sha3" //nolint:golint
	"golang.org/x/term"
)

type Signer struct {
	signature.Signer

	PK   *ecdsa.PrivateKey
	Cert string
}

func NewKeySigner(ctx context.Context, shamirFiles []string, privateKey string) (Signer, error) {
	s, err := DecideSignerType(ctx, shamirFiles, privateKey)
	if err != nil {
		return Signer{}, fmt.Errorf("create signer: %v", err)
	}
	return s, nil
}

func NewKeylessSigner(ctx context.Context, shamirFiles []string, privateKey string) (Signer, error) {
	s, err := DecideSignerType(ctx, shamirFiles, privateKey)
	if err != nil {
		return Signer{}, fmt.Errorf("create signer: %v", err)
	}

	flow := fulcio.FlowNormal
	if !term.IsTerminal(0) {
		fmt.Fprintln(os.Stderr, "Non-interactive mode detected, using device flow.")
		flow = fulcio.FlowDevice
	}

	cert, _, err := fulcio.GetCert(ctx, s.PK, flow)
	if err != nil {
		return Signer{}, fmt.Errorf("retrieving cert: %v", err)
	}

	return Signer{
		Signer: s,
		Cert:   cert,
	}, nil
}

func NewSignerFromShamir(ctx context.Context, files []string) (Signer, error) {
	s, err := LoadAndCombinePrivateKeysFromPaths(password.GetPass, files, nil)
	if err != nil {
		return Signer{}, fmt.Errorf("loading keys: %v", err)
	}

	return NewSignerFromBytes(s)
}

func NewSignerFromBytes(bytes []byte) (Signer, error) {
	pk, err := DecryptTUFEncryptedPrivateKey(bytes, password.GetPass)
	if err != nil {
		return Signer{}, fmt.Errorf("decrypt with master key: %v", err)
	}

	verifier := signature.NewECDSASignerVerifier(pk, crypto.SHA3_512)

	return Signer{
		Signer: verifier,
		PK:     pk,
	}, nil
}

func DecideSignerType(ctx context.Context, shamirFiles []string, privateKey string) (Signer, error) {
	switch {
	case privateKey != "":
		bytes, err := ReadFileAndDecodePEMFromPath(privateKey)
		if err != nil {
			return Signer{}, fmt.Errorf("read private key: %v", err)
		}
		s, err := NewSignerFromBytes(bytes)
		if err != nil {
			return Signer{}, fmt.Errorf("create signer from bytes: %v", err)
		}
		return s, nil
	case len(shamirFiles) >= 2:
		s, err := NewSignerFromShamir(ctx, shamirFiles)
		if err != nil {
			return Signer{}, fmt.Errorf("create signer: %v", err)
		}
		return s, nil
	default:
		return Signer{}, fmt.Errorf("does not provided any private key(s)")
	}
}

func CreateSigner(ctx context.Context, signer signature.Signer, payload []byte) (string, error) {
	sig, _, err := signer.Sign(ctx, payload)
	if err != nil {
		return "", fmt.Errorf("signing: %v", err)
	}

	return base64.StdEncoding.EncodeToString(sig), nil
}
