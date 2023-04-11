package signer

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/232425wxy/rocen/bccsp"
)

type bccspCryptoSigner struct {
	csp        bccsp.BCCSP
	privateKey bccsp.Key
	publicKey  interface{}
}

func New(csp bccsp.BCCSP, key bccsp.Key) (crypto.Signer, error) {
	if csp == nil {
		return nil, errors.New("bccsp instance must be different from nil")
	}
	if key == nil {
		return nil, errors.New("key must be different from nil")
	}
	if key.Symmetric() {
		return nil, errors.New("key must be asymmetric")
	}
	pub, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed getting public key: [%s]", err)
	}
	raw, err := pub.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed marshalling public key: [%s]", err)
	}
	pk, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling der to public key: [%s]", err)
	}

	return &bccspCryptoSigner{
		csp:        csp,
		privateKey: key,
		publicKey:  pk,
	}, err
}

func (s *bccspCryptoSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *bccspCryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.csp.Sign(s.privateKey, digest, opts)
}