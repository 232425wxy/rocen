package sw

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/232425wxy/rocen/bccsp"
)

type rsaPublicKey struct {
	publicKey *rsa.PublicKey
}

var _ = bccsp.Key(&rsaPublicKey{})

func (key *rsaPublicKey) Bytes() ([]byte, error) {
	if key.publicKey == nil {
		return nil, errors.New("failed marshalling key, key is nil")
	}

	raw, err := x509.MarshalPKIXPublicKey(key.publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling key [%s]", err.Error())
	}

	return raw, nil
}

func (key *rsaPublicKey) Symmetric() bool {
	return false
}

func (key *rsaPublicKey) Private() bool {
	return false
}

func (key *rsaPublicKey) SKI() []byte {
	raw, _ := key.Bytes()
	if raw == nil {
		return nil
	}
	hash := sha256.New()
	return hash.Sum(raw)
}

func (key *rsaPublicKey) PublicKey() (bccsp.Key, error) {
	return key, nil
}
