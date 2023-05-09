package sw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"github.com/232425wxy/rocen/bccsp"
)

// /////////////////////////////////////////////////////////////////
// ECDSA Key

type ecdsaPrivateKey struct {
	privateKey *ecdsa.PrivateKey
}

var _ = bccsp.Key(&ecdsaPrivateKey{})

func (key *ecdsaPrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("Not supported.")
}

func (key *ecdsaPrivateKey) SKI() []byte {
	if key.privateKey == nil {
		return nil
	}

	// 对公钥进行序列化。
	raw := elliptic.Marshal(key.privateKey.Curve, key.privateKey.X, key.privateKey.Y)

	// 公钥序列化后，求其哈希值。
	hash := sha256.New()
	return hash.Sum(raw)
}

func (key *ecdsaPrivateKey) Symmetric() bool {
	return false
}

func (key *ecdsaPrivateKey) Private() bool {
	return true
}

func (key *ecdsaPrivateKey) PublicKey() (bccsp.Key, error) {
	if key.privateKey == nil {
		return nil, nil
	}
	return &ecdsaPublicKey{publicKey: &key.privateKey.PublicKey}, nil
}


type ecdsaPublicKey struct {
	publicKey *ecdsa.PublicKey
}

var _ = bccsp.Key(&ecdsaPublicKey{})

func (key *ecdsaPublicKey) Bytes() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(key.publicKey)
}

func (key *ecdsaPublicKey) SKI() []byte {
	if key.publicKey == nil {
		return nil
	}

	raw := elliptic.Marshal(key.publicKey.Curve, key.publicKey.X, key.publicKey.Y)

	hash := sha256.New()
	return hash.Sum(raw)
}

func (key *ecdsaPublicKey) Symmetric() bool {
	return false
}

func (key *ecdsaPublicKey) Private() bool {
	return false
}

func (key *ecdsaPublicKey) PublicKey() (bccsp.Key, error) {
	return key, nil
}