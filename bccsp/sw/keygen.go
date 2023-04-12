package sw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/232425wxy/rocen/bccsp"
)

type ecdsaKeyGenerator struct {
	curve elliptic.Curve
}

// KeyGen 返回一个 *ecdsaKeyGenerator 实例。
func (kg *ecdsaKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privateKey, err := ecdsa.GenerateKey(kg.curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ecdsaPrivateKey{privateKey: privateKey}, nil
}

type aesKeyGenerator struct {
	length int
}

// KeyGen 返回一个 *aesPrivateKey 实例。
func (kg *aesKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	lowLevelKey, err := GetRandomBytes(kg.length)
	if err != nil {
		return nil, err
	}
	return &aesPrivateKey{privKey: lowLevelKey, exportable: false}, nil
}