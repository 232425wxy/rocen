package sw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/232425wxy/rocen/bccsp"
)

///////////////////////////////////////////////////////////////////
// ecdsaKeyGenerator 生成 ECDSA 私钥。
type ecdsaKeyGenerator struct {
	curve elliptic.Curve
}

func (kg *ecdsaKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privateKey, err := ecdsa.GenerateKey(kg.curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed generating ECDSA key for [%v]: [%s]", kg.curve, err)
	}

	return &ecdsaPrivateKey{privateKey: privateKey}, nil
}

///////////////////////////////////////////////////////////////////
// aesKeyGenerator 生成 AES 密钥。
type aesKeyGenerator struct {
	length int
}

func (kg *aesKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	raw, err := getRandomBytes(kg.length)
	if err != nil {
		return nil, fmt.Errorf("failed generating AES key [%d]: [%s]", kg.length, err)
	}
	return &aesKey{key: raw, exportable: false}, nil
}

func getRandomBytes(len int) ([]byte, error) {
	if len <= 0 {
		return nil, errors.New("len must be larger than 0")
	}

	buffer := make([]byte, len)

	n, err := rand.Read(buffer)
	if err != nil {
		return nil, err
	}
	if  n != len {
		return nil, fmt.Errorf("random buffer not filled, request [%d], got [%d]", len, n)
	}
	
	return buffer, nil
}