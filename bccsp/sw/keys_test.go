package sw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestECDSAPrivateKeyToDER(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	t.Log(privateKey)
	der, err := ecdsaPrivateKeyToDER(privateKey)
	assert.NoError(t, err)
	t.Log(der)
}

func TestIsNeedToContinueVerifyNilAfterTypeAssert(t *testing.T) {
	var key *ecdsa.PrivateKey
	t.Log(test(key))
}

func test(key interface{}) string {
	if key == nil {
		return "判断interface{}是否为nil的测试没通过"
	}
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if k == nil {
			return "判断interface{}是否为nil的测试被通过了,但是switch-case里判断是否为nil时没通过"
		}
	default:
		return "变量类型不对"
	}
	return "判断是否为nil的测试被通过了"
}

func TestBigIntBitLen(t *testing.T) {
	curve := elliptic.P256()
	bitLen := curve.Params().N.BitLen()
	t.Log(bitLen)

	privateKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
	t.Log(len(privateKey.D.Bytes()))
}

func TestCompareECPublicKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	pubX, pubY := privateKey.X, privateKey.Y

	publicKeyX, publicKeyY := elliptic.P256().ScalarBaseMult(privateKey.D.Bytes())

	assert.Equal(t, 0, pubX.Cmp(publicKeyX))
	assert.Equal(t, 0, pubY.Cmp(publicKeyY))
}

func TestECDSAPrivateKeyToPEM(t *testing.T) {
	curve := elliptic.P256()
	privateKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
	pemBytes, err := ecdsaPrivateKeyToPEM(privateKey, nil)
	assert.NoError(t, err)
	fmt.Println(string(pemBytes))
}

func TestECDSAPrivateKeyToEncryptedPEM(t *testing.T) {
	curve := elliptic.P256()
	privateKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
	pemBytes1, err := ecdsaPrivateKeyToPEM(privateKey, []byte("123456"))
	assert.NoError(t, err)
	fmt.Println(string(pemBytes1))

	pemBytes2, err := ecdsaPrivateKeyToPEM(privateKey, nil)
	assert.NoError(t, err)
	fmt.Println(string(pemBytes2))
}

func TestECDSAPublicKeyToPEM(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKey := privateKey.PublicKey

	pem1, err := ecdsaPublicKeyToPEM(&publicKey, nil)
	assert.NoError(t, err)
	fmt.Println(string(pem1))

	pem2, err := ecdsaPublicKeyToPEM(&publicKey, []byte("123456"))
	assert.NoError(t, err)
	fmt.Println(string(pem2))
}