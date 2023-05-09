package sw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestECDSAPublicKeyBytes(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	publicKey := privateKey.PublicKey

	ecdsaPublicKey := &ecdsaPublicKey{publicKey: &publicKey}
	bz, err := ecdsaPublicKey.Bytes()
	assert.NoError(t, err)
	fmt.Printf("%s\n", bz)
}
