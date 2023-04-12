package sw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLowOrderSignatureECDSA(t *testing.T) {
	for i := 0; i < 10000; i++ {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		hash := sha256.New()

		msg := []byte("fly to the moon")
		digest := hash.Sum(msg)

		sig, err := signECDSA(privateKey, digest, nil)
		require.NoError(t, err)

		ver, err := verifyECDSA(&privateKey.PublicKey, sig, digest, nil)
		require.NoError(t, err)
		require.True(t, ver)
	}
}
