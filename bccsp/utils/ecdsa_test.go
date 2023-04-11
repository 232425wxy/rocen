package utils_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/232425wxy/rocen/bccsp/utils"
	"github.com/stretchr/testify/require"
)

func TestCurveHalfOrders(t *testing.T) {
	orders := map[elliptic.Curve]*big.Int{
		elliptic.P224(): new(big.Int).Rsh(elliptic.P224().Params().N, 1),
		elliptic.P256(): new(big.Int).Rsh(elliptic.P256().Params().N, 1),
		elliptic.P384(): new(big.Int).Rsh(elliptic.P384().Params().N, 1),
		elliptic.P521(): new(big.Int).Rsh(elliptic.P521().Params().N, 1),
	}

	for key, value := range orders {
		t.Log(key.Params().N, "=>", value)
	}
}

func TestMarshalECDSASignature(t *testing.T) {
	r := elliptic.P224().Params().N
	s := elliptic.P256().Params().N
	sig := utils.ECDSASignature{R: r, S: s}
	bz, err := utils.MarshalECDSASignature(sig)
	require.NoError(t, err)
	t.Log(bz)
}

func TestSignatureToLowS(t *testing.T) {
	lowLevelKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	s := new(big.Int)
	s = s.Set(utils.GetCurveHalfOrderAt(elliptic.P256()))
	s = s.Add(s, big.NewInt(1))

	lowS, err := utils.IsLowS(&lowLevelKey.PublicKey, s)
	require.NoError(t, err)
	require.False(t, lowS)
	sig := utils.ECDSASignature{R: big.NewInt(1), S: s}
	sigma, err := utils.MarshalECDSASignature(sig)
	require.NoError(t, err)
	sigma2, err := utils.SignatureToLowS(&lowLevelKey.PublicKey, sigma)
	require.NoError(t, err)
	sig, err = utils.UnmarshalECDSASignature(sigma2)
	require.NoError(t, err)
	lowS, err = utils.IsLowS(&lowLevelKey.PublicKey, sig.S)
	require.NoError(t, err)
	require.True(t, lowS)
}
