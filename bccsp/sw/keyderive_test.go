package sw

import (
	"testing"

	mock2 "github.com/232425wxy/rocen/bccsp/mock"
	"github.com/stretchr/testify/require"
)

// func TestKeyDeriv(t *testing.T) {
// 	t.Parallel()

// 	expectedKey := &mock2.MockKey{BytesValue: []byte{1, 2, 3}}
// 	expectedOpts := &mock2.KeyDerivOpts{EphemeralValue: true}
// 	expectetValue := &mock2.MockKey{BytesValue: []byte{1, 2, 3, 4, 5}}
// 	expectedErr := errors.New("Expected Error")

// 	keyDerivers := make(map[reflect.Type]KeyDeriver)
// 	keyDerivers[reflect.TypeOf(&mock2.MockKey{})] = &mock.KeyDeriver{
// 		KeyArg:  expectedKey,
// 		OptsArg: expectedOpts,
// 		Value:   expectetValue,
// 		Err:     expectedErr,
// 	}
// 	csp := CSP{KeyDerivers: keyDerivers}
// 	value, err := csp.KeyDerive(expectedKey, expectedOpts)
// 	require.Nil(t, value)
// 	require.Contains(t, err.Error(), expectedErr.Error())

// 	keyDerivers = make(map[reflect.Type]KeyDeriver)
// 	keyDerivers[reflect.TypeOf(&mock2.MockKey{})] = &mock.KeyDeriver{
// 		KeyArg:  expectedKey,
// 		OptsArg: expectedOpts,
// 		Value:   expectetValue,
// 		Err:     nil,
// 	}
// 	csp = CSP{KeyDerivers: keyDerivers}
// 	value, err = csp.KeyDerive(expectedKey, expectedOpts)
// 	require.Equal(t, expectetValue, value)
// 	require.Nil(t, err)
// }

func TestECDSAPublicKeyKeyDeriver(t *testing.T) {
	t.Parallel()

	kd := ecdsaPublicKeyDeriver{}

	_, err := kd.KeyDerive(&mock2.MockKey{}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid opts parameter, it must not be nil")

	_, err = kd.KeyDerive(&ecdsaPublicKey{}, &mock2.KeyDerivOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported 'KeyDeriveOpts' provided [")
}

func TestECDSAPrivateKeyKeyDeriver(t *testing.T) {
	t.Parallel()

	kd := ecdsaPrivateKeyDeriver{}

	_, err := kd.KeyDerive(&mock2.MockKey{}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid opts parameter, it must not be nil")

	_, err = kd.KeyDerive(&ecdsaPrivateKey{}, &mock2.KeyDerivOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported 'KeyDeriveOpts' provided [")
}

func TestAESPrivateKeyKeyDeriver(t *testing.T) {
	t.Parallel()

	kd := aesPrivateKeyDeriver{}

	_, err := kd.KeyDerive(&mock2.MockKey{}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid opts parameter, it must not be nil")

	_, err = kd.KeyDerive(&aesPrivateKey{}, &mock2.KeyDerivOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported 'KeyDeriveOpts' provided [")
}
