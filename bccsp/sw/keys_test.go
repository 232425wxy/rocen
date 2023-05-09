package sw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestOidFromNamedCurve(t *testing.T) {
	var (
		oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
		oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
		oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
		oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	)

	type result struct {
		oid asn1.ObjectIdentifier
		ok  bool
	}

	var tests = []struct {
		name     string
		curve    elliptic.Curve
		expected result
	}{
		{
			name:  "P224",
			curve: elliptic.P224(),
			expected: result{
				oid: oidNamedCurveP224,
				ok:  true,
			},
		},
		{
			name:  "P256",
			curve: elliptic.P256(),
			expected: result{
				oid: oidNamedCurveP256,
				ok:  true,
			},
		},
		{
			name:  "P384",
			curve: elliptic.P384(),
			expected: result{
				oid: oidNamedCurveP384,
				ok:  true,
			},
		},
		{
			name:  "P521",
			curve: elliptic.P521(),
			expected: result{
				oid: oidNamedCurveP521,
				ok:  true,
			},
		},
		{
			name:  "T-1000",
			curve: &elliptic.CurveParams{Name: "T-1000"},
			expected: result{
				oid: nil,
				ok:  false,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oid, ok := oidFromNamedCurve(test.curve)
			require.Equal(t, oid, test.expected.oid)
			require.Equal(t, ok, test.expected.ok)
		})
	}

}

func TestECDSAKeys(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	// Private Key DER format
	der, err := ecdsaPrivateKeyToDER(key)
	if err != nil {
		t.Fatalf("Failed converting private key to DER [%s]", err)
	}
	keyFromDER, err := derToPrivateKey(der)
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}
	ecdsaKeyFromDer := keyFromDER.(*ecdsa.PrivateKey)
	// TODO: check the curve
	if key.D.Cmp(ecdsaKeyFromDer.D) != 0 {
		t.Fatal("Failed converting DER to private key. Invalid D.")
	}
	if key.X.Cmp(ecdsaKeyFromDer.X) != 0 {
		t.Fatal("Failed converting DER to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(ecdsaKeyFromDer.Y) != 0 {
		t.Fatal("Failed converting DER to private key. Invalid Y coordinate.")
	}

	// Private Key PEM format
	rawPEM, err := ecdsaPrivateKeyToPEM(key, nil)
	if err != nil {
		t.Fatalf("Failed converting private key to PEM [%s]", err)
	}
	pemBlock, _ := pem.Decode(rawPEM)
	if pemBlock.Type != "PRIVATE KEY" {
		t.Fatalf("Expected type 'PRIVATE KEY' but found '%s'", pemBlock.Type)
	}
	_, err = x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse PKCS#8 private key [%s]", err)
	}
	keyFromPEM, err := pemToPrivateKey(rawPEM, nil)
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}
	ecdsaKeyFromPEM := keyFromPEM.(*ecdsa.PrivateKey)
	// TODO: check the curve
	if key.D.Cmp(ecdsaKeyFromPEM.D) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid D.")
	}
	if key.X.Cmp(ecdsaKeyFromPEM.X) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(ecdsaKeyFromPEM.Y) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid Y coordinate.")
	}

	// Nil Private Key <-> PEM
	_, err = ecdsaPrivateKeyToPEM(nil, nil)
	if err == nil {
		t.Fatal("PublicKeyToPEM should fail on nil")
	}

	_, err = ecdsaPrivateKeyToPEM((*ecdsa.PrivateKey)(nil), nil)
	if err == nil {
		t.Fatal("PrivateKeyToPEM should fail on nil")
	}

	_, err = pemToPrivateKey(nil, nil)
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on nil")
	}

	_, err = pemToPrivateKey([]byte{0, 1, 3, 4}, nil)
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail invalid PEM")
	}

	_, err = derToPrivateKey(nil)
	if err == nil {
		t.Fatal("DERToPrivateKey should fail on nil")
	}

	_, err = derToPrivateKey([]byte{0, 1, 3, 4})
	if err == nil {
		t.Fatal("DERToPrivateKey should fail on invalid DER")
	}

	_, err = ecdsaPrivateKeyToDER(nil)
	if err == nil {
		t.Fatal("DERToPrivateKey should fail on nil")
	}

	// Private Key Encrypted PEM format
	encPEM, err := ecdsaPrivateKeyToPEM(key, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting private key to encrypted PEM [%s]", err)
	}
	_, err = pemToPrivateKey(encPEM, nil)
	require.Error(t, err)
	encKeyFromPEM, err := pemToPrivateKey(encPEM, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}
	ecdsaKeyFromEncPEM := encKeyFromPEM.(*ecdsa.PrivateKey)
	// TODO: check the curve
	if key.D.Cmp(ecdsaKeyFromEncPEM.D) != 0 {
		t.Fatal("Failed converting encrypted PEM to private key. Invalid D.")
	}
	if key.X.Cmp(ecdsaKeyFromEncPEM.X) != 0 {
		t.Fatal("Failed converting encrypted PEM to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(ecdsaKeyFromEncPEM.Y) != 0 {
		t.Fatal("Failed converting encrypted PEM to private key. Invalid Y coordinate.")
	}

	// Public Key PEM format
	rawPEM, err = ecdsaPublicKeyToPEM(&key.PublicKey, nil)
	if err != nil {
		t.Fatalf("Failed converting public key to PEM [%s]", err)
	}
	pemBlock, _ = pem.Decode(rawPEM)
	if pemBlock.Type != "PUBLIC KEY" {
		t.Fatalf("Expected type 'PUBLIC KEY' but found '%s'", pemBlock.Type)
	}
	keyFromPEM, err = pemToPublicKey(rawPEM, nil)
	if err != nil {
		t.Fatalf("Failed converting DER to public key [%s]", err)
	}
	ecdsaPkFromPEM := keyFromPEM.(*ecdsa.PublicKey)
	// TODO: check the curve
	if key.X.Cmp(ecdsaPkFromPEM.X) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(ecdsaPkFromPEM.Y) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid Y coordinate.")
	}

	// Nil Public Key <-> PEM
	_, err = ecdsaPublicKeyToPEM(nil, nil)
	if err == nil {
		t.Fatal("PublicKeyToPEM should fail on nil")
	}

	_, err = pemToPublicKey(nil, nil)
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on nil")
	}

	_, err = pemToPublicKey([]byte{0, 1, 3, 4}, nil)
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on invalid PEM")
	}

	// Public Key Encrypted PEM format
	encPEM, err = ecdsaPublicKeyToPEM(&key.PublicKey, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting private key to encrypted PEM [%s]", err)
	}
	_, err = pemToPublicKey(encPEM, nil)
	require.Error(t, err)
	pkFromEncPEM, err := pemToPublicKey(encPEM, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}
	ecdsaPkFromEncPEM := pkFromEncPEM.(*ecdsa.PublicKey)
	// TODO: check the curve
	if key.X.Cmp(ecdsaPkFromEncPEM.X) != 0 {
		t.Fatal("Failed converting encrypted PEM to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(ecdsaPkFromEncPEM.Y) != 0 {
		t.Fatal("Failed converting encrypted PEM to private key. Invalid Y coordinate.")
	}

	_, err = pemToPublicKey(encPEM, []byte("passw"))
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on wrong password")
	}

	_, err = pemToPublicKey(encPEM, []byte("passw"))
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on nil password")
	}

	_, err = pemToPublicKey(nil, []byte("passwd"))
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on nil PEM")
	}

	_, err = pemToPublicKey([]byte{0, 1, 3, 4}, []byte("passwd"))
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on invalid PEM")
	}

	_, err = pemToPublicKey(nil, []byte("passw"))
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on nil PEM and wrong password")
	}

	// Public Key DER format
	der, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	keyFromDER, err = derToPublicKey(der)
	require.NoError(t, err)
	ecdsaPkFromPEM = keyFromDER.(*ecdsa.PublicKey)
	// TODO: check the curve
	if key.X.Cmp(ecdsaPkFromPEM.X) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(ecdsaPkFromPEM.Y) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid Y coordinate.")
	}
}

func TestAESKey(t *testing.T) {
	k := []byte{0, 1, 2, 3, 4, 5}
	pem := aesToPEM(k)

	k2, err := pemToAES(pem, nil)
	require.NoError(t, err)
	require.Equal(t, k, k2)

	pem, err = aesToEncryptedPEM(k, k)
	require.NoError(t, err)

	k2, err = pemToAES(pem, k)
	require.NoError(t, err)
	require.Equal(t, k, k2)

	_, err = pemToAES(pem, nil)
	require.Error(t, err)

	_, err = aesToEncryptedPEM(k, nil)
	require.NoError(t, err)

	k2, err = pemToAES(pem, k)
	require.NoError(t, err)
	require.Equal(t, k, k2)
}

func TestDERToPublicKey(t *testing.T) {
	_, err := derToPublicKey(nil)
	require.Error(t, err)
}

func TestNil(t *testing.T) {
	_, err := ecdsaPrivateKeyToEncryptedPEM(nil, nil)
	require.Error(t, err)

	_, err = ecdsaPrivateKeyToEncryptedPEM((*ecdsa.PrivateKey)(nil), nil)
	require.Error(t, err)

	_, err = ecdsaPrivateKeyToEncryptedPEM("Hello World", nil)
	require.Error(t, err)

	_, err = pemToAES(nil, nil)
	require.Error(t, err)

	_, err = aesToEncryptedPEM(nil, nil)
	require.Error(t, err)

	_, err = ecdsaPublicKeyToPEM(nil, nil)
	require.Error(t, err)
	_, err = ecdsaPublicKeyToPEM((*ecdsa.PublicKey)(nil), nil)
	require.Error(t, err)
	_, err = ecdsaPublicKeyToPEM(nil, []byte("hello world"))
	require.Error(t, err)

	_, err = ecdsaPublicKeyToPEM("hello world", nil)
	require.Error(t, err)
	_, err = ecdsaPublicKeyToPEM("hello world", []byte("hello world"))
	require.Error(t, err)

	_, err = ecdsaPublicKeyToEncryptedPEM(nil, nil)
	require.Error(t, err)
	_, err = ecdsaPublicKeyToEncryptedPEM((*ecdsa.PublicKey)(nil), nil)
	require.Error(t, err)
	_, err = ecdsaPublicKeyToEncryptedPEM("hello world", nil)
	require.Error(t, err)
	_, err = ecdsaPublicKeyToEncryptedPEM("hello world", []byte("Hello world"))
	require.Error(t, err)
}
