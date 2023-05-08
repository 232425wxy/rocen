package sw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
)

///////////////////////////////////////////////////////////////////
// pkcs8Info 的全称是 Public-Key Cryptography Standard 8，公钥密码标准 8，
// pkcs8 用来存储私钥，存储的私钥会使用 pkcs5 标准进行加密，然后进行
// base64 编码，转换成 PEM 格式进行存储。
type pkcs8Info struct {
	Version             int
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

///////////////////////////////////////////////////////////////////
// ecPrivateKey 椭圆曲线密钥。
type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

var oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	default:
		return nil, false
	}
}

// ecdsaPrivateKeyToDER
func ecdsaPrivateKeyToDER(key *ecdsa.PrivateKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("invalid ecdsa private key, it must be different from nil")
	}
	return x509.MarshalECPrivateKey(key)
}

// ecdsaPrivateKeyToPEM 将椭圆曲线签名转换为 PEM 格式，如果无需加密存储，即 pwd 等于 nil 时，
// 转换结果如下例子所示：
// -----BEGIN PRIVATE KEY-----
// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgk6KZ7xl5UhNcuJs/
// RQTJKmbV1JNk1EWehXDmdtrlss+hRANCAAQOkBxplJyalVTyhB2LfLWh2sg9ZD63
// In+DR5tvZ9WCD2w/ardz3dNVKTMaUVoY0yhcV7pYi608DeMKxoERdQ8W
// -----END PRIVATE KEY-----
// 如果需要加密存储，即 pwd 不等于 nil，转换结果如下例子所示：
// -----BEGIN PRIVATE KEY-----
// Proc-Type: 4,ENCRYPTED
// DEK-Info: AES-256-CBC,95fab0a7bb826548ff61a4f87e6c63ac
//
// Uz/BV6wiHxt8V5NwQDb7zUssGT79HgZhxT01tjulYSJnqtQ2LcPTDpYZQUfksrwL
// e2k8M4tMlsVZN12KtwjdxZxKFcy8Q0hjoxj+TIsqHRQ2uCGvInye2cZHSmsjQQ6K
// lr0y/A35e3M9OxXB8qZqFM4DOMkAsJfuN9fKlyrwK/4=
// -----END PRIVATE KEY-----
func ecdsaPrivateKeyToPEM(privateKey interface{}, pwd []byte) ([]byte, error) {
	if len(pwd) != 0 {
		return ecdsaPrivateKeyToEncryptedPEM(privateKey, pwd)
	}
	if privateKey == nil {
		return nil, errors.New("invalid private key, it must be different from nil")
	}

	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		if key == nil {
			return nil, errors.New("invalid ecdsa private key, it must be different from nil")
		}

		oidNamedCurve, ok := oidFromNamedCurve(key.Curve)
		if !ok {
			return nil, errors.New("unknown elliptic curve")
		}

		privateKeyBytes := key.D.Bytes()
		// 如果所基于的椭圆曲线的安全级别为 256 | 224 | 384，那么 paddedPrivateKey 的长度就是 256 | 224 | 384。
		paddedPrivateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
		copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)
		asn1Bytes, err := asn1.Marshal(ecPrivateKey{
			Version:    1,
			PrivateKey: paddedPrivateKey,
			PublicKey:  asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)},
		})
		if err != nil {
			return nil, fmt.Errorf("error marshaling EC key to asn1: [%s]", err)
		}

		var pkcs8Key pkcs8Info = pkcs8Info{
			Version:             0,
			PrivateKeyAlgorithm: make([]asn1.ObjectIdentifier, 2),
			PrivateKey:          asn1Bytes,
		}
		pkcs8Key.PrivateKeyAlgorithm[0] = oidPublicKeyECDSA
		pkcs8Key.PrivateKeyAlgorithm[1] = oidNamedCurve
		pkcs8Key.PrivateKey = asn1Bytes

		pkcs8Bytes, err := asn1.Marshal(pkcs8Key)
		if err != nil {
			return nil, fmt.Errorf("error marshaling EC key to asn1: [%s]", err)
		}

		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes}), nil
	default:
		return nil, errors.New("invalid key type, it must be *ecdsa.PrivateKey")
	}
}

func ecdsaPrivateKeyToEncryptedPEM(privateKey interface{}, pwd []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("invalid private key, it must be different from nil")
	}

	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		if key == nil {
			// 尽管 interface{} 不为 nil，但是到这里后依然可能等于 nil。
			return nil, errors.New("invalid ecdsa private key, it must be different from nil")
		}
		raw, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}

		block, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", raw, pwd, x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(block), nil
	default:
		return nil, errors.New("invalid private key type, it must be *ecdsa.PrivateKey")
	}
}

func derToPrivateKey(der []byte) (key interface{}, err error) {
	// 解析 RSA 密钥。
	if key, err = x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	// 可能解析 RSA、ECDSA、ED25519 中其中一种私钥。
	if key, err = x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key.(type) {
		case *ecdsa.PrivateKey:
			return
		default:
			return nil, errors.New("found unknown private key type in PKCS#8 wrapping")
		}
	}

	// 解析 ECDSA 私钥。
	if key, err = x509.ParseECPrivateKey(der); err == nil {
		return
	}

	return nil, errors.New("invalid key type, the der must contain an ecdsa.PrivateKey")
}

func pemToPrivateKey(raw []byte, pwd []byte) (interface{}, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("failed decoding PEM")
	}

	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("key is encrypted, need a password")
		}

		decrypted, err := x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt: [%s]", err)
		}

		key, err := derToPrivateKey(decrypted)
		if err != nil {
			return nil, err
		}
		return key, err
	}

	return derToPrivateKey(block.Bytes)
}

func pemToAES(raw []byte, pwd []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid PEM, it must be different from nil")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("failed decoding PEM")
	}

	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("key is encrypted, need a password")
		}

		decrypted, err := x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt: [%s]", err)
		}
		return decrypted, nil
	}

	return block.Bytes, nil
}

func aesToPEM(raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "AES PRIVATE KEY", Bytes: raw})
}

func aesToEncryptedPEM(raw []byte, pwd []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid aes key, it must be different from nil")
	}
	if len(pwd) == 0 {
		return aesToPEM(raw), nil
	}

	block, err := x509.EncryptPEMBlock(rand.Reader, "AES PRIVATE KEY", raw, pwd, x509.PEMCipherAES256)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(block), nil
}

// ecdsaPublicKeyToPEM 将椭圆曲线公钥转换为 PEM 格式，pwd 是个密码变量，如果 pwd 不为nil，
// 那么在转换过程中会对其进行加密，如下面的例子：
// -----BEGIN PUBLIC KEY-----
// Proc-Type: 4,ENCRYPTED
// DEK-Info: AES-256-CBC,23dbec6faba40c95195df8b1fe7daea0
//
// El7ej0IUeLw0J0F0exz33Er3XU04v8qn1Jl4Z2SnCmxHjJnFlzg20kq0g8QHnNx1
//9aaSNGvxI1ze0DMFlhsxl+UcVb0nQO+1oTgqs7KbfDAfi7ImerILViVFCZCMf7DP
// -----END PUBLIC KEY-----
// 如果 pwd 等于 nil，那么在转换过程中不会加密，如下面的例子：
// -----BEGIN PUBLIC KEY-----
// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXxgbeICpJhDFzJAvRhcQ0AxE9aCx
// cpXXAxeDTAmKwlWx1hkGdjR8Qz37EJOWLEdB+iyJlFO5yqOviI3PmNkeZQ==
// -----END PUBLIC KEY-----
func ecdsaPublicKeyToPEM(publicKey interface{}, pwd []byte) ([]byte, error) {
	if len(pwd) != 0 {
		return ecdsaPublicKeyToEncryptedPEM(publicKey, pwd)
	}

	if publicKey == nil {
		return nil, errors.New("invalid public key, it must be different from nil")
	}

	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		if key == nil {
			return nil, errors.New("invalid ecdsa public key, it must be different from nil")
		}
		pubASN1, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubASN1}), nil
	default:
		return nil, errors.New("invalid key type, it must be *ecdsa.PublicKey")
	}
}

func ecdsaPublicKeyToEncryptedPEM(publicKey interface{}, pwd []byte) ([]byte, error) {
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		if key == nil {
			return nil, errors.New("invalid ecdsa public key, it must be different from nil")
		}
		raw, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, err
		}

		block, err := x509.EncryptPEMBlock(rand.Reader, "PUBLIC KEY", raw, pwd, x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(block), nil

	default:
		return nil, errors.New("invalid key type, it must be *ecdsa.PublicKey")
	}
}

func pemToPublicKey(raw []byte, pwd []byte) (interface{}, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid PEM, it must be different from nil")
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("failed decoding")
	}

	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("public key is encrypted, password must be different from nil")
		}

		decrypted, err := x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt: [%s]", err)
		}

		return derToPublicKey(decrypted)
	}

	return derToPublicKey(block.Bytes)
}

func derToPublicKey(raw []byte) (publicKey interface{}, err error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid DER, it must be different from nil")
	}

	return x509.ParsePKIXPublicKey(raw)
}
