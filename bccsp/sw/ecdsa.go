package sw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/232425wxy/rocen/bccsp"
	"github.com/232425wxy/rocen/bccsp/utils"
)

///////////////////////////////////////////////////////////////////
// ECDSA 签名和验签

type ecdsaSigner struct {}

func (s *ecdsaSigner) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return signECDSA(k.(*ecdsaPrivateKey).privateKey, digest, opts)
}

type ecdsaPrivateKeyVerifier struct{}

func (v *ecdsaPrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifyECDSA(&(k.(*ecdsaPrivateKey).privateKey.PublicKey), signature, digest, opts)
}

type ecdsaPublicKeyVerifier struct{}

func (v *ecdsaPublicKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifyECDSA(k.(*ecdsaPublicKey).publicKey, signature, digest, opts)
}

func signECDSA(k *ecdsa.PrivateKey, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, k, digest)
	if err != nil {
		return nil, err
	}
	s, err = utils.ToLowS(&k.PublicKey, s)
	if err != nil {
		return nil, err
	}
	return utils.MarshalECDSASignature(utils.ECDSASignature{R: r, S: s})
}

func verifyECDSA(k *ecdsa.PublicKey, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	sig, err := utils.UnmarshalECDSASignature(signature)
	if err != nil {
		return false, err
	}
	lowS, err := utils.IsLowS(k, sig.S)
	if err != nil {
		return false, err
	}
	if !lowS {
		return false, fmt.Errorf("invalid S, must be smaller than half the order [%s][%s]", sig.S, utils.GetCurveHalfOrderAt(k.Curve))
	}
	return ecdsa.Verify(k, digest, sig.R, sig.S), nil
}

///////////////////////////////////////////////////////////////////
// ECDSA 的私钥

type ecdsaPrivateKey struct {
	privateKey *ecdsa.PrivateKey
}

// Bytes ECDSA 的密钥不支持这个功能，调用此方法会返回一个错误。
func (k *ecdsaPrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("not supported")
}

// SKI 利用 elliptic.Marshal 方法将 ECDSA 私钥对应的公钥序列化，得到一串字节切片，
// 接着再计算这串切片的 SHA256 哈希值。
func (k *ecdsaPrivateKey) SKI() []byte {
	if k.privateKey == nil {
		return nil
	}
	raw := elliptic.Marshal(k.privateKey.Curve, k.privateKey.PublicKey.X, k.privateKey.PublicKey.Y)

	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric 返回 false，表示 ECDSA 密钥是非对称的。
func (k *ecdsaPrivateKey) Symmetric() bool {
	return false
}

// Private 返回 true，表示这是 ECDSA 的私钥。
func (k *ecdsaPrivateKey) Private() bool {
	return true
}

// PublicKey 返回 ECDSA 私钥对应的公钥。
func (k *ecdsaPrivateKey) PublicKey() (bccsp.Key, error) {
	return &ecdsaPublicKey{publicKey: &k.privateKey.PublicKey}, nil
}

///////////////////////////////////////////////////////////////////
// ECDSA 的公钥

type ecdsaPublicKey struct {
	publicKey *ecdsa.PublicKey
}

// Bytes 调用 x509.MarshalPKIXPublicKey 方法对 ECDSA 的公钥进行序列化，然后返回序列化后的结果。
func (k *ecdsaPublicKey) Bytes() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(k.publicKey)
}

// SKI 调用 elliptic.Marshal 对 ECDSA 的公钥进行序列化，得到一串字节切片，然后计算这串字节切片
// 的 SHA256 哈希值，最后将哈希值返回。
func (k *ecdsaPublicKey) SKI() []byte {
	if k.publicKey == nil {
		return nil
	}
	raw := elliptic.Marshal(k.publicKey.Curve, k.publicKey.X, k.publicKey.Y)
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric 返回 false，表示 ECDSA 公钥是非对称的。
func (k *ecdsaPublicKey) Symmetric() bool {
	return false
}

// Private 返回 false，表示这是 ECDSA 公钥。
func (k *ecdsaPublicKey) Private() bool {
	return false
}

// PublicKey 返回自己。
func (k *ecdsaPublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}
