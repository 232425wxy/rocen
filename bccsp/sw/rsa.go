package sw

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"github.com/232425wxy/rocen/bccsp"
)

type rsaPublicKey struct {
	publicKey *rsa.PublicKey
}

// Bytes 调用 x509.MarshalPKIXPublicKey 方法对 RSA 的公钥进行序列化，然后返回序列化后的结果。
func (k *rsaPublicKey) Bytes() ([]byte, error) {
	if k.publicKey == nil {
		return nil, errors.New("rsa public key is nil")
	}
	raw, err := x509.MarshalPKIXPublicKey(k.publicKey)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// SKI 调用 x509.MarshalPKCS1PublicKey 对 RSA 公钥进行序列化，然后计算序列化得到的结果的 SHA256 哈希值，
// 最后将哈希值返回出来。
func (k *rsaPublicKey) SKI() []byte {
	if k.publicKey == nil {
		return nil
	}
	raw := x509.MarshalPKCS1PublicKey(k.publicKey)
	hash := sha256.Sum256(raw)
	return hash[:]
}

// Symmetric 返回 false，RSA 密钥是非对称的。
func (k *rsaPublicKey) Symmetric() bool {
	return false
}

// Private 返回 false，这是 RSA 公钥。
func (k *rsaPublicKey) Private() bool {
	return false
}

// PublicKey 直接返回自身。
func (k *rsaPublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}