package bccsp

import (
	"crypto"
	"hash"
)

type Key interface {
	Bytes() ([]byte, error)
	SKI() []byte
	// Symmetric 方法返回 true 的话，则代表该密钥是对称密钥，否则是非对称密钥。
	Symmetric() bool
	Private() bool
	PublicKey() (Key, error)
}

type KeyGenOpts interface {
	// Algorithm 返回密钥生成算法的标识符。
	Algorithm() string
	Ephemeral() bool
}

type KeyDeriveOpts interface {
	// Algorithm 返回密钥派生算法的标识符。
	Algorithm() string
	Ephemeral() bool
}

type KeyImportOpts interface {
	// Algorithm 返回密钥导入算法的标识符。
	Algorithm() string
	Ephemeral() bool
}

type HashOpts interface {
	// Algorithm 返回哈希算法的标识符。
	Algorithm() string
}

type SignerOpts interface {
	crypto.SignerOpts
}

type EncrypterOpts interface{}

type DecrypterOpts interface{}

type BCCSP interface {
	KeyGen(opts KeyGenOpts) (key Key, err error)
	KeyDerive(key Key, opts KeyDeriveOpts) (dk Key, err error)
	KeyImport(raw interface{}, opts KeyImportOpts) (key Key, err error)
	GetKey(ski []byte) (key Key, err error)
	Hash(msg []byte, opts HashOpts) ([]byte, error)
	GetHash(opts HashOpts) (hash hash.Hash, err error)
	Sign(key Key, digest []byte, opts SignerOpts) (signature []byte, err error)
	Verify(key Key, digest []byte, opts SignerOpts) (valid bool, err error)
	Encrypt(key Key, plaintext []byte, opts EncrypterOpts) (ciphertext []byte, err error)
	Decrypt(key Key, ciphertext []byte, opts DecrypterOpts) (plaintext []byte, err error)
}

type KeyStore interface {
	ReadOnly() bool
	GetKey(ski []byte) (key Key, err error)
	StoreKey(key Key) (err error)
}