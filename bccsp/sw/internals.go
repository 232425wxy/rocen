package sw

import (
	"hash"

	"github.com/232425wxy/rocen/bccsp"
)

// /////////////////////////////////////////////////////////////////
// KeyGenerator 生成密钥的接口。
type KeyGenerator interface {
	KeyGen(opts bccsp.KeyGenOpts) (key bccsp.Key, err error)
}

// /////////////////////////////////////////////////////////////////
// KeyDeriver 衍生密钥的接口。
type KeyDeriver interface {
	KeyDeriv(key bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error)
}

// /////////////////////////////////////////////////////////////////
// KeyImporter 导入密钥的接口。
type KeyImporter interface {
	KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (key bccsp.Key, err error)
}

// /////////////////////////////////////////////////////////////////
// Encryptor 加密数据接口。
type Encryptor interface {
	Encrypt(key bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) (ciphertext []byte, err error)
}

// /////////////////////////////////////////////////////////////////
// Decryptor 解密数据接口。
type Decryptor interface {
	Decrypt(key bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error)
}

// /////////////////////////////////////////////////////////////////
// Signer 数字签名接口。
type Signer interface {
	Sign(key bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error)
}

// /////////////////////////////////////////////////////////////////
// Verifier 验证数字签名接口。
type Verifier interface {
	Verify(key bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error)
}

// /////////////////////////////////////////////////////////////////
// Hasher 数据哈希接口。
type Hasher interface {
	Hash(msg []byte, opts bccsp.HashOpts) (hash []byte, err error)
	GetHash(opts bccsp.HashOpts) (h hash.Hash, err error)
}
