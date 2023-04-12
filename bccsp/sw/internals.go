package sw

import (
	"hash"

	"github.com/232425wxy/rocen/bccsp"
)

type KeyGenerator interface {
	KeyGen(bccsp.KeyGenOpts) (bccsp.Key, error)
}

type KeyDeriver interface {
	KeyDerive(bccsp.Key, bccsp.KeyDeriveOpts) (bccsp.Key, error)
}

type KeyImporter interface {
	KeyImport(interface{}, bccsp.KeyImportOpts) (bccsp.Key, error)
}

type Encryptor interface {
	Encrypt(key bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) (ciphertext []byte, err error)
}

type Decryptor interface {
	Decrypt(key bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error)
}

type Signer interface {
	Sign(key bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error)
}

type Verifier interface {
	Verify(key bccsp.Key, signature []byte, digest []byte, opts bccsp.SignerOpts) (valid bool, err error)
}

type Hasher interface {
	Hash(msg []byte, opts bccsp.HashOpts) (hash []byte, err error)
	GetHash(opts bccsp.HashOpts) (h hash.Hash, err error)
}
