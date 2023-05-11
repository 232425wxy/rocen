package sw

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/232425wxy/rocen/bccsp"
)

// /////////////////////////////////////////////////////////////////
// aes256ImportKeyOptsKeyImporter 导入 256 比特长的 AES 密钥。
type aes256ImportKeyOptsKeyImporter struct{}

func (*aes256ImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	aesRaw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("invalid AES raw material, it must be bytes")
	}

	if len(aesRaw) != 32 {
		return nil, fmt.Errorf("invalid AES256 key length, got [%d]", len(aesRaw))
	}

	return &aesKey{key: aesRaw, exportable: false}, nil
}

// /////////////////////////////////////////////////////////////////
// hmacImportKeyOptsKeyImporter 导入 AES 密钥，长度不限。
type hmacImportKeyOptsKeyImporter struct{}

func (*hmacImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	aesRaw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("invalid AES raw material, it must be bytes")
	}

	if len(aesRaw) == 0 {
		return nil, errors.New("invalid AES key, it must be different from nil")
	}

	return &aesKey{key: aesRaw, exportable: false}, nil
}

// /////////////////////////////////////////////////////////////////
// ecdsaPKIXpublicKeyImportOptsKeyImporter 导入 ECDSA 公钥。
type ecdsaPKIXpublicKeyImportOptsKeyImporter struct{}

func (*ecdsaPKIXpublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("invalid ECDSA key DER material, it must be bytes")
	}

	if len(der) == 0 {
		return nil, errors.New("invalid raw, it must be different from nil")
	}

	key, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed converting PKIX to ECDSA public key [%s]", err)
	}

	publicKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed casting to ECDSA public key, invalid raw material")
	}

	return &ecdsaPublicKey{publicKey: publicKey}, nil
}

// /////////////////////////////////////////////////////////////////
// ecdsaPrivateKeyImportOptsKeyImporter 导入 ECDSA 私钥。
type ecdsaPrivateKeyImportOptsKeyImporter struct{}

func (*ecdsaPrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("invalid ECDSA key DER material, it must be bytes")
	}

	if len(der) == 0 {
		return nil, errors.New("invalid raw, it must be different from nil")
	}

	key, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed converting PKIX to ECDSA private key [%s]", err)
	}

	privateKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("failed casting to ECDSA private key, invalid raw material")
	}

	return &ecdsaPrivateKey{privateKey: privateKey}, nil
}

///////////////////////////////////////////////////////////////////
// ecdsaGoPublicKeyImportOptsKeyImporter
type ecdsaGoPublicKeyImportOptsKeyImporter struct{}

func (*ecdsaGoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	key, ok := raw.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid raw material, expected *ecdsa.PublicKey")
	}

	return &ecdsaPublicKey{publicKey: key}, nil
}

