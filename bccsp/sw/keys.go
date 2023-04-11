package sw

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func pemToAES(raw []byte, pwd []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid PEM, it must be different from nil")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("failed decoding PEM, block must be different from nil [% x]", raw)
	}
	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("encrypted key, password must be different fom nil")
		}

		decrypted, err := x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("failed PEM decryption: [%s]", err)
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
		return nil, errors.New("invalid aes key. It must be different from nil")
	}
	if len(pwd) == 0 {
		return aesToPEM(raw), nil
	}

	block, err := x509.EncryptPEMBlock(
		rand.Reader,
		"AES PRIVATE KEY",
		raw,
		pwd,
		x509.PEMCipherAES256)

	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(block), nil
}
