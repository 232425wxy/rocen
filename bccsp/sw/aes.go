package sw

import (
	"crypto/sha256"
	"errors"

	"github.com/232425wxy/rocen/bccsp"
)

///////////////////////////////////////////////////////////////////
// AES Key

type aesKey struct {
	key        []byte
	exportable bool
}

var _ = bccsp.Key(&aesKey{})

func (key *aesKey) Bytes() ([]byte, error) {
	if key.exportable {
		return key.key, nil
	}
	return nil, errors.New("not supported")
}

func (key *aesKey) SKI() []byte {
	hash := sha256.New()
	hash.Write([]byte{0x01})
	hash.Write(key.key)
	return hash.Sum(nil)
}

func (key *aesKey) Symmetric() bool {
	return true
}

func (key *aesKey) Private() bool {
	return true
}

func (key *aesKey) PublicKey() (bccsp.Key, error) {
	return nil, errors.New("cannot call this method on a symmetric key")
}
