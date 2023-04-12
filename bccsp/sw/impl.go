package sw

import (
	"reflect"

	"github.com/232425wxy/rocen/bccsp"
	"github.com/232425wxy/rocen/common/logging"
)

var logger logging.Logger

func init() {
	var err error
	logger, err = logging.NewLogger()
	if err != nil {
		panic(err)
	}
	logger.Update(logging.Option{Module: "bccsp_sw"})
}

// CSP Cryptography Service Provider.
type CSP struct {
	keyStore bccsp.KeyStore

	KeyGenerators map[reflect.Type]KeyGenerator
	KeyDerivers   map[reflect.Type]KeyDeriver
	KeyImporters  map[reflect.Type]KeyImporter
	Encryptors    map[reflect.Type]Encryptor
	Decryptors    map[reflect.Type]Decryptor
	Signers       map[reflect.Type]Signer
	Verifiers     map[reflect.Type]Verifier
	Hashers       map[reflect.Type]Hasher
}
