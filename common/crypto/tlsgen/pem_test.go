package tlsgen

import (
	"bytes"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPEMEncoding(t *testing.T) {
	block := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: map[string]string{
			"name": "Xiangyu Wu",
			"School": "Northwestern Polytechnical University",
		},
		Bytes:   []byte("My rsa private key."),
	}

	buf := &bytes.Buffer{}

	err := pem.Encode(buf, &block)

	assert.NoError(t, err)

	t.Log(buf.String())
}
