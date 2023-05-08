package tlsgen

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPrivateKey(t *testing.T) {
	_, bz, err := newPrivateKey()
	assert.NoError(t, err)

	t.Log(bz)
}

func TestLoadCert(t *testing.T) {
	pair, err := newCertKeyPair(false, false, "", nil, nil)
	require.NoError(t, err)
	require.NotNil(t, pair)
	tlsCertPair, err := tls.X509KeyPair(pair.Cert, pair.Key)
	require.NoError(t, err)
	require.NotNil(t, tlsCertPair)

	block, _ := pem.Decode(pair.Cert)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.NotNil(t, cert)
}
