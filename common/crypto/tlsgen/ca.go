package tlsgen

import (
	"crypto"
	"crypto/x509"
)

type CA interface {
	NewIntermediateCA() (CA, error)

	CertBytes() []byte

	NewClientCertKeyPair() (*CertKeyPair, error)

	NewServerCertKeyPair(host string) (*CertKeyPair, error)
}

type CertKeyPair struct {
	Cert          []byte            // 与签名私钥对应的公钥的证书
	Key           []byte            // 签名私钥的原始字节被编码成 PEM 格式的字节切片。
	crypto.Signer                   // 签名私钥
	TLSCert       *x509.Certificate // 对 Cert 进行 pem 解码，然后进行 x509 证书解析得到的证书
}

type ca struct {
	caCert *CertKeyPair
}

func NewCA() (CA, error) {
	var c = new(ca)
	var err error
	c.caCert, err = newCertKeyPair(true, false, "", nil, nil)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// NewIntermediateCA 
func (c *ca) NewIntermediateCA() (CA, error) {
	var intermediateCA = new(ca)
	var err error
	intermediateCA.caCert, err = newCertKeyPair(true, false, "", c.caCert.Signer, c.caCert.TLSCert)
	if err != nil {
		return nil, err
	}
	return intermediateCA, nil
}

// CertBytes 返回证书的 PEM 编码内容。
func (c *ca) CertBytes() []byte {
	return c.caCert.Cert
}

// NewClientCertKeyPair 生成由 CA 签署的客户端 TLS 证书。
func (c *ca) NewClientCertKeyPair() (*CertKeyPair, error) {
	return newCertKeyPair(false, false, "", c.caCert.Signer, c.caCert.TLSCert)
}

// NewServerCertKeyPair 生成由 CA 签署的服务端 TLS 证书。
func (c *ca) NewServerCertKeyPair(host string) (*CertKeyPair, error) {
	return newCertKeyPair(false, true, host, c.caCert.Signer, c.caCert.TLSCert)
}