package tlsgen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// newPrivateKey 方法返回一个椭圆曲线签名私钥及私钥的 asn.1 编码，基于椭圆曲线的安全级别是 256。
func newPrivateKey() (*ecdsa.PrivateKey, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, privateKeyBytes, nil
}

func newCertTemplate() (x509.Certificate, error) {
	// 随机产生一个 [0,2^128] 范围内的整数
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return x509.Certificate{}, err
	}

	return x509.Certificate{
		Subject:      pkix.Name{SerialNumber: sn.String()},
		NotBefore:    time.Now().Add(time.Hour * (-24)),
		NotAfter:     time.Now().Add(time.Hour * 24),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature, // KeyUsage 表示这个密钥能干什么。
		SerialNumber: sn,
	}, nil
}

func newCertKeyPair(isCA bool, isServer bool, host string, certSigner crypto.Signer, parent *x509.Certificate) (*CertKeyPair, error) {
	// 生成一个椭圆曲线签名私钥，基于的椭圆曲线的安全级别为 256。
	privateKey, privateKeyBytes, err := newPrivateKey()
	if err != nil {
		return nil, err
	}

	template, err := newCertTemplate()
	if err != nil {
		return nil, err
	}

	// 10年以后的时间。
	tenYearsFromNow := time.Now().Add(time.Hour * 24 * 365 * 10)

	if isCA {
		template.NotAfter = tenYearsFromNow
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.ExtKeyUsage = []x509.ExtKeyUsage{ // ExtKeyUsage 表示扩展密钥的使用顺序。
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		}
		template.BasicConstraintsValid = true
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	if isServer {
		template.NotAfter = tenYearsFromNow
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}

	if parent == nil || certSigner == nil {
		parent = &template
		certSigner = privateKey
	}
	// 该证书由 parent 证书签署。如果 parent 等于 template，那么该证书是自己给自己签的。参数 pub 是要生成的证书的公钥，priv 是签名者的私钥。
	rawBytes, err := x509.CreateCertificate(rand.Reader, &template, parent, &privateKey.PublicKey, certSigner)
	if err != nil {
		return nil, err
	}
	publicKey := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rawBytes})

	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, fmt.Errorf("%s: wrong PEM encoding", publicKey)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &CertKeyPair{
		Key: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBytes}),
		Cert: publicKey,
		Signer: privateKey,
		TLSCert: cert,
	}, nil
}
