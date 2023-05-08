package tlsgen

import "sync/atomic"

// TLSCertificates 聚合了服务端和客户端的证书。
type TLSCertificates struct {
	TLSServerCert atomic.Value
	TLSClientCert atomic.Value
}
