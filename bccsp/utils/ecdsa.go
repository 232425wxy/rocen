package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// ECDSASignature 表示椭圆曲线签名，假设签名私钥是 x，待签名的消息是 m，签名的生成过程如下：
//  1. 随机选择一个整数 r，计算 r·G=(X_R,X_Y)，让 R=X_R；
//  2. 计算 e=H(m)；
//  3. 计算 s=r^(-1)·(e+x·R)，让 S=s；
//  4. 得到签名 (R,S)
type ECDSASignature struct {
	R, S *big.Int
}

var (
	// curveHalfOrders 包含了预先计算好的椭圆曲线群阶的一半。
	// 它是用来确保签名 S 值低于或等于相应椭圆曲线群阶的一半，这样的签名被称为 low-S 签名。
	curveHalfOrders = map[elliptic.Curve]*big.Int{
		elliptic.P224(): new(big.Int).Rsh(elliptic.P224().Params().N, 1),
		elliptic.P256(): new(big.Int).Rsh(elliptic.P256().Params().N, 1),
		elliptic.P384(): new(big.Int).Rsh(elliptic.P384().Params().N, 1),
		elliptic.P521(): new(big.Int).Rsh(elliptic.P521().Params().N, 1),
	}
)

// GetCurveHalfOrderAt 根据给定的椭圆曲线，获取该椭圆曲线群阶 N 的一半值。
func GetCurveHalfOrderAt(c elliptic.Curve) *big.Int {
	return new(big.Int).Set(curveHalfOrders[c])
}

// MarshalECDSASignature
func MarshalECDSASignature(sig ECDSASignature) ([]byte, error) {

	return asn1.Marshal(sig)
}

func UnmarshalECDSASignature(raw []byte) (ECDSASignature, error) {
	sig := new(ECDSASignature)
	_, err := asn1.Unmarshal(raw, sig)

	if err != nil {
		return ECDSASignature{}, fmt.Errorf("failed unmarshalling signature [%s]", err)
	}

	if sig.R == nil {
		return ECDSASignature{}, fmt.Errorf("invalid signature, R must be different from nil")
	}

	if sig.S == nil {
		return ECDSASignature{}, fmt.Errorf("invalid signature, S must be different from nil")
	}

	if sig.R.Sign() != 1 {
		return ECDSASignature{}, fmt.Errorf("invalid signature, R must be larger than zero")
	}

	if sig.S.Sign() != 1 {
		return ECDSASignature{}, fmt.Errorf("invalid signature, S must be larger than zero")
	}

	return *sig, nil
}

// SignatureToLowS 确保 ECDSA 签名 (r,s) 里的 s 小于对应群阶的一半，然后用 asn1 将签名编码并返回。
func SignatureToLowS(k *ecdsa.PublicKey, signatureRaw []byte) ([]byte, error) {
	sig, err := UnmarshalECDSASignature(signatureRaw)
	if err != nil {
		return nil, err
	}
	s, err := ToLowS(k, sig.S)
	if err != nil {
		return nil, err
	}
	sig.S = s
	return MarshalECDSASignature(sig)
}

// IsLowS 判断 ECDSA 签名 (r,s) 里的 s 是否小于对应椭圆曲线群阶的一半。
func IsLowS(k *ecdsa.PublicKey, s *big.Int) (bool, error) {
	halfOrder, ok := curveHalfOrders[k.Curve]
	if !ok {
		return false, fmt.Errorf("curve not recognized [%s]", k.Curve)
	}
	return s.Cmp(halfOrder) != 1, nil
}

// ToLowS 如果 ECDSA 签名 (r,s) 里的 s 大于 对应椭圆曲线群阶的一半，则用椭圆曲线群
// 的阶减去 s，得到的差值重新赋值给 s。
func ToLowS(k *ecdsa.PublicKey, s *big.Int) (*big.Int, error) {
	lowS, err := IsLowS(k, s)
	if err != nil {
		return nil, err
	}

	if !lowS {
		s.Sub(k.Params().N, s)
		return s, nil
	}
	return s, nil
}
