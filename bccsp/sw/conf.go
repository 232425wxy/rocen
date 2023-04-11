package sw

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"golang.org/x/crypto/sha3"
)

type config struct {
	ellipticCurve elliptic.Curve
	hashFunction  func() hash.Hash
	aesBitLength  int
}

func (conf *config) setSecurityLevel(securityLevel int, hashFamily string) (err error) {
	switch hashFamily {
	case "SHA2":
		err = conf.setSecurityLevelSHA2(securityLevel)
	case "SHA3":
		err = conf.setSecurityLevelSHA3(securityLevel)
	default:
		err = fmt.Errorf("hash family not supported [%s]", hashFamily)
	}
	return err
}

// setSecurityLevelSHA2 方法接受的参数 level 的取值只能是 256 或者 384。
// 如果取值是 256，则 config 的椭圆曲线是 P-256 的曲线，哈希函数是一个计
// 算 SHA-256 校验和的哈希函数，AES 加密方案的密钥长度被设为 32。
// 如果取值是 384，则 config 的椭圆曲线是 P-384 的曲线，哈希函数是一个计
// 算 SHA-384 校验和的哈希函数，AES 加密方案的密钥长度被设为 32。
func (conf *config) setSecurityLevelSHA2(level int) (err error) {
	switch level {
	case 256:
		conf.ellipticCurve = elliptic.P256()
		conf.hashFunction = sha256.New
		conf.aesBitLength = 32
	case 384:
		conf.ellipticCurve = elliptic.P384()
		conf.hashFunction = sha512.New384
		conf.aesBitLength = 32
	default:
		err = fmt.Errorf("security level not supported [%d]", level)
	}
	return err
}

// setSecurityLevelSHA2 方法接受的参数 level 的取值只能是 256 或者 384。
// 如果取值是 256，则 config 的椭圆曲线是 P-256 的曲线，哈希函数是一个计
// 算 SHA-256 校验和的哈希函数，AES 加密方案的密钥长度被设为 32。
// 如果取值是 384，则 config 的椭圆曲线是 P-384 的曲线，哈希函数是一个计
// 算 SHA-384 校验和的哈希函数，AES 加密方案的密钥长度被设为 32。
func (conf *config) setSecurityLevelSHA3(level int) (err error) {
	switch level {
	case 256:
		conf.ellipticCurve = elliptic.P256()
		conf.hashFunction = sha3.New256
		conf.aesBitLength = 32
	case 384:
		conf.ellipticCurve = elliptic.P384()
		conf.hashFunction = sha3.New384
		conf.aesBitLength = 32
	default:
		err = fmt.Errorf("security level not supported [%d]", level)
	}
	return err
}