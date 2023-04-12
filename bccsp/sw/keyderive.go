package sw

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"errors"
	"fmt"
	"math/big"

	"github.com/232425wxy/rocen/bccsp"
)

type ecdsaPublicKeyDeriver struct{}

// KeyDerive 根据给定的 ECDSA 公钥和 bccsp.KeyDeriveOpts 衍生出一个新的 ECDSA 公钥。
// 这里，bccsp.KeyDeriveOpts 非常重要，它必须能转化为 *bccsp.ECDSAReRandKeyOpts 实
// 例，然后依据其提供的 Expansion 值，计算 k，然后计算 k = k mod (n-1)，其中，n 是椭
// 圆曲线群的阶，然后计算 k = k + 1，计算 k = k * G，临时公钥 pub = (k.X + old.X, pub.Y + old.Y)。
func (kd *ecdsaPublicKeyDeriver) KeyDerive(key bccsp.Key, opts bccsp.KeyDeriveOpts) (bccsp.Key, error) {
	if opts == nil {
		return nil, errors.New("invalid opts parameter, it must not be nil")
	}

	ecdsaKey := key.(*ecdsaPublicKey)

	reRandOpts, ok := opts.(*bccsp.ECDSAReRandKeyOpts)
	if !ok {
		return nil, fmt.Errorf("unsupported 'KeyDeriveOpts' provided [%v]", opts)
	}

	// 重新实例化一个 ECDSA 公钥
	tempPK := &ecdsa.PublicKey{
		Curve: ecdsaKey.publicKey.Curve,
		X:     new(big.Int),
		Y:     new(big.Int),
	}

	var k = new(big.Int).SetBytes(reRandOpts.ExpansionValue())
	var one = new(big.Int).SetInt64(1)
	// 用之前群的阶减去 1 并赋值给 n。
	n := new(big.Int).Sub(ecdsaKey.publicKey.Params().N, one)
	// k = k mod n
	k.Mod(k, n)
	// k = k + 1
	k.Add(k, one)

	// pub.X, pub.Y = k*G
	tempX, tempY := ecdsaKey.publicKey.ScalarBaseMult(k.Bytes())
	tempPK.X, tempPK.Y = tempPK.Add(ecdsaKey.publicKey.X, ecdsaKey.publicKey.Y, tempX, tempY)

	// 验证临时公钥是否是椭圆曲线上的点。
	isOn := tempPK.Curve.IsOnCurve(tempPK.X, tempPK.Y)
	if !isOn {
		return nil, errors.New("temporary ECDSA public key is not on the curve")
	}
	return &ecdsaPublicKey{publicKey: tempPK}, nil
}

type ecdsaPrivateKeyDeriver struct{}

// KeyDerive 根据给定的 ECDSA 私钥和 bccsp.KeyDeriveOpts 衍生出一个新的 ECDSA 私钥。
func (kd *ecdsaPrivateKeyDeriver) KeyDerive(key bccsp.Key, opts bccsp.KeyDeriveOpts) (bccsp.Key, error) {
	if opts == nil {
		return nil, errors.New("invalid opts parameter, it must not be nil")
	}

	ecdsaKey := key.(*ecdsaPrivateKey)

	reRandOpts, ok := opts.(*bccsp.ECDSAReRandKeyOpts)
	if !ok {
		return nil, fmt.Errorf("unsupported 'KeyDeriveOpts' provided [%v]", opts)
	}

	tempSK := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: ecdsaKey.privateKey.Curve,
			X:     new(big.Int),
			Y:     new(big.Int),
		},
		D: new(big.Int),
	}

	var k = new(big.Int).SetBytes(reRandOpts.ExpansionValue())
	var one = new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(ecdsaKey.privateKey.Params().N, one)
	k.Mod(k, n)
	k.Add(k, one)

	tempSK.D.Add(ecdsaKey.privateKey.D, k)
	tempSK.D.Mod(tempSK.D, ecdsaKey.privateKey.Params().N)

	tempX, tempY := ecdsaKey.privateKey.ScalarBaseMult(k.Bytes())
	tempSK.PublicKey.X, tempSK.PublicKey.Y = ecdsaKey.privateKey.PublicKey.Add(ecdsaKey.privateKey.X, ecdsaKey.privateKey.Y, tempX, tempY)

	isOn := tempSK.Curve.IsOnCurve(tempSK.PublicKey.X, tempSK.PublicKey.Y)
	if !isOn {
		return nil, errors.New("temporary ECDSA public key is not on curve")
	}
	return &ecdsaPrivateKey{privateKey: tempSK}, nil
}

type aesPrivateKeyDeriver struct {
	conf *config
}

func (kd *aesPrivateKeyDeriver) KeyDerive(key bccsp.Key, opts bccsp.KeyDeriveOpts) (bccsp.Key, error) {
	if opts == nil {
		return nil, errors.New("invalid opts parameter, it must not be nil")
	}

	aesKey := key.(*aesPrivateKey)

	switch hmacOpts := opts.(type) {
	case *bccsp.HMACTruncated256AESDeriveKeyOpts:
		mac := hmac.New(kd.conf.hashFunction, aesKey.privKey)
		mac.Write(hmacOpts.Argument())
		return &aesPrivateKey{privKey: mac.Sum(nil)[:kd.conf.aesBitLength], exportable: false}, nil
	case *bccsp.HMACDeriveKeyOpts:
		mac := hmac.New(kd.conf.hashFunction, aesKey.privKey)
		mac.Write(hmacOpts.Argument())
		return &aesPrivateKey{privKey: mac.Sum(nil), exportable: true}, nil
	default:
		return nil, fmt.Errorf("unsupported 'KeyDeriveOpts' provided [%v]", opts)
	}
}
