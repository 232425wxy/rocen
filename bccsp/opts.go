package bccsp

import (
	"crypto"
	"fmt"
	"io"
)

const (
	// ECDSA 代表默认安全级别的椭圆曲线数字签名算法族，包括密钥生成、密钥导入、签名和验签算法。
	ECDSA = "ECDSA"

	// ECDSAP256 代表 P-256 曲线上的椭圆曲线签名算法。
	ECDSAP256 = "ECDSAP256"

	// ECDSAP384 代表 P-384 曲线上的椭圆曲线签名算法。
	ECDSAP384 = "ECDSAP384"

	// ECDSAReRand ECDSA 密钥重新随机化。
	ECDSAReRand = "ECDSA_RERAND"

	// AES 代表默认安全级别的加密标准。
	AES = "AES"

	// AES128 表示 128 比特安全级别的 AES 加密标准。
	AES128 = "AES128"

	// AES192 表示 192 比特安全级别的 AES 加密标准。
	AES192 = "AES192"

	// AES256 表示 256 比特安全级别的 AES 加密标准。
	AES256 = "AES256"

	// HMAC 表示基于 Hash 算法的消息验证码。
	HMAC = "HMAC"

	// HMACTruncated256 表示前 256 比特的消息验证码。
	HMACTruncated256 = "HMAC_TRUNCATED_256"

	// SHA 表示默认哈希算法族的安全哈希算法。
	SHA = "SHA"

	// SHA2 表示 SHA2 哈希族。
	SHA2 = "SHA2"

	// SHA3 表示 SHA3 哈希族。
	SHA3 = "SHA3"

	SHA256 = "SHA256"

	SHA384 = "SHA384"

	SHA3_256 = "SHA3_256"

	SHA3_384 = "SHA3_384"

	X509Certificate = "X509Certificate"

	IDEMIX = "IDEMIX"
)

type RevocationAlgorithm int32

const (
	// AlgNoRevocation 意味着不支持撤销。
	AlgNoRevocation RevocationAlgorithm = iota
)

///////////////////////////////////////////////////////////////////
// ECDSA

type ECDSAKeyGenOpts struct {
	Temporary bool
}

// Algorithm 返回 "ECDSA"。
func (opts *ECDSAKeyGenOpts) Algorithm() string {
	return ECDSA
}

func (opts *ECDSAKeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type ECDSAPKIXPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm 返回 "ECDSA"。
func (opts *ECDSAPKIXPublicKeyImportOpts) Algorithm() string {
	return ECDSA
}

func (opts *ECDSAPKIXPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type ECDSAPrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm 返回 "ECDSA"。
func (opts *ECDSAPrivateKeyImportOpts) Algorithm() string {
	return ECDSA
}

func (opts *ECDSAPrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type ECDSAGoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm 返回 "ECDSA"。
func (opts *ECDSAGoPublicKeyImportOpts) Algorithm() string {
	return ECDSA
}

func (opts *ECDSAGoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

///////////////////////////////////////////////////////////////////
// ECDSAP256

type ECDSAP256KeyGenOpts struct {
	Temporary bool
}

// Algorithm 返回 "ECDSAP256"。
func (opts *ECDSAP256KeyGenOpts) Algorithm() string {
	return ECDSAP256
}

func (opts *ECDSAP256KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

///////////////////////////////////////////////////////////////////
// ECDSAP384

type ECDSAP384KeyGenOpts struct {
	Temporary bool
}

// Algorithm 返回 "ECDSAP384"。
func (opts *ECDSAP384KeyGenOpts) Algorithm() string {
	return ECDSAP384
}

func (opts *ECDSAP384KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

///////////////////////////////////////////////////////////////////
// ECDSAReRand

type ECDSAReRandKeyOpts struct {
	Temporary bool
	Expansion []byte // 随机因子。
}

func (opts *ECDSAReRandKeyOpts) Algorithm() string {
	return ECDSAReRand
}

func (opts *ECDSAReRandKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

func (opts *ECDSAReRandKeyOpts) ExpansionValue() []byte {
	return opts.Expansion
}

///////////////////////////////////////////////////////////////////
// AES

type AESKeyGenOpts struct {
	Temporary bool
}

// Algorithm 返回 "AES"。
func (opts *AESKeyGenOpts) Algorithm() string {
	return AES
}

func (opts *AESKeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type AES256ImportKeyOpts struct {
	Temporary bool
}

// Algorithm 返回 "AES"。
func (opts *AES256ImportKeyOpts) Algorithm() string {
	return AES
}

func (opts *AES256ImportKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

///////////////////////////////////////////////////////////////////
// AES128

type AES128KeyGenOpts struct {
	Temporary bool
}

func (opts *AES128KeyGenOpts) Algorithm() string {
	return AES128
}

func (opts *AES128KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

///////////////////////////////////////////////////////////////////
// AES192

type AES192KeyGenOpts struct {
	Temporary bool
}

func (opts *AES192KeyGenOpts) Algorithm() string {
	return AES192
}

func (opts *AES192KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

///////////////////////////////////////////////////////////////////
// AES256

type AES256KeyGenOpts struct {
	Temporary bool
}

func (opts *AES256KeyGenOpts) Algorithm() string {
	return AES256
}

func (opts *AES256KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

///////////////////////////////////////////////////////////////////
// AESCBCPKCS7

type AESCBCPKCS7ModeOpts struct {
	// IV (initialization vector) 初始化向量，被用于底层密码。只有当 IV 不等于 nil 时，IV 才会被使用。
	IV []byte
	// PRNG 被用于底层加密，只有当 PRNG 不等于 nil 时，PRNG 才会被使用。
	PRNG io.Reader
}

///////////////////////////////////////////////////////////////////
// HMAC

type HMACDerivKeyOpts struct {
	Temporary bool
	Arg       []byte
}

// Algorithm 返回 "HMAC"。
func (opts *HMACDerivKeyOpts) Algorithm() string {
	return HMAC
}

func (opts *HMACDerivKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

func (opts *HMACDerivKeyOpts) Argument() []byte {
	return opts.Arg
}

type HMACImportKeyOpts struct {
	Temporary bool
}

// Algorithm 返回 "HMAC"。
func (opts *HMACImportKeyOpts) Algorithm() string {
	return HMAC
}

func (opts *HMACImportKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

///////////////////////////////////////////////////////////////////
// HMACTruncated256

type HMACTruncated256AESDerivKeyOpts struct {
	Temporary bool
	Arg       []byte
}

// Algorithm 返回 "HMACTruncated256"。
func (opts *HMACTruncated256AESDerivKeyOpts) Algorithm() string {
	return HMACTruncated256
}

func (opts *HMACTruncated256AESDerivKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

func (opts *HMACTruncated256AESDerivKeyOpts) Argument() []byte {
	return opts.Arg
}

///////////////////////////////////////////////////////////////////
// SHA

type SHAOpts struct{}

// Algorithm 返回 "SHA"。
func (opts *SHAOpts) Algorithm() string {
	return SHA
}

type X509PublicKeyImportOpts struct {
	Temporary bool
}

///////////////////////////////////////////////////////////////////
// SHA256

type SHA256Opts struct{}

func (opts *SHA256Opts) Algorithm() string {
	return SHA256
}

///////////////////////////////////////////////////////////////////
// SHA384

type SHA384Opts struct{}

func (opts *SHA384Opts) Algorithm() string {
	return SHA384
}

///////////////////////////////////////////////////////////////////
// SHA3_256

type SHA3_256Opts struct{}

func (opts *SHA3_256Opts) Algorithm() string {
	return SHA3_256
}

///////////////////////////////////////////////////////////////////
// SHA3_384

type SHA3_384Opts struct{}

func (opts *SHA3_384Opts) Algorithm() string {
	return SHA3_384
}

///////////////////////////////////////////////////////////////////
// X509Certificate

// Algorithm 返回 "X509Certificate"。
func (opts *X509PublicKeyImportOpts) Algorithm() string {
	return X509Certificate
}

func (opts *X509PublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

///////////////////////////////////////////////////////////////////
// IDEMIX

type IdemixIssuerKeyGenOpts struct {
	Temporary      bool
	AttributeNames []string
}

func (opts *IdemixIssuerKeyGenOpts) Algorithm() string {
	return IDEMIX
}

func (opts *IdemixIssuerKeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type IdemixIssuerPublicKeyImportOpts struct {
	Temporary      bool
	AttributeNames []string
}

func (opts *IdemixIssuerPublicKeyImportOpts) Algorithm() string {
	return IDEMIX
}

func (opts *IdemixIssuerPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type IdemixUserSecretKeyGenOpts struct {
	Temporary bool
}

func (opts *IdemixUserSecretKeyGenOpts) Algorithm() string {
	return IDEMIX
}

func (opts *IdemixUserSecretKeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type IdemixUserSecretKeyImportOpts struct {
	Temporary bool
}

func (opts *IdemixUserSecretKeyImportOpts) Algorithm() string {
	return IDEMIX
}

func (opts *IdemixUserSecretKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type IdemixNymKeyDerivationOpts struct {
	Temporary bool
	IssuerPK  Key
}

func (IdemixNymKeyDerivationOpts) Algorithm() string {
	return IDEMIX
}

func (opts *IdemixNymKeyDerivationOpts) Ephemeral() bool {
	return opts.Temporary
}

func (opts *IdemixNymKeyDerivationOpts) IssuerPublicKey() Key {
	return opts.IssuerPK
}

type IdemixNymPublicKeyImportOpts struct {
	Temporary bool
}

func (opts *IdemixNymPublicKeyImportOpts) Algorithm() string {
	return IDEMIX
}

func (opts *IdemixNymPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type IdemixRevocationKeyGenOpts struct {
	Temporary bool
}

func (opts *IdemixRevocationKeyGenOpts) Algorithm() string {
	return IDEMIX
}

func (opts *IdemixRevocationKeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type IdemixRevocationPublicKeyImportOpts struct {
	Temporary bool
}

func (opts *IdemixRevocationPublicKeyImportOpts) Algorithm() string {
	return IDEMIX
}

func (opts *IdemixRevocationPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type IdemixCredentialRequestSignerOpts struct {
	Attributes  []int
	IssuerPK    Key
	IssuerNonce []byte
	Hash        crypto.Hash
}

func (opts *IdemixCredentialRequestSignerOpts) HashFunc() crypto.Hash {
	return opts.Hash
}

func (opts *IdemixCredentialRequestSignerOpts) IssuerPublicKey() Key {
	return opts.IssuerPK
}

type IdemixAttributeType int

const (
	IdemixHiddenAttribute IdemixAttributeType = iota
	IdemixBytesAttribute
	IdemixIntAttribute
)

type IdemixAttribute struct {
	Type  IdemixAttributeType
	Value interface{}
}

type IdemixCredentialSignerOpts struct {
	Attributes []IdemixAttribute
	IssuerPK   Key
	Hash       crypto.Hash
}

func (opts *IdemixCredentialSignerOpts) HashFunc() crypto.Hash {
	return opts.Hash
}

func (opts *IdemixCredentialSignerOpts) IssuerPublicKey() Key {
	return opts.IssuerPK
}

type IdemixSignerOpts struct {
	Nym Key
	// IssuerPK 是发行者的公钥。
	IssuerPK Key
	// Credential 是由发行人签名的凭证的字节表示。
	Credential []byte
	// Attributes 指定哪些属性应该被披露，哪些不应该。如果
	// Attributes[i].Type = IdemixHiddenAttribute，那么
	// 第 i 个凭证属性不应该被披露，否则第 i 个凭证属性将被披露。
	// 在验证时，如果第 i 个属性被披露（Attributes[i].Type != IdemixHiddenAttribute），
	// 那么 Attributes[i].Value 必须被相应设置。
	Attributes []IdemixAttribute
	// RhIndex 是包含撤销处理程序的属性的索引。
	RhIndex int
	// CRI 包含凭证撤销信息。
	CRI []byte
	// Epoch 是指该签名应针对的撤销时间。
	Epoch int
	// RevocationPublicKey 是撤销的公钥。
	RevocationPublicKey Key
	Hash                crypto.Hash
}

func (opts *IdemixSignerOpts) HashFunc() crypto.Hash {
	return opts.Hash
}

type IdemixNymSignerOpts struct {
	Nym      Key
	IssuerPK Key
	Hash     crypto.Hash
}

func (opts *IdemixNymSignerOpts) HashFunc() crypto.Hash {
	return opts.Hash
}

type IdemixCRISignerOpts struct {
	Epoch               int
	RevocationAlgorithm RevocationAlgorithm
	UnrevokedHandles    [][]byte
	Hash                crypto.Hash
}

func (opts *IdemixCRISignerOpts) HashFunc() crypto.Hash {
	return opts.Hash
}

///////////////////////////////////////////////////////////////////
// GetHashOpt

func GetHashOpt(hashFunction string) (HashOpts, error) {
	switch hashFunction {
	case SHA256:
		return &SHA256Opts{}, nil
	case SHA384:
		return &SHA384Opts{}, nil
	case SHA3_256:
		return &SHA3_256Opts{}, nil
	case SHA3_384:
		return &SHA3_384Opts{}, nil
	default:
		return nil, fmt.Errorf("hash function not recognized [%s]", hashFunction)
	}
}
