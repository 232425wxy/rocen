package sw

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/232425wxy/rocen/bccsp"
)

///////////////////////////////////////////////////////////////////
// AES-KEY

type aesPrivateKey struct {
	privKey    []byte
	exportable bool
}

// Bytes 如果这个私钥是可导出的，则返回该私钥的具体内容。
func (k *aesPrivateKey) Bytes() (raw []byte, err error) {
	if k.exportable {
		return k.privKey, nil
	}

	return nil, errors.New("not supported")
}

// SKI 返回 0x01|PrivateKey 的哈希值。
func (k *aesPrivateKey) SKI() (ski []byte) {
	hash := sha256.New()
	hash.Write([]byte{0x01})
	hash.Write(k.privKey)
	return hash.Sum(nil)
}

// Symmetric 返回 true，表示 AES 的密钥是对称密钥。
func (k *aesPrivateKey) Symmetric() bool {
	return true
}

// Private 返回 true，表示 AES 的密钥是秘密非公开的。
func (k *aesPrivateKey) Private() bool {
	return true
}

// PublicKey 直接返回错误，因为对称密钥没有公钥。
func (k *aesPrivateKey) PublicKey() (bccsp.Key, error) {
	return nil, errors.New("cannot call this method on a symmetric key")
}

// AESCBCPKCS7Encrypt combines CBC encryption and PKCS7 padding
func AESCBCPKCS7Encrypt(key, src []byte) ([]byte, error) {
	// 1. 填充。
	tmp := pkcs7Padding(src)

	// 2. 加密。
	return aesCBCEncrypt(key, tmp)
}

// AESCBCPKCS7Encrypt combines CBC encryption and PKCS7 padding using as prng the passed to the function
func AESCBCPKCS7EncryptWithRand(prng io.Reader, key, src []byte) ([]byte, error) {
	// 1. 填充。
	tmp := pkcs7Padding(src)

	// 2. 加密。
	return aesCBCEncryptWithRand(prng, key, tmp)
}

// AESCBCPKCS7Encrypt combines CBC encryption and PKCS7 padding, the IV used is the one passed to the function
func AESCBCPKCS7EncryptWithIV(IV []byte, key, src []byte) ([]byte, error) {
	// 1. 填充。
	tmp := pkcs7Padding(src)

	// 2. 加密。
	return aesCBCEncryptWithIV(IV, key, tmp)
}

// AESCBCPKCS7Decrypt combines CBC decryption and PKCS7 unpadding
func AESCBCPKCS7Decrypt(key, src []byte) ([]byte, error) {
	// 1. 解密。
	pt, err := aesCBCDecrypt(key, src)
	if err == nil {
		// 2. 取消填充
		return pkcs7UnPadding(pt)
	}
	return nil, err
}

// GetRandomBytes 返回指定个数个随机字节。
func GetRandomBytes(len int) ([]byte, error) {
	if len < 0 {
		return nil, errors.New("len must be larger than 0")
	}
	buffer := make([]byte, len)
	n, err := rand.Read(buffer)
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, fmt.Errorf("buffer not filled, requested [%d], got [%d]", len, n)
	}

	return buffer, nil
}

// pkcs7Padding 方法会对字节切片进行填充，要求填充后的字节切片长度等于 16 的倍数，填充内容等于 16-16%(字节切片的原长度)。
func pkcs7Padding(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// pkcs7UnPadding 将被填充的字节切片里的填充物去除掉。
func pkcs7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	// unpadding 是 src 中最后一个字节的值。
	unpadding := int(src[length-1])
	if unpadding > aes.BlockSize || unpadding == 0 {
		return nil, errors.New("invalid pkcs7 padding (unpadding > aes.BlockSize || unpadding == 0)")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}

func aesCBCEncrypt(key, s []byte) ([]byte, error) {
	return aesCBCEncryptWithRand(rand.Reader, key, s)
}

// aesCBCEncryptWithRand 方法通过给定的伪随机因子 prng 生成初始向量。
func aesCBCEncryptWithRand(prng io.Reader, key, s []byte) ([]byte, error) {
	if len(s)%aes.BlockSize != 0 {
		return nil, errors.New("invalid plaintext, it must be a multiple of the block size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(s))
	// iv (initialization vector) 初始向量，全零。
	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(prng, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], s)
	return ciphertext, nil
}

func aesCBCEncryptWithIV(iv []byte, key, s []byte) ([]byte, error) {
	if len(s)%aes.BlockSize != 0 {
		return nil, errors.New("invalid plaintext, it must be a multiple of the block size")
	}
	if len(iv) != aes.BlockSize {
		return nil, errors.New("invalid iv, it must have length the block size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(s))
	copy(ciphertext[:aes.BlockSize], iv)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], s)
	return ciphertext, nil
}

func aesCBCDecrypt(key, src []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(src) < aes.BlockSize {
		return nil, errors.New("invalid ciphertext, it must be a multiple of the block size")
	}
	iv := src[:aes.BlockSize]
	src = src[aes.BlockSize:]
	if len(src)%aes.BlockSize != 0 {
		return nil, errors.New("invalid ciphertext, it must be a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(src, src)

	return src, nil
}

type aescbcpkcs7Encryptor struct{}

func (e *aescbcpkcs7Encryptor) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
	switch o := opts.(type) {
	case *bccsp.AESCBCPKCS7ModeOpts:
		// AES in CBC mode with PKCS7 padding

		if len(o.IV) != 0 && o.PRNG != nil {
			return nil, errors.New("invalid options, either iv or prng should be different from nil, or both nil")
		}

		if len(o.IV) != 0 {
			// Encrypt with the passed IV
			return AESCBCPKCS7EncryptWithIV(o.IV, k.(*aesPrivateKey).privKey, plaintext)
		} else if o.PRNG != nil {
			// Encrypt with PRNG
			return AESCBCPKCS7EncryptWithRand(o.PRNG, k.(*aesPrivateKey).privKey, plaintext)
		}
		// AES in CBC mode with PKCS7 padding
		return AESCBCPKCS7Encrypt(k.(*aesPrivateKey).privKey, plaintext)
	case bccsp.AESCBCPKCS7ModeOpts:
		return e.Encrypt(k, plaintext, &o)
	default:
		return nil, fmt.Errorf("mode not recognized [%s]", opts)
	}
}

type aescbcpkcs7Decryptor struct{}

func (*aescbcpkcs7Decryptor) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) ([]byte, error) {
	// check for mode
	switch opts.(type) {
	case *bccsp.AESCBCPKCS7ModeOpts, bccsp.AESCBCPKCS7ModeOpts:
		// AES in CBC mode with PKCS7 padding
		return AESCBCPKCS7Decrypt(k.(*aesPrivateKey).privKey, ciphertext)
	default:
		return nil, fmt.Errorf("mode not recognized [%s]", opts)
	}
}
