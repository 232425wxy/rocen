package sw

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/232425wxy/rocen/bccsp"
)

// /////////////////////////////////////////////////////////////////
// fileBasedKeyStore 是一个基于文件夹的 KeyStore。每个密钥都存储在一个
// 单独的文件中，文件名包含密钥的 SKI 和标识密钥类型的标志。所有的密钥都
// 存储在一个文件夹中，其路径是在初始化时提供的。KeyStore 可以用一个密码
// 来初始化，这个密码用来加密和解密存储钥匙的文件。一个 KeyStore 可以是
// 只读的，以避密钥匙被篡改。
type fileBasedKeyStore struct {
	path     string
	readOnly bool
	isOpen   bool
	pwd      []byte // 加解密密钥的密码
	mu       sync.Mutex
}

///////////////////////////////////////////////////////////////////
// NewFileBasedKeyStore 新建一个存储密钥的 KeyStore。
func NewFileBasedKeyStore(pwd []byte, path string, readOnly bool) (bccsp.KeyStore, error) {
	ks := new(fileBasedKeyStore)
	return ks, ks.Init(pwd, path, readOnly)
}

///////////////////////////////////////////////////////////////////
// Init
func (ks *fileBasedKeyStore) Init(pwd []byte, path string, readOnly bool) error {
	if len(path) == 0 {
		return errors.New("invalid KeyStore path, it must be different from \"\"")
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.isOpen {
		return errors.New("KeyStore is already initialized")
	}

	ks.path = path

	clone := make([]byte, len(pwd))
	copy(clone, pwd)
	ks.pwd = clone
	ks.readOnly = readOnly

	exists, err := dirExists(path)
	if err != nil {
		return err
	}
	if !exists {
		err = ks.createKeyStore()
		if err != nil {
			return err
		}
		return ks.openKeyStore()
	}

	empty, err := dirEmpty(path)
	if err != nil {
		return err
	}
	if empty {
		err = ks.createKeyStore()
		if err != nil {
			return err
		}
	}

	return ks.openKeyStore()
}

///////////////////////////////////////////////////////////////////
// ReadOnly 返回一个布尔值，判断 KeyStore 是否是只读的。
func (ks *fileBasedKeyStore) ReadOnly() bool {
	return ks.readOnly
}

///////////////////////////////////////////////////////////////////
// LoadKey 从 KeyStore 中加载与 SKI 对应的密钥。
func (ks *fileBasedKeyStore) LoadKey(ski []byte) (bccsp.Key, error) {
	if len(ski) == 0 {
		return nil, errors.New("invalid SKI, it must be different from nil")
	}

	alias := hex.EncodeToString(ski)
	suffix := ks.getSuffix(alias)

	switch suffix {
	case "key":
		// AES 密钥
		key, err := ks.loadAESKey(alias)
		if err != nil {
			return nil, fmt.Errorf("failed loading key [%s]: [%s]", alias, err)
		}
		return &aesKey{key: key, exportable: false}, nil
	case "sk":
		// ECDSA 私钥
		key, err := ks.loadPrivateKey(alias)
		if err != nil {
			return nil, fmt.Errorf("failed loading private key [%s]: [%s]", alias, err)
		}

		switch k := key.(type) {
		case *ecdsa.PrivateKey:
			return &ecdsaPrivateKey{privateKey: k}, nil
		default:
			return nil, errors.New("private key type not recognised")
		}
	case "pk":
		// ECDSA 公钥
		key, err := ks.loadPublicKey(alias)
		if err != nil {
			return nil, fmt.Errorf("failed loading public key [%s]: [%s]", alias, err)
		}

		switch k := key.(type) {
		case *ecdsa.PublicKey:
			return &ecdsaPublicKey{publicKey: k}, nil
		default:
			return nil, errors.New("public key type not recognised")
		}
	default:
		return ks.searchKeystoreForSKI(ski)
	}
}

///////////////////////////////////////////////////////////////////
// StoreKey 存储密钥，支持存储 ECDSA 的公钥、私钥和 AES 的密钥，其他的
// 不支持。
func (ks *fileBasedKeyStore) StoreKey(key bccsp.Key) (err error) {
	if ks.readOnly {
		return errors.New("KeyStore is read only")
	}

	if key == nil {
		return errors.New("invalid key, it must be different from nil")
	}

	switch k := key.(type) {
	case *ecdsaPrivateKey:
		if err = ks.storeECDSAPrivateKey(hex.EncodeToString(key.SKI()), k.privateKey); err != nil {
			return fmt.Errorf("failed storing ECDSA private key [%s]", err)
		}
	case *ecdsaPublicKey:
		if err = ks.storeECDSAPublicKey(hex.EncodeToString(key.SKI()), k.publicKey); err != nil {
			return fmt.Errorf("failed storing ECDSA public key [%s]", err)
		}
	case *aesKey:
		if err = ks.storeAESKey(hex.EncodeToString(key.SKI()), k.key); err != nil {
			return fmt.Errorf("failed storing AES key [%s]", err)
		}
	default:
		return fmt.Errorf("key type not recognised [%s]", key)
	}
	return nil
}

// /////////////////////////////////////////////////////////////////
// searchKeystoreForSKI 从存储密钥的文件夹里寻找 SKI 对的上的密钥。
func (ks fileBasedKeyStore) searchKeystoreForSKI(ski []byte) (key bccsp.Key, err error) {
	files, _ := os.ReadDir(ks.path)
	for _, f := range files {
		if f.IsDir() {
			// 忽略文件夹
			continue
		}
		fileInfo, _ := f.Info()
		if fileInfo.Size() > (1 << 16) {
			// 存储密钥的文件最大不超过 64KB
			continue
		}

		raw, err := ioutil.ReadFile(filepath.Join(ks.path, f.Name()))
		if err != nil {
			continue
		}
		k, err := pemToPrivateKey(raw, ks.pwd)
		if err != nil {
			continue
		}

		// 寻找 ECDSA 的私钥。
		switch kk := k.(type) {
		case *ecdsa.PrivateKey:
			key = &ecdsaPrivateKey{privateKey: kk}
		default:
			continue
		}

		if !bytes.Equal(key.SKI(), ski) {
			continue
		}
		return key, nil
	}

	return nil, fmt.Errorf("key with SKI %x not found in %s", ski, ks.path)
}

// /////////////////////////////////////////////////////////////////
// getSuffix 存储密钥的文件，获取该文件的后缀：sk|pk|key。
func (ks *fileBasedKeyStore) getSuffix(alias string) string {
	files, _ := os.ReadDir(ks.path)
	for _, f := range files {
		if strings.HasPrefix(f.Name(), alias) {
			if strings.HasSuffix(f.Name(), "sk") {
				return "sk"
			}
			if strings.HasSuffix(f.Name(), "pk") {
				return "pk"
			}
			if strings.HasSuffix(f.Name(), "key") {
				return "key"
			}
			break
		}
	}
	return ""
}

// /////////////////////////////////////////////////////////////////
// storeECDSAPrivateKey 在指定文件中存储 ECDSA 私钥。
func (ks *fileBasedKeyStore) storeECDSAPrivateKey(alias string, privateKey interface{}) error {
	pem, err := ecdsaPrivateKeyToPEM(privateKey, ks.pwd)
	if err != nil {
		logger.Errorf("Failed converting private key to PEM [%s]: [%s].", alias, err)
		return err
	}

	if err = ioutil.WriteFile(ks.getPathForAlias(alias, "sk"), pem, 0600); err != nil {
		logger.Errorf("Failed storing private key [%s]: [%s].", alias, err)
		return err
	}

	return nil
}

// /////////////////////////////////////////////////////////////////
// storeECDSAPublicKey 在指定文件中存储 ECDSA 公钥。
func (ks *fileBasedKeyStore) storeECDSAPublicKey(alias string, publicKey interface{}) error {
	pem, err := ecdsaPublicKeyToPEM(publicKey, ks.pwd)
	if err != nil {
		logger.Errorf("Failed converting public key to PEM [%s]: [%s].", alias, err)
		return err
	}

	if err = ioutil.WriteFile(ks.getPathForAlias(alias, "pk"), pem, 0600); err != nil {
		logger.Errorf("Failed storing public key [%s]: [%s].", alias, err)
		return err
	}

	return nil
}

// /////////////////////////////////////////////////////////////////
// storeAESKey 在指定文件中存储 AES 密钥。
func (ks *fileBasedKeyStore) storeAESKey(alias string, key []byte) error {
	pem, err := aesToEncryptedPEM(key, ks.pwd)
	if err != nil {
		logger.Errorf("Failed converting aes key to PEM [%s]: [%s].", alias, err)
		return err
	}

	if err = ioutil.WriteFile(ks.getPathForAlias(alias, "key"), pem, 0600); err != nil {
		logger.Errorf("Failed storing aes key [%s]: [%s].", alias, err)
		return err
	}

	return nil
}

// loadPrivateKey 从文件加载私钥。
func (ks *fileBasedKeyStore) loadPrivateKey(alias string) (interface{}, error) {
	path := ks.getPathForAlias(alias, "sk")
	logger.Debugf("Loading private key [%s] at [%s]...", alias, path)

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorf("Failed loading private key [%s]: [%s].", alias, err)
		return nil, err
	}

	privateKey, err := pemToPrivateKey(raw, ks.pwd)
	if err != nil {
		logger.Errorf("Failed parsing private key [%s]: [%s].", alias, err)
		return nil, err
	}

	return privateKey, err
}

// loadPublicKey 从文件加载公钥。
func (ks *fileBasedKeyStore) loadPublicKey(alias string) (interface{}, error) {
	path := ks.getPathForAlias(alias, "pk")
	logger.Debugf("Loading public key [%s] at [%s]...", alias, path)

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorf("Failed loading public key [%s]: [%s].", alias, err)
		return nil, err
	}

	publicKey, err := pemToPublicKey(raw, ks.pwd)
	if err != nil {
		logger.Errorf("Failed parsing public key [%s]: [%s].", alias, err)
		return nil, err
	}

	return publicKey, err
}

// loadAESKey 从文件加载 AES 密钥。
func (ks *fileBasedKeyStore) loadAESKey(alias string) ([]byte, error) {
	path := ks.getPathForAlias(alias, "key")
	logger.Debugf("Loading key [%s] at [%s]...", alias, path)

	pem, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorf("Failed loading key [%s]: [%s].", alias, err)
		return nil, err
	}

	key, err := pemToAES(pem, ks.pwd)
	if err != nil {
		logger.Errorf("Failed parsing key [%s]: [%s].", alias, err)
		return nil, err
	}

	return key, nil
}

func (ks *fileBasedKeyStore) createKeyStore() error {
	logger.Debugf("Creating KeyStore at [%s]...", ks.path)

	if err := os.MkdirAll(ks.path, 0755); err != nil {
		return err
	}

	logger.Debugf("KeyStore created at [%s].", ks.path)
	return nil
}

func (ks *fileBasedKeyStore) openKeyStore() error {
	if ks.isOpen {
		return nil
	}
	ks.isOpen = true
	logger.Debugf("KeyStore opened at [%s]...done", ks.path)
	return nil
}

// getPathForAlias 获取别名的路径。
func (ks *fileBasedKeyStore) getPathForAlias(alias, suffix string) string {
	return filepath.Join(ks.path, alias+"_"+suffix)
}

// dirExists 判断指定路径的文件夹是否存在。
func dirExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		// 没出错，说明文件夹肯定存在。
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// dirEmpty 判断指定路径的文件夹是否为空。
func dirEmpty(path string) (bool, error) {
	fs, err := os.ReadDir(path)
	if err != nil {
		if err == io.EOF {
			return true, nil
		} else {
			return false, err
		}
	}
	return len(fs) == 0, nil
}
