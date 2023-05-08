package sw

import (
	"io"
	"os"
	"sync"
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

// func NewFileBasedKeyStore(pwd []byte, path string, readOnly bool) (bccsp.KeyStore, error) {

// }

func dirEmpty(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.ReadDir(1)
	if err == io.EOF {
		return true, nil
	}
	return false, nil
}
