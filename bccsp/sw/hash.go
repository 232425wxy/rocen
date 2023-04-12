package sw

import (
	"hash"

	"github.com/232425wxy/rocen/bccsp"
)

type hasher struct {
	hash func() hash.Hash // 方便每次调用哈希功能时实例化一个新的哈希函数。
}

func (c *hasher) Hash(msg []byte, opts bccsp.HashOpts) ([]byte, error) {
	h := c.hash()
	h.Write(msg)
	return h.Sum(nil), nil
}

func (c *hasher) GetHash(opts bccsp.HashOpts) (hash.Hash, error) {
	return c.hash(), nil
}