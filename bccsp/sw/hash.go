package sw

import (
	"hash"

	"github.com/232425wxy/rocen/bccsp"
)

type hasher struct {
	hash func() hash.Hash // 用函数作为 hash 的类型，可以保证每次调用该方法时，返回的哈希函数都是干净的。
}

func (h *hasher) Hash(msh []byte, opts bccsp.HashOpts) ([]byte, error) {
	hash := h.hash()
	hash.Write(msh)
	return hash.Sum(nil), nil
}

func (h *hasher) GetHash(opts bccsp.HashOpts) (hash.Hash, error) {
	return h.hash(), nil
}