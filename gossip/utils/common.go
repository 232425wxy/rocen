package utils

import (
	"bytes"
	"encoding/hex"
)

///////////////////////////////////////////////////////////////////
// PKIidType

// PKIidType 定义了持有 PKI-id 的类型，PKI-id 是一个 peer 的安全标识。
type PKIidType []byte

func (p PKIidType) String() string {
	if p == nil {
		return "<nil>"
	}
	return hex.EncodeToString(p)
}

// IsNotSameFilter 是一个过滤函数，用来判断当前 id 是否与另一个 id 不相等，
// 不相等时返回 true。
func (id PKIidType) IsNotSameFilter(that PKIidType) bool {
	return !bytes.Equal(id, that)
}

///////////////////////////////////////////////////////////////////
// MessageAcceptor

// MessageAcceptor 是一个谓词，用于确定创建 MessageAcceptor 实例的订阅
// 者对哪些消息感兴趣。
type MessageAcceptor func(interface{}) bool

///////////////////////////////////////////////////////////////////
// Payload

// Payload 定义了一个包含 ledger block 的对象。
type Payload struct {
	ChannelID ChannelID // 区块的 channel id。
	Data      []byte    // 消息内容，可能被加密或者被签名。
	Hash      string    // 消息的哈希值。
	SeqNum    uint64    // 消息的序列号。
}

///////////////////////////////////////////////////////////////////
// ChannelID

// ChannelID 定义了一条 chain 的身份 id。
type ChannelID []byte

func (c ChannelID) String() string {
	return hex.EncodeToString(c)
}

///////////////////////////////////////////////////////////////////
// MessageReplacingPolicy

// MessageReplacingPolicy
type MessageReplacingPolicy func(this interface{}, that interface{}) InvalidationResult

///////////////////////////////////////////////////////////////////
// InvalidationResult

// InvalidationResult 决定了当一个消息被放入 gossip store 时，它如何影响另一个消息。
type InvalidationResult int

const (
	// MessageNoAction 表示消息不起作用。
	MessageNoAction InvalidationResult = iota
	// MessageInvalidates 表示当前消息使其他消息无效。
	MessageInvalidates
	// MessageInvalidated 表示其他消息使当前消息无效。
	MessageInvalidated
)