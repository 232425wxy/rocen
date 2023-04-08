package metrics

import "github.com/go-stack/stack"

func CreateEntry() string {
	call := write()
	return call
}

func write() string {
	call := stack.Caller(2)
	return call.String()
}