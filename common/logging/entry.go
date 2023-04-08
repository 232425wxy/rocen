package logging

import (
	"time"

	"github.com/go-stack/stack"
)

type Entry struct {
	level   LogLevel
	time    time.Time
	module  string
	call    stack.Call
	message string
}
