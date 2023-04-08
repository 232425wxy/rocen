package logging

import (
	"time"

	"github.com/go-stack/stack"
)

type logger struct {
	name        string
	filterLevel LogLevel
}

func (l *logger) log(msg string, level LogLevel, keyValues []interface{}) {
	entry := &Entry{
		time:      time.Now(),
		level:     level,
		message:   msg,
		call:      stack.Caller(2),
	}
	_ = entry
}
