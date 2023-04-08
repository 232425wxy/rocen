package logging

import "fmt"



type LogLevel int8

const (
	PanicLevel = iota
	ErrorLevel
	WarnLevel
	InfoLevel
	DebugLevel
)

func (l LogLevel) CapitalString() string {
	switch l {
	case PanicLevel:
		return "PANIC"
	case ErrorLevel:
		return "ERROR"
	case WarnLevel:
		return "WARN "
	case InfoLevel:
		return "INFO "
	case DebugLevel:
		return "DEBUG"
	default:
		panic(fmt.Sprintf("invalid log level: (%d)", l))
	}
}

func (l LogLevel) LowercaseString() string {
	switch l {
	case PanicLevel:
		return "panic"
	case ErrorLevel:
		return "error"
	case WarnLevel:
		return "warn "
	case InfoLevel:
		return "info "
	case DebugLevel:
		return "debug"
	default:
		panic(fmt.Sprintf("invalid log level: (%d)", l))
	}
}

