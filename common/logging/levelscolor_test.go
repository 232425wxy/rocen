package logging_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/232425wxy/rocen/common/logging"
)

func TestColor(t *testing.T) {
	var tests = []struct {
		desc    string
		level   logging.LogLevel
		message string
	}{
		{
			desc:    "debug",
			level:   logging.DebugLevel,
			message: "output debug level log",
		},
		{
			desc:    "info",
			level:   logging.InfoLevel,
			message: "output info level log",
		},
		{
			desc:    "warn",
			level:   logging.WarnLevel,
			message: "output warn level log",
		},
		{
			desc:    "error",
			level:   logging.ErrorLevel,
			message: "output error level log",
		},
		{
			desc:    "panic",
			level:   logging.PanicLevel,
			message: "output panic level log",
		},
	}

	buf := new(bytes.Buffer)
	buf.Reset()
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			fmt.Fprint(buf, test.level.SpecifiedColor().Color(), test.message, logging.ResetColor()+"\n")
			t.Log("")
		})
	}
	fmt.Print(buf.String())
}
