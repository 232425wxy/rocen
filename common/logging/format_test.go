package logging_test

import (
	"bytes"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/232425wxy/rocen/common/logging"
	"github.com/232425wxy/rocen/common/metrics"
	"github.com/go-stack/stack"
	"github.com/stretchr/testify/require"
)

func TestStackCall(t *testing.T) {
	call := metrics.CreateEntry()
	fmt.Println(call)
}

func TestRegexp(t *testing.T) {
	var formatRegexp = regexp.MustCompile(`%{(color|level|time|module|location|message)(?::(.*?))?}`)
	spec := "%{color}%{level:in}"

	matches := formatRegexp.FindAllStringSubmatchIndex(spec, -1)
	for _, match := range matches {
		t.Log(match)
	}
}

func TestParseFormat(t *testing.T) {
	mf := logging.NewMultiFormatter()

	var tests = []struct {
		spec string
		e logging.Entry
	}{
		{
			spec: "%{color}%{level}[%{time}]%{color:reset}%{message}",
			e: logging.Entry{
				Level:   logging.DebugLevel,
				Time:    time.Now(),
				Module:  "consensus",
				Call:    stack.Caller(0),
				Message: "prepare consensus",
			},
		},
		{
			spec: "%{color}[%{time}]%{color:reset} => %{message}",
			e: logging.Entry{
				Level:   logging.InfoLevel,
				Time:    time.Now(),
				Module:  "consensus",
				Call:    stack.Caller(0),
				Message: "prepare consensus",
			},
		},
		{
			spec: "%{color}%{level}[%{time}][%{module}]%{color:reset}%{message}",
			e: logging.Entry{
				Level:   logging.WarnLevel,
				Time:    time.Now(),
				Module:  "consensus",
				Call:    stack.Caller(0),
				Message: "prepare consensus",
			},
		},
		{
			spec: "%{color}%{level}[%{time}][%{location}]%{color:reset}%{message}",
			e: logging.Entry{
				Level:   logging.ErrorLevel,
				Time:    time.Now(),
				Module:  "consensus",
				Call:    stack.Caller(0),
				Message: "prepare consensus",
			},
		},
		{
			spec: "%{color}[%{time}][%{location}]%{message}%{color:reset}",
			e: logging.Entry{
				Level:   logging.PanicLevel,
				Time:    time.Now(),
				Module:  "consensus",
				Call:    stack.Caller(0),
				Message: "prepare consensus",
			},
		},
	}

	buf := new(bytes.Buffer)
	for _, test := range tests {
		formatters, err := logging.ParseFormat(test.spec)
		require.NoError(t, err)
		mf.SetFormatters(formatters)
		mf.Format(buf, test.e)
		buf.Write([]byte("\n"))
	}
	fmt.Println(buf.String())
}
