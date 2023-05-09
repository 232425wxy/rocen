package sw

import (
	"os"

	"github.com/232425wxy/rocen/common/logging"
)

var opt = logging.Option{
	Module:         "bccsp_sw",
	FilterLevel:    logging.DebugLevel,
	Spec:           "%{color}%{level}[%{time}] [%{module}]%{color:reset}: %{message}",
	FormatSelector: "terminal",
	Writer:         os.Stdout,
}

var logger = logging.MustNewLogger(opt)
