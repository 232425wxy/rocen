package logging

import (
	"fmt"
	"io"
	"regexp"
)

// formatRegexp 匹配日志格式的正则表达式。这里用到了非捕获匹配规则 `?:`，非捕获匹配规则的简单解释如下：
// 给定一个待匹配字符串："%{color:reset}%{level:info}"，我们利用 formatRegexp 来匹配该字符串，得到如
// 下结果：
// [0 13] [2 6] [2 12] [14 26] [16 20] [16 25]，每个中括号里的数字分别对应匹配到的不同字符串的左右边界；
// 如果去掉正则表达式里的 `?:`，改用捕获匹配规则，得到的匹配结果会是下面这样的：
// [0 13] [2 6] [7 12] [2 12] [14 26] [16 20] [21 25] [16 25]，会发现多了 [7 12] 和 [21 25]，也就是
// 说，捕获匹配也将字符串的子串 ":reset" 和 ":info" 也单独匹配出来了。
var formatRegexp = regexp.MustCompile(`%{(color|level|time|module|location|message)(?::(.*?))?}`)

type Formatter interface {
	Format(w io.Writer, e Entry)
}

// func ParseFormat(spec string) ([]Formatter, error) {

// }

type ColorFormatter struct {
	reset bool
}

func newColorFormatter(f string) (ColorFormatter, error) {
	switch f {
	case "reset":
		return ColorFormatter{reset: true}, nil
	case "":
		return ColorFormatter{}, nil
	default:
		return ColorFormatter{}, fmt.Errorf("invalid color option: %s", f)
	}
}