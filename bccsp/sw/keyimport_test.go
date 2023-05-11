package sw

import "testing"

func TestBytesNilLength(t *testing.T) {
	test := func(raw interface{}) {
		bytesRaw, ok := raw.([]byte)

		if !ok {
			t.Log("not bytes, return")
			return
		}

		if bytesRaw == nil {
			t.Log("bytes is nil")
		}

		t.Log(len(bytesRaw))
	}

	var raw []byte

	test(raw)
}
