package sw

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReaddir(t *testing.T) {
	f, err := os.Open("/home/rocen/lab/code/go/src")
	assert.NoError(t, err)
	defer f.Close()

	entries, err := f.ReadDir(4)
	if err != io.EOF {
		assert.NoError(t, err)
	}

	for i := 0; i < len(entries); i++ {
		t.Log(entries[i])
	}
}
