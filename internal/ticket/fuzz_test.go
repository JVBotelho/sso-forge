package ticket

import (
	"encoding/hex"
	"testing"
)

func FuzzEncryptRC4(f *testing.F) {
	k, _ := hex.DecodeString("61bb7f03790448210063f5fe4cf1ca50")

	f.Add([]byte{1, 2, 3})
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 1024))
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		result := encryptRC4(k, data, 2)
		if len(result) != 16+8+len(data) {
			t.Errorf("encryptRC4: expected %d bytes, got %d", 16+8+len(data), len(result))
		}
	})
}
