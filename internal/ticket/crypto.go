package ticket

import (
	"crypto/hmac"
	"crypto/md5"
)

func init() {
	_hmacMD5 = func(key, data []byte) []byte {
		m := hmac.New(md5.New, key)
		m.Write(data)
		return m.Sum(nil)
	}
}
