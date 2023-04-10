// hmac package
//
// Deprecated: It is no longer recommended to use this package.
// It is suggested to use the github.com/3JoB/ulib/crypt/hash
// series of packages, such as github.com/3JoB/ulib/crypt/hash
// and github.com/3JoB/ulib/crypt/hash/hmac, because it provides
// a more comprehensive method of wrapping.
package hash

import (
	"github.com/3JoB/ulib/crypt/hash"
	"github.com/3JoB/ulib/crypt/hash/hmac"
)

func HmacSha256(key, body []byte) []byte {
	return hmac.SHA256(body, key).Sum(nil)
}

func HmacSha256Hex(key, body []byte) string {
	return hash.HexEncoding(hmac.SHA256(body, key))
}

func HmacSha512(key, body []byte) []byte {
	return hmac.SHA512(body, key).Sum(nil)
}

func HmacSha512Hex(key, body []byte) string {
	return hash.HexEncoding(hmac.SHA512(body, key))
}
