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
)

func Sha512Hex(data []byte) string {
	return hash.HexEncoding(hash.SHA512(data))
}

func Sha512(data []byte) []byte {
	return hash.SHA512(data).Sum(nil)
}
