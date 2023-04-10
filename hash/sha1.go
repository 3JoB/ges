// hmac package
//
// Deprecated: It is no longer recommended to use this package.
// It is suggested to use the github.com/3JoB/ulib/crypt/hash
// series of packages, such as github.com/3JoB/ulib/crypt/hash
// and github.com/3JoB/ulib/crypt/hash/hmac, because it provides
// a more comprehensive method of wrapping.

package hash

import (
	"crypto/sha1"

	"github.com/3JoB/ulib/hex"
)

func Sha1Hex(data []byte) string {
	return hex.EncodeToString(Sha1(data))
}

func Sha1(data []byte) []byte {
	digest := sha1.New()
	digest.Write(data)
	return digest.Sum(nil)
}
