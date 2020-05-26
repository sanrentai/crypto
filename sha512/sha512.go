package sha512

import (
	"crypto/sha512"
	"encoding/hex"
)

func Hex(data []byte) string {
	return hex.EncodeToString(Sum(data))
}

func Sum(data []byte) []byte {
	digest := sha512.New()
	digest.Write(data)
	return digest.Sum(nil)
}
