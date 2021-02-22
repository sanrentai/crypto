package sha256

import (
	"crypto/sha256"
	"encoding/hex"
)

func Hex(data []byte) string {
	return hex.EncodeToString(Sum(data))
}

func Sum(data []byte) []byte {
	digest := sha256.New()
	digest.Write(data)
	return digest.Sum(nil)
}
