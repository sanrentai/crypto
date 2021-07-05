package sm3

import (
	"encoding/hex"
	"testing"
)

var testData = map[string]string{
	"abc": "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
	"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd": "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"}

func TestSum(t *testing.T) {
	for src, expected := range testData {
		testSum(t, src, expected)
	}
}

func testSum(t *testing.T, src string, expected string) {
	hash := Sum([]byte(src))
	hashHex := hex.EncodeToString(hash[:])
	if hashHex != expected {
		t.Errorf("result:%s , not equal expected\n", hashHex)
		return
	}
}
