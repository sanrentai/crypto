package gm4

import (
	"encoding/base64"
	"testing"
)

func TestECB(t *testing.T) {
	key := `qwertyuiasdfghjk`
	in := `0123456789abcdef`
	out, err := ECBEncryptPKCS7padding([]byte(key), []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(base64.StdEncoding.EncodeToString(out))
	out2, err := ECBDecryptPKCS7padding([]byte(key), out)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(out2))
}
