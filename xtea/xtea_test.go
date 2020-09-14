package xtea

import (
	"fmt"
	"testing"
)

func TestEncrypt(t *testing.T) {
	t.Log("加密开始")
	mw, err := Encrypt([]byte("你好吗"), []byte("abcd1234abcd1234"))
	t.Log("加密结束")
	if err != nil {
		t.Log(err)
		return
	}
	t.Log(fmt.Sprintf("%x", mw))
	src, err := Decrypt(mw, []byte("abcd1234abcd1234"))
	if err != nil {
		t.Log(err)
		return
	}
	t.Log(string(src))
}
