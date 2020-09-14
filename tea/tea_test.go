package tea

import (
	"fmt"
	"testing"
)

func Test_tea_Encrypt(t *testing.T) {
	type args struct {
		dst []byte
		src []byte
	}
	tests := []struct {
		name string
		t    *tea
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.t.Encrypt(tt.args.dst, tt.args.src)
		})
	}
}

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
