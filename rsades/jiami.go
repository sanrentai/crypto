package rsades

import "encoding/json"

type JiaMi struct {
	T  string `json:"t"`  // rsa加密后的des密钥
	St string `json:"st"` // 原文的rsa私钥签名
	C  string `json:"c"`  // des加密后的密文
}

func (this *JiaMi) ToJsonString() string {
	bytes, _ := json.Marshal(this)
	return string(bytes)
}

func (this *JiaMi) ToBytes() []byte {
	bytes, _ := json.Marshal(this)
	return bytes
}
