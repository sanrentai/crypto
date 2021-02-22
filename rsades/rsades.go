// rsa+des混合加密
package rsades

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/rand"
	"time"

	"github.com/sanrentai/crypto/des"
	"github.com/sanrentai/crypto/rsa"
)

func GetRandomString(l int) string {
	return string(GetRandomBytes(l))
}

func GetRandomBytes(l int) []byte {
	str := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%^&*()_+-=<>,./?{}[]"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return result
}

// 加密
func Encrypt(msg, privateKeyPath, publicKeyPath string) (string, error) {
	// 生成des密钥
	desKey := GetRandomBytes(16)
	// 将des密钥加密
	t, err := rsa.Encrypt(publicKeyPath, desKey)
	if err != nil {
		return "", err
	}
	// 对原文进行签名
	st, err := rsa.Sign(privateKeyPath, []byte(msg))
	if err != nil {
		return "", err
	}
	// 使用des密钥加密原文
	c, err := des.EncryptECB([]byte(msg), desKey, des.PKCS5PADDING)
	if err != nil {
		return "", err
	}
	jm := JiaMi{
		T:  base64.StdEncoding.EncodeToString(t),
		St: base64.StdEncoding.EncodeToString(st),
		C:  base64.StdEncoding.EncodeToString(c),
	}
	return jm.ToJsonString(), nil
}

// 解密
func Decrypt(msg, privateKeyPath, publicKeyPath string) (string, error) {
	jm := JiaMi{}
	err := json.Unmarshal([]byte(msg), &jm)
	if err != nil {
		return "", err
	}
	desKeyEncrypted, err := base64.StdEncoding.DecodeString(jm.T)
	if err != nil {
		return "", err
	}
	contentBytes, err := base64.StdEncoding.DecodeString(jm.C)
	if err != nil {
		return "", err
	}
	sign, err := base64.StdEncoding.DecodeString(jm.St)
	if err != nil {
		return "", err
	}
	// rsa 解密获得des密钥
	desKey, err := rsa.Decrypt(privateKeyPath, desKeyEncrypted)
	if err != nil {
		return "", err
	}
	// des解密获得原文
	yw, err := des.DecryptECB(contentBytes, desKey, des.PKCS5PADDING)
	if err != nil {
		return "", err
	}
	if rsa.Verify(publicKeyPath, yw, sign) {
		return string(yw), nil
	}
	return "", errors.New("验签失败！")
}
