package gm2gm4

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"math/rand"
	"time"

	"github.com/sanrentai/crypto"
	"github.com/sanrentai/crypto/gm2"
	"github.com/sanrentai/crypto/gm4"
)

func getRandomString(l int) string {
	return string(getRandomBytes(l))
}

func getRandomBytes(l int) []byte {
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
	// 生成gm4密钥
	gm4Key := getRandomBytes(gm4.KeySize)
	// 根据公钥地址，生成公钥的
	pubkeyBytes, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return "", err
	}
	pubkey, err := gm2.RawBytesToPublicKey(pubkeyBytes)
	if err != nil {
		return "", err
	}
	// 根据私钥地址，生成公钥的
	prikeyBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return "", err
	}
	prikey, err := gm2.RawBytesToPrivateKey(prikeyBytes)
	if err != nil {
		return "", err
	}
	// 将gm4密钥加密
	t, err := gm2.Encrypt(pubkey, gm4Key, gm2.C1C3C2)
	if err != nil {
		return "", err
	}
	// 对原文进行签名
	st, err := gm2.Sign(prikey, gm4Key, []byte(msg))
	if err != nil {
		return "", err
	}
	// 使用gm4密钥加密原文
	c, err := gm4.ECBEncryptPKCS7padding(gm4Key, []byte(msg))
	if err != nil {
		return "", err
	}
	jm := crypto.JiaMi{
		T:  base64.StdEncoding.EncodeToString(t),
		St: base64.StdEncoding.EncodeToString(st),
		C:  base64.StdEncoding.EncodeToString(c),
	}
	return jm.ToJsonString(), nil
}

// 解密
func Decrypt(msg, privateKeyPath, publicKeyPath string) (string, error) {
	jm := crypto.JiaMi{}
	err := json.Unmarshal([]byte(msg), &jm)
	if err != nil {
		return "", err
	}
	// 根据公钥地址，生成公钥的
	pubkeyBytes, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return "", err
	}
	pubkey, err := gm2.RawBytesToPublicKey(pubkeyBytes)
	if err != nil {
		return "", err
	}
	// 根据私钥地址，生成公钥的
	prikeyBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return "", err
	}
	prikey, err := gm2.RawBytesToPrivateKey(prikeyBytes)
	if err != nil {
		return "", err
	}
	gm4KeyEncrypted, err := base64.StdEncoding.DecodeString(jm.T)
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
	// rsa 解密获得gm4密钥
	gm4Key, err := gm2.Decrypt(prikey, gm4KeyEncrypted, gm2.C1C3C2)
	if err != nil {
		return "", err
	}
	// gm4解密获得原文
	yw, err := gm4.ECBDecryptPKCS7padding(gm4Key, contentBytes)
	if err != nil {
		return "", err
	}
	if gm2.Verify(pubkey, gm4Key, yw, sign) {
		return string(yw), nil
	}
	return "", errors.New("验签失败！")
}
