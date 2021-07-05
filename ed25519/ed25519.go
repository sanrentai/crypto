package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	PRIVATE_KEY = "ED25519 PRIVATE KEY"
	PUBLIC_KEY  = "PUBLIC KEY"
)

func GenerateKeyFile(privateKeyFile, publickKeyFile string) error {

	pub, pri, err := ed25519.GenerateKey(nil)

	if err != nil {
		return err
	}

	prifile, err := os.Create(privateKeyFile)
	if err != nil {
		return err
	}
	defer prifile.Close()

	_, err = prifile.Write(pri)
	if err != nil {
		return err
	}

	pubfile, err := os.Create(publickKeyFile)
	if err != nil {
		return err
	}
	defer pubfile.Close()

	_, err = pubfile.Write(pub)
	if err != nil {
		return err
	}

	return nil
}

func GenerateKeyPemFile(privateKeyFile, publickKeyFile, certPath string) error {

	pub, pri, err := ed25519.GenerateKey(nil)

	if err != nil {
		return err
	}

	prifile, err := os.Create(privateKeyFile)
	if err != nil {
		return err
	}
	defer prifile.Close()

	priblock := pem.Block{
		Type:  PRIVATE_KEY,
		Bytes: pri,
	}

	if err = pem.Encode(prifile, &priblock); err != nil {
		return err
	}

	pubfile, err := os.Create(publickKeyFile)
	if err != nil {
		return err
	}
	defer pubfile.Close()

	pubblock := pem.Block{
		Type:  PUBLIC_KEY,
		Bytes: pub,
	}

	if err = pem.Encode(pubfile, &pubblock); err != nil {
		return err
	}

	if certPath == "" {
		certPath = "cert.crt"
	}

	// 证书文件
	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}

	// 生成证书
	max := new(big.Int).Lsh(big.NewInt(1), 128)   //把 1 左移 128 位，返回给 big.Int
	serialNumber, _ := rand.Int(rand.Reader, max) //返回在 [0, max) 区间均匀随机分布的一个随机值
	subject := pkix.Name{                         //Name代表一个X.509识别名。只包含识别名的公共属性，额外的属性被忽略。
		Organization:       []string{"Organization"},
		OrganizationalUnit: []string{"ou"},
		CommonName:         "CommonName",
	}
	template := x509.Certificate{
		SerialNumber: serialNumber, // SerialNumber 是 CA 颁布的唯一序列号，在此使用一个大随机数来代表它
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature, //KeyUsage 与 ExtKeyUsage 用来表明该证书是用来做服务器认证的
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},               // 密钥扩展用途的序列
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	//CreateCertificate基于模板创建一个新的证书
	//第二个第三个参数相同，则证书是自签名的
	//返回的切片是DER编码的证书
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, pub, pri) //DER 格式
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICAET", Bytes: derBytes})

	return nil
}

func PrivateKeyFromPem(path string) (ed25519.PrivateKey, error) {
	bs, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(bs)
	if b == nil {
		if len(bs) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(bs), err
		} else {
			return nil, errors.New("data lenth error")
		}

	}
	switch b.Type {
	case PRIVATE_KEY:
		if len(b.Bytes) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(b.Bytes), nil
		} else {
			return nil, errors.New("data lenth error")
		}
	}

	return nil, errors.New("data error")

}

func PublicKeyFromPem(path string) (ed25519.PublicKey, error) {
	bs, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(bs)
	if b == nil {
		if len(bs) == ed25519.PublicKeySize {
			return ed25519.PublicKey(bs), err
		} else {
			return nil, errors.New("data lenth error")
		}
	}
	switch b.Type {
	case PUBLIC_KEY:
		if len(b.Bytes) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b.Bytes), nil
		} else {
			return nil, errors.New("data lenth error")
		}

	}

	return nil, errors.New("data error")
}

func PublicKeyFromB64(b64 string) (ed25519.PublicKey, error) {
	bs, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if len(bs) == ed25519.PublicKeySize {
		return ed25519.PublicKey(bs), nil
	} else {
		return nil, errors.New("data lenth error")
	}
}

func PrivateKeyFromB64(b64 string) (ed25519.PrivateKey, error) {
	bs, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if len(bs) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(bs), nil
	} else {
		return nil, errors.New("data lenth error")
	}
}

func PublicKey(bs []byte) (ed25519.PublicKey, error) {
	if len(bs) == ed25519.PublicKeySize {
		return ed25519.PublicKey(bs), nil
	} else {
		return nil, errors.New("data lenth error")
	}
}

func PrivateKey(bs []byte) (ed25519.PrivateKey, error) {
	if len(bs) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(bs), nil
	} else {
		return nil, errors.New("data lenth error")
	}
}

func Sign(privateKey ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(privateKey, message)
}

func Verify(publicKey ed25519.PublicKey, message, sig []byte) bool {
	return ed25519.Verify(publicKey, message, sig)
}

func SignFile(path string, message []byte) ([]byte, error) {
	key, err := PrivateKeyFromPem(path)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key, message), nil
}

func VerifyFile(path string, message, sig []byte) (bool, error) {
	key, err := PublicKeyFromPem(path)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(key, message, sig), nil
}

func SignString(privateKey ed25519.PrivateKey, message string) (string, error) {
	m, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return message, err
	}
	s := ed25519.Sign(privateKey, m)
	return base64.StdEncoding.EncodeToString(s), nil
}

func VerifyString(publicKey ed25519.PublicKey, message, sig string) (bool, error) {
	m, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return false, err
	}
	s, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(publicKey, m, s), nil
}
