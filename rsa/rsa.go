package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"
)

type PKCS int

const (
	PKCS1 PKCS = iota
	PKCS8
)

var rsatypes = map[PKCS]string{
	PKCS1: "RSA PRIVATE KEY",
	PKCS8: "PRIVATE KEY",
}

const (
	// PKCS1            = "RSA PRIVATE KEY"
	// PKCS8            = "PRIVATE KEY"
	PUBKEY           = "PUBLIC KEY"
	RSAAlgorithmSign = crypto.SHA256
)

// 生成密钥对
func GenerateKeyFile(bits int, pkcs PKCS, privateKeyPath, publicKeyPath, certPath string) error {
	if publicKeyPath == "" {
		publicKeyPath = "public.pem"
	}
	if privateKeyPath == "" {
		privateKeyPath = "private.pem"
	}
	if certPath == "" {
		certPath = "cert.crt"
	}

	if bits == 0 || bits < 1024 {
		bits = 1024
	}

	//创建文件保存私钥
	privateFile, err := os.Create(privateKeyPath)
	if err != nil {
		return err
	}
	defer privateFile.Close()

	//创建用于保存公钥的文件
	publicFile, err := os.Create(publicKeyPath)
	if err != nil {
		return err
	}
	defer publicFile.Close()

	// 证书文件
	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}

	//GenerateKey函数使用随机数据生成器random生成一对具有指定字位数的RSA密钥
	//Reader是一个全局、共享的密码用强随机数生成器
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	//保存私钥
	//通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	// x509.MarshalPKCS8PrivateKey
	var X509PrivateKey []byte
	switch pkcs {
	case PKCS1:
		X509PrivateKey = x509.MarshalPKCS1PrivateKey(privateKey)
	case PKCS8:
		X509PrivateKey, err = x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return err
		}
	}

	//使用pem格式对x509输出的内容进行编码
	//构建一个pem.Block结构体对象
	privateBlock := pem.Block{Type: rsatypes[pkcs], Bytes: X509PrivateKey}
	//将数据保存到文件
	err = pem.Encode(privateFile, &privateBlock)
	if err != nil {
		return err
	}

	//保存公钥
	//获取公钥的数据
	publicKey := privateKey.PublicKey
	//X509对公钥编码
	X509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return err
	}

	//pem格式编码
	//创建一个pem.Block结构体对象
	publicBlock := pem.Block{Type: PUBKEY, Bytes: X509PublicKey}
	//保存到文件
	err = pem.Encode(publicFile, &publicBlock)

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
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &publicKey, privateKey) //DER 格式
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICAET", Bytes: derBytes})
	return err
}

// 通过pem文件生成rsa私钥
func ParsePrivateKey(path string) (*rsa.PrivateKey, error) {
	bs, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(bs)
	switch b.Type {
	case rsatypes[PKCS1]:
		return x509.ParsePKCS1PrivateKey(b.Bytes)
	case rsatypes[PKCS8]:
		k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
		if err != nil {
			return nil, err
		}
		return k.(*rsa.PrivateKey), nil
	}
	return x509.ParsePKCS1PrivateKey(b.Bytes)
}

// 通过pem文件生成rsa公钥
func ParsePublicKey(path string) (*rsa.PublicKey, error) {
	bs, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(bs)
	pubkey, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, err
	}

	return pubkey.(*rsa.PublicKey), nil
}

// RSA加密
// path 公钥匙文件地址
// msg 要加密的数据
func Encrypt(path string, msg []byte) ([]byte, error) {
	key, err := ParsePublicKey(path)
	if err != nil {
		return nil, err
	}
	//对明文进行加密
	return rsa.EncryptPKCS1v15(rand.Reader, key, msg)
}

// RSA解密
// path 私钥匙文件地址
// msg 要解密的数据
func Decrypt(path string, msg []byte) ([]byte, error) {
	key, err := ParsePrivateKey(path)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, key, msg)
}

// RSA签名
// path 私钥匙文件地址
// msg 要解密的数据
func Sign(path string, msg []byte) ([]byte, error) {
	key, err := ParsePrivateKey(path)
	if err != nil {
		return nil, err
	}

	//计算散列值
	// rsa.SignPSS
	hash := crypto.Hash.New(crypto.SHA1) //进行SHA1的散列
	hash.Write(msg)
	bytes := hash.Sum(nil)
	//SignPKCS1v15使用RSA PKCS#1 v1.5规定的RSASSA-PKCS1-V1_5-SIGN签名方案计算签名
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, bytes)
}

func SignSHA256(path string, msg []byte) ([]byte, error) {
	key, err := ParsePrivateKey(path)
	if err != nil {
		return nil, err
	}
	hash := crypto.Hash.New(crypto.SHA256) //进行SHA256的散列
	hash.Write(msg)
	bytes := hash.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, bytes)
}

// RSA验签
// path 公钥匙文件地址
// msg 解密的数据
// sign 签名的数据
func VerifySHA256(path string, msg, sign []byte) bool {
	//计算消息散列值
	hash := crypto.Hash.New(crypto.SHA256)
	hash.Write(msg)
	bytes := hash.Sum(nil)
	key, err := ParsePublicKey(path)
	if err != nil {
		return false
	}
	err = rsa.VerifyPKCS1v15(key, crypto.SHA256, bytes, sign)
	return err == nil
}

// RSA验签
// path 公钥匙文件地址
// msg 解密的数据
// sign 签名的数据
func Verify(path string, msg, sign []byte) bool {
	//计算消息散列值
	hash := crypto.Hash.New(crypto.SHA1)
	hash.Write(msg)
	bytes := hash.Sum(nil)
	key, err := ParsePublicKey(path)
	if err != nil {
		return false
	}
	err = rsa.VerifyPKCS1v15(key, crypto.SHA1, bytes, sign)
	return err == nil
}
