package tea

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

//TEA(Tiny Encryption Algorithm)是一种简单高效的加密算法,以加密解密速度快,实现简单高效著称.
//算法真的很简单,TEA算法每一次可以操作64-bit(8-byte), 采用128-bit(16-byte)作为key,算法采用迭代的形式,推荐的迭代轮数是64轮,最少32轮.

const (
	// TEA BlockSize 单位byte
	BlockSize = 8

	// KeySize TEA 算法 Key的byte长度.
	KeySize = 16

	// delta is the TEA key schedule 常量.
	delta = 0x9e3779b9

	// numRounds TEA算法 round 标准常量.
	numRounds = 64

	IVDefaultValue = "xteaXTEA"
)

//tea TEA加密算法.
type tea struct {
	key    [16]byte
	rounds int
}

// NewCipher 加密算法构造器,使用标准rounds, key 长度必须是 16 byte
func NewCipher(key []byte) (cipher.Block, error) {
	return NewCipherWithRounds(key, numRounds)
}

// NewCipherWithRounds 加密算法构造器,key 长度必须是 16 byte
func NewCipherWithRounds(key []byte, rounds int) (cipher.Block, error) {
	if len(key) != 16 {
		return nil, errors.New("tea: incorrect key size")
	}

	if rounds&1 != 0 {
		return nil, errors.New("tea: odd number of rounds specified")
	}

	c := &tea{
		rounds: rounds,
	}
	copy(c.key[:], key)

	return c, nil
}

//BlockSize 返回TEA block size,结果为常量. 方法来满足package "crypto/cipher" 的 Block interface
func (*tea) BlockSize() int {
	return BlockSize
}

//Encrypt 使用t.key 来加密 src参数8byte buffer内容,密文保存在dst里面.
// 注意data的长度大于block, 在连续的block上调用encrypt是不安全的,应该使用 CBC crypto/cipher/cbc.go 那种方式来encrypt
func (t *tea) Encrypt(dst, src []byte) {
	e := binary.BigEndian
	v0, v1 := e.Uint32(src), e.Uint32(src[4:])
	k0, k1, k2, k3 := e.Uint32(t.key[0:]), e.Uint32(t.key[4:]), e.Uint32(t.key[8:]), e.Uint32(t.key[12:])

	sum := uint32(0)
	delta := uint32(delta)

	for i := 0; i < t.rounds/2; i++ {
		sum += delta
		v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1)
		v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3)
	}

	e.PutUint32(dst, v0)
	e.PutUint32(dst[4:], v1)
}

// Decrypt 使用t.key 来解密 src参数8byte buffer内容,明文保存在dst里面.
func (t *tea) Decrypt(dst, src []byte) {
	e := binary.BigEndian
	v0, v1 := e.Uint32(src), e.Uint32(src[4:])
	k0, k1, k2, k3 := e.Uint32(t.key[0:]), e.Uint32(t.key[4:]), e.Uint32(t.key[8:]), e.Uint32(t.key[12:])

	delta := uint32(delta)
	sum := delta * uint32(t.rounds/2) // in general, sum = delta * n

	for i := 0; i < t.rounds/2; i++ {
		v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3)
		v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1)
		sum -= delta
	}

	e.PutUint32(dst, v0)
	e.PutUint32(dst[4:], v1)
}

// Encrypt is alias of EncryptCBC.
func Encrypt(plainText []byte, key []byte, iv ...[]byte) ([]byte, error) {
	return EncryptCBC(plainText, key, iv...)
}

// Decrypt is alias of DecryptCBC.
func Decrypt(cipherText []byte, key []byte, iv ...[]byte) ([]byte, error) {
	return DecryptCBC(cipherText, key, iv...)
}

func EncryptCBC(plainText []byte, key []byte, iv ...[]byte) ([]byte, error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	plainText = PKCS5Padding(plainText, blockSize)
	ivValue := ([]byte)(nil)
	if len(iv) > 0 {
		ivValue = iv[0]
	} else {
		ivValue = []byte(IVDefaultValue)
	}
	blockMode := cipher.NewCBCEncrypter(block, ivValue)
	cipherText := make([]byte, len(plainText))
	blockMode.CryptBlocks(cipherText, plainText)

	return cipherText, nil
}

// DecryptCBC decrypts <cipherText> using CBC mode.
// Note that the key must be 16 byte length.
// The parameter <iv> initialization vector is unnecessary.
func DecryptCBC(cipherText []byte, key []byte, iv ...[]byte) ([]byte, error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if len(cipherText) < blockSize {
		return nil, errors.New("cipherText too short")
	}
	ivValue := ([]byte)(nil)
	if len(iv) > 0 {
		ivValue = iv[0]
	} else {
		ivValue = []byte(IVDefaultValue)
	}
	if len(cipherText)%blockSize != 0 {
		return nil, errors.New("cipherText is not a multiple of the block size")
	}
	blockModel := cipher.NewCBCDecrypter(block, ivValue)
	plainText := make([]byte, len(cipherText))
	blockModel.CryptBlocks(plainText, cipherText)
	plainText, e := PKCS5UnPadding(plainText, blockSize)
	if e != nil {
		return nil, e
	}
	return plainText, nil
}

func PKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func PKCS5UnPadding(src []byte, blockSize int) ([]byte, error) {
	length := len(src)
	if blockSize <= 0 {
		return nil, errors.New("invalid blocklen")
	}

	if length%blockSize != 0 || length == 0 {
		return nil, errors.New("invalid data len")
	}

	unpadding := int(src[length-1])
	if unpadding > blockSize || unpadding == 0 {
		return nil, errors.New("invalid padding")
	}

	padding := src[length-unpadding:]
	for i := 0; i < unpadding; i++ {
		if padding[i] != byte(unpadding) {
			return nil, errors.New("invalid padding")
		}
	}

	return src[:(length - unpadding)], nil
}
