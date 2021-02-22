package xtea

import (
	"bytes"
	"crypto/cipher"
	"errors"
)

// XTEA - 块TEA的继任者的第一个版本,
// 之后 TEA 算法被发现存在缺陷,作为回应,设计者提出了一个 TEA 的升级版本——XTEA(有时也被称为“tean”).
// XTEA 跟 TEA 使用了相同的简单运算,但它采用了截然不同的顺序,
//为了阻止密钥表攻击,四个子密钥(在加密过程中,原 128 位的密钥被拆分为 4 个 32 位的子密钥)采用了一种不太正规的方式进行混合,但速度更慢了

// XTEA is based on 64 rounds.
const numRounds = 64
const IVDefaultValue = "xteaXTEA"

// blockToUint32 读取8 byte 边出 2个 uint32
func blockToUint32(src []byte) (uint32, uint32) {
	r0 := uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
	r1 := uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
	return r0, r1
}

//uint32ToBlock 2个 uint32 边出 8 bytes
func uint32ToBlock(v0, v1 uint32, dst []byte) {
	dst[0] = byte(v0 >> 24)
	dst[1] = byte(v0 >> 16)
	dst[2] = byte(v0 >> 8)
	dst[3] = byte(v0)
	dst[4] = byte(v1 >> 24)
	dst[5] = byte(v1 >> 16)
	dst[6] = byte(v1 >> 8)
	dst[7] = byte(v1 >> 0)
}

// encryptBlock 使用XTEA加密单个8 byte block
func encryptBlock(c *Cipher, dst, src []byte) {
	v0, v1 := blockToUint32(src)

	// Two rounds of XTEA applied per loop
	for i := 0; i < numRounds; {
		v0 += ((v1<<4 ^ v1>>5) + v1) ^ c.table[i]
		i++
		v1 += ((v0<<4 ^ v0>>5) + v0) ^ c.table[i]
		i++
	}

	uint32ToBlock(v0, v1, dst)
}

// decryptBlock 使用XTEA解密单个8 byte block
func decryptBlock(c *Cipher, dst, src []byte) {
	v0, v1 := blockToUint32(src)

	// Two rounds of XTEA applied per loop
	for i := numRounds; i > 0; {
		i--
		v1 -= ((v0<<4 ^ v0>>5) + v0) ^ c.table[i]
		i--
		v0 -= ((v1<<4 ^ v1>>5) + v1) ^ c.table[i]
	}

	uint32ToBlock(v0, v1, dst)
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
