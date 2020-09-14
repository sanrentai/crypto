package xtea

import "strconv"

// XTEA block size in bytes.
const BlockSize = 8

// A Cipher is an instance of an XTEA cipher using a particular key.
type Cipher struct {
	// table contains a series of precalculated values that are used each round.
	table [64]uint32
}

// KeySizeError 自定义错误
type KeySizeError int

// Error .
func (k KeySizeError) Error() string {
	return "crypto/xtea: invalid key size " + strconv.Itoa(int(k))
}

// NewCipher 构造器.
// key 只能长度 16 bytes.
func NewCipher(key []byte) (*Cipher, error) {
	k := len(key)
	switch k {
	default:
		return nil, KeySizeError(k)
	case 16:
		break
	}

	c := new(Cipher)
	initCipher(c, key)

	return c, nil
}

//BlockSize 返回XTEA block size,结果为常量. 方法来满足package "crypto/cipher" 的 Block interface
func (c *Cipher) BlockSize() int { return BlockSize }

// Encrypt 加密 src参数8byte buffer内容,明文保存在dst里面.
// 注意data的长度大于block, 在连续的block上调用encrypt是不安全的,应该使用 CBC crypto/cipher/cbc.go 那种方式来encrypt
func (c *Cipher) Encrypt(dst, src []byte) { encryptBlock(c, dst, src) }

// Decrypt decrypts the 8 byte buffer src using the key and stores the result in dst.
// Decrypt 使用t.key 来解密 src参数8byte buffer内容,明文保存在dst里面.

func (c *Cipher) Decrypt(dst, src []byte) { decryptBlock(c, dst, src) }

// initCipher 把key转换成计算好的table
func initCipher(c *Cipher, key []byte) {
	// Load the key into four uint32s
	var k [4]uint32
	for i := 0; i < len(k); i++ {
		j := i << 2 // Multiply by 4
		k[i] = uint32(key[j+0])<<24 | uint32(key[j+1])<<16 | uint32(key[j+2])<<8 | uint32(key[j+3])
	}

	// Precalculate the table
	const delta = 0x9E3779B9
	var sum uint32

	// Two rounds of XTEA applied per loop
	for i := 0; i < numRounds; {
		c.table[i] = sum + k[sum&3]
		i++
		sum += delta
		c.table[i] = sum + k[(sum>>11)&3]
		i++
	}
}
