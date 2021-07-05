package gm2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash"
	"math/big"

	"github.com/sanrentai/crypto/gm3"
)

type ExchangeResult struct {
	Key []byte
	S1  []byte
	S2  []byte
}

func reduce(x *big.Int, w int) *big.Int {
	intOne := new(big.Int).SetInt64(1)
	result := Lsh(intOne, uint(w))
	result = Sub(result, intOne)
	result = And(x, result)
	result = SetBit(result, w, 1)
	return result
}

func calculateU(w int, selfStaticPriv *PrivateKey, selfEphemeralPriv *PrivateKey, selfEphemeralPub *PublicKey,
	otherStaticPub *PublicKey, otherEphemeralPub *PublicKey) (x *big.Int, y *big.Int) {
	x1 := reduce(selfEphemeralPub.X, w)
	x2 := reduce(otherEphemeralPub.X, w)
	tA := Mul(x1, selfEphemeralPriv.D)
	tA = Add(selfStaticPriv.D, tA)
	k1 := Mul(sm2H, tA)
	k1 = Mod(k1, selfStaticPriv.Curve.N)
	k2 := Mul(k1, x2)
	k2 = Mod(k2, selfStaticPriv.Curve.N)

	p1x, p1y := selfStaticPriv.Curve.ScalarMult(otherStaticPub.X, otherStaticPub.Y, k1.Bytes())
	p2x, p2y := selfStaticPriv.Curve.ScalarMult(otherEphemeralPub.X, otherEphemeralPub.Y, k2.Bytes())
	x, y = selfStaticPriv.Curve.Add(p1x, p1y, p2x, p2y)
	return
}

func kdfForExch(digest hash.Hash, ux, uy *big.Int, za, zb []byte, keyBits int) []byte {
	bufSize := 4
	if bufSize < digest.BlockSize() {
		bufSize = digest.BlockSize()
	}
	buf := make([]byte, bufSize)

	rv := make([]byte, (keyBits+7)/8)
	rvLen := len(rv)
	uxBytes := ux.Bytes()
	uyBytes := uy.Bytes()
	off := 0
	ct := uint32(0)
	for off < rvLen {
		digest.Reset()
		digest.Write(uxBytes)
		digest.Write(uyBytes)
		digest.Write(za)
		digest.Write(zb)
		ct++
		binary.BigEndian.PutUint32(buf, ct)
		digest.Write(buf[:4])
		tmp := digest.Sum(nil)
		copy(buf[:bufSize], tmp[:bufSize])

		copyLen := rvLen - off
		copy(rv[off:off+copyLen], buf[:copyLen])
		off += copyLen
	}
	return rv
}

func calculateInnerHash(digest hash.Hash, ux *big.Int, za, zb []byte, p1x, p1y *big.Int, p2x, p2y *big.Int) []byte {
	digest.Reset()
	digest.Write(ux.Bytes())
	digest.Write(za)
	digest.Write(zb)
	digest.Write(p1x.Bytes())
	digest.Write(p1y.Bytes())
	digest.Write(p2x.Bytes())
	digest.Write(p2y.Bytes())
	return digest.Sum(nil)
}

func s1(digest hash.Hash, uy *big.Int, innerHash []byte) []byte {
	digest.Reset()
	digest.Write([]byte{0x02})
	digest.Write(uy.Bytes())
	digest.Write(innerHash)
	return digest.Sum(nil)
}

func s2(digest hash.Hash, uy *big.Int, innerHash []byte) []byte {
	digest.Reset()
	digest.Write([]byte{0x03})
	digest.Write(uy.Bytes())
	digest.Write(innerHash)
	return digest.Sum(nil)
}

func CalculateKeyWithConfirmation(initiator bool, keyBits int, confirmationTag []byte,
	selfStaticPriv *PrivateKey, selfEphemeralPriv *PrivateKey, selfId []byte,
	otherStaticPub *PublicKey, otherEphemeralPub *PublicKey, otherId []byte) (*ExchangeResult, error) {
	if selfId == nil {
		selfId = make([]byte, 0)
	}
	if otherId == nil {
		otherId = make([]byte, 0)
	}
	if initiator && confirmationTag == nil {
		return nil, errors.New("if initiating, confirmationTag must be set")
	}

	selfStaticPub := CalculatePubKey(selfStaticPriv)
	digest := gm3.New()
	za := getZ(digest, &selfStaticPriv.Curve, selfStaticPub.X, selfStaticPub.Y, selfId)
	zb := getZ(digest, &selfStaticPriv.Curve, otherStaticPub.X, otherStaticPub.Y, otherId)

	w := selfStaticPriv.Curve.BitSize/2 - 1
	selfEphemeralPub := CalculatePubKey(selfEphemeralPriv)
	ux, uy := calculateU(w, selfStaticPriv, selfEphemeralPriv, selfEphemeralPub, otherStaticPub, otherEphemeralPub)
	if initiator {
		rv := kdfForExch(digest, ux, uy, za, zb, keyBits)
		innerHash := calculateInnerHash(digest, ux, za, zb, selfEphemeralPub.X, selfEphemeralPub.Y,
			otherEphemeralPub.X, otherEphemeralPub.Y)
		s1 := s1(digest, uy, innerHash)
		if !bytes.Equal(s1, confirmationTag) {
			return nil, errors.New("confirmation tag mismatch")
		}
		s2 := s2(digest, uy, innerHash)
		return &ExchangeResult{Key: rv, S2: s2}, nil
	} else {
		rv := kdfForExch(digest, ux, uy, zb, za, keyBits)
		innerHash := calculateInnerHash(digest, ux, zb, za, otherEphemeralPub.X, otherEphemeralPub.Y,
			selfEphemeralPub.X, selfEphemeralPub.Y)
		s1 := s1(digest, uy, innerHash)
		s2 := s2(digest, uy, innerHash)
		return &ExchangeResult{Key: rv, S1: s1, S2: s2}, nil
	}
}
