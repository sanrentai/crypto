package ed25519

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
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

func GenerateKeyPemFile(privateKeyFile, publickKeyFile string) error {

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
