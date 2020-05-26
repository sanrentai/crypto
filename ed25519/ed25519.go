package ed25519

import (
	"crypto/ed25519"
	"encoding/pem"
	"os"
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
		Type:  "ED25519 PRIVATE KEY",
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
		Type:  "PUBLIC KEY",
		Bytes: pub,
	}

	if err = pem.Encode(pubfile, &pubblock); err != nil {
		return err
	}

	return nil
}
