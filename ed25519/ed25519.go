package ed25519

import (
	"crypto/ed25519"
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
