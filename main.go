package main

import (
	"github.com/sanrentai/crypto/ed25519"
)

func main() {
	if err := ed25519.GenerateKeyFile("pri.key", "pub.key"); err != nil {
		panic(err)
	}

	if err := ed25519.GenerateKeyPemFile("pri.pem", "pub.pem"); err != nil {
		panic(err)
	}

}
