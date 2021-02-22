package main

import (
	"fmt"

	"github.com/sanrentai/crypto/ed25519"
)

func main() {
	// if err := ed25519.GenerateKeyFile("pri.key", "pub.key"); err != nil {
	// 	panic(err)
	// }

	// if err := ed25519.GenerateKeyPemFile("pri.pem", "pub.pem"); err != nil {
	// 	panic(err)
	// }

	pri, err := ed25519.PrivateKeyFromPem("pri.key")
	if err != nil {
		panic(err)
	}
	message := []byte("hello world")
	sig := ed25519.Sign(pri, message)
	v, err := ed25519.VerifyFile("pub.key", message, sig)
	if err != nil {
		panic(err)
	}
	fmt.Println(v)
}
