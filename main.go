package main

import (
	"fmt"

	"github.com/sanrentai/crypto/ed25519"
)

func main() {
	err := ed25519.GenerateKeyFile("pri.key", "pub.key")
	if err != nil {
		fmt.Println(err)
	}

}
