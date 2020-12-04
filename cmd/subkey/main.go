package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/vedhavyas/go-subkey/sr25519"
)

func main() {
	s := flag.String("secret", "", "Secret key in Hex")
	m := flag.String("msg", "", "Message to be signed in Hex")
	flag.Parse()

	msg, err := decodeHex(*m)
	if err != nil {
		panic(err)
	}

	kr, err := sr25519.KeyRingFromURI(*s)
	if err != nil {
		panic(err)
	}

	sig, err := kr.Sign(msg)
	if err != nil {
		panic(err)
	}

	fmt.Println(kr.Verify(msg, sig))
}

func decodeHex(data string) ([]byte, error) {
	data = strings.TrimPrefix(strings.TrimSpace(data), "0x")
	if data == "" {
		return nil, errors.New("empty string")
	}
	return hex.DecodeString(data)
}
