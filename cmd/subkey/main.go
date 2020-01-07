package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/vedhavyas/go-subkey"
)

func main() {
	s := flag.String("secret", "", "Secret key in Hex")
	m := flag.String("msg", "", "Message to be signed in Hex")
	flag.Parse()

	secb, err := decodeHex(*s)
	if err != nil {
		panic(err)
	}
	var secret [32]byte
	copy(secret[:], secb)

	msg, err := decodeHex(*m)
	if err != nil {
		panic(err)
	}

	sig, err := subkey.Sign(secret, msg)
	if err != nil {
		panic(err)
	}

	fmt.Println(subkey.Verify(secret, sig, msg))
}

func decodeHex(data string) ([]byte, error) {
	data = strings.TrimPrefix(strings.TrimSpace(data), "0x")
	if data == "" {
		return nil, errors.New("empty string")
	}
	return hex.DecodeString(data)
}
