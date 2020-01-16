package common

import (
	"encoding/hex"
	"strings"
)

// DecodeHex decodes the hex string to bytes.
// `0x` prefix is accepted.
func DecodeHex(uri string) (seed []byte, ok bool) {
	if strings.HasPrefix(uri, "0x") {
		uri = strings.TrimPrefix(uri, "0x")
	}
	res, err := hex.DecodeString(uri)
	return res, err == nil
}
