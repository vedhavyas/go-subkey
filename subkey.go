package subkey

import (
	"fmt"

	"github.com/vedhavyas/go-subkey/common"
)

// Scheme represents a cryptography scheme.
type Scheme interface {
	fmt.Stringer
	Generate() (common.KeyPair, error)
	FromSeed(seed []byte) (common.KeyPair, error)
	FromPhrase(phrase, password string) (common.KeyPair, error)
	Derive(pair common.KeyPair, djs []common.DeriveJunction) (common.KeyPair, error)
}

// Derive derives the Keypair from the URI using the provided cryptography scheme.
func Derive(scheme Scheme, uri string) (kp common.KeyPair, err error) {
	phrase, path, pwd, err := common.SplitURI(uri)
	if err != nil {
		return nil, err
	}

	if b, ok := common.DecodeHex(phrase); ok {
		kp, err = scheme.FromSeed(b)
	} else {
		kp, err = scheme.FromPhrase(phrase, pwd)
	}
	if err != nil {
		return nil, err
	}

	djs, err := common.DeriveJunctions(common.DerivePath(path))
	if err != nil {
		return nil, err
	}

	return scheme.Derive(kp, djs)
}
