package subkey

import (
	"fmt"

	"github.com/vedhavyas/go-subkey/common"
)

type Scheme interface {
	fmt.Stringer
	FromSeed(seed []byte) (common.KeyPair, error)
	FromPhrase(phrase, password string) (common.KeyPair, error)
	Derive(pair common.KeyPair, djs []common.DeriveJunction) (common.KeyPair, error)
}

func Derive(scheme Scheme, uri string) (common.KeyPair, error) {
	phrase, path, pwd, err := common.SplitURI(uri)
	if err != nil {
		return nil, err
	}

	var kp common.KeyPair
	if b, ok := common.DecodeHex(phrase); ok {
		kp, err = scheme.FromSeed(b)
	} else {
		kp, err = scheme.FromPhrase(phrase, pwd)
	}

	djs, err := common.DeriveJunctions(common.DerivePath(path))
	if err != nil {
		return nil, err
	}

	return scheme.Derive(kp, djs)
}
