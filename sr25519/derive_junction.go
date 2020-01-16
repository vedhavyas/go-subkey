package sr25519

import (
	"encoding/binary"
	"strconv"
	"strings"

	sr25519 "github.com/ChainSafe/go-schnorrkel"
	"github.com/gtank/merlin"
	"golang.org/x/crypto/blake2b"
)

const junctionIDLen = 32

type deriveJunction struct {
	path      string
	chainCode [32]byte
	isHard    bool
}

func deriveKeySoft(secret *sr25519.SecretKey, cc [32]byte) (*sr25519.SecretKey, error) {
	t := merlin.NewTranscript("SchnorrRistrettoHDKD")
	t.AppendMessage([]byte("sign-bytes"), nil)
	ek, err := secret.DeriveKey(t, cc)
	if err != nil {
		return nil, err
	}
	return ek.Secret()
}

func deriveKeyHard(secret *sr25519.SecretKey, cc [32]byte) (*sr25519.MiniSecretKey, error) {
	t := merlin.NewTranscript("SchnorrRistrettoHDKD")
	t.AppendMessage([]byte("sign-bytes"), nil)
	t.AppendMessage([]byte("chain-code"), cc[:])
	s := secret.Encode()
	t.AppendMessage([]byte("secret-key"), s[:])
	mskb := t.ExtractBytes([]byte("HDKD-hard"), MiniSecretKeyLength)
	msk := [MiniSecretKeyLength]byte{}
	copy(msk[:], mskb)
	return sr25519.NewMiniSecretKeyFromRaw(msk)
}

func deriveJunctions(codes []string) (djs []*deriveJunction, err error) {
	for _, code := range codes {
		dj, err := parseDeriveJunction(code)
		if err != nil {
			return nil, err
		}

		djs = append(djs, dj)
	}

	return djs, nil
}

func parseDeriveJunction(code string) (*deriveJunction, error) {
	var jd deriveJunction
	if strings.HasPrefix(code, "/") {
		jd.isHard = true
		code = strings.TrimPrefix(code, "/")
	}

	var bc []byte
	u64, err := strconv.ParseUint(code, 10, 0)
	if err == nil {
		bc = make([]byte, 8, 8)
		binary.LittleEndian.PutUint64(bc, u64)
	} else {
		cl, err := compactUint(uint64(len(code)))
		if err != nil {
			return nil, err
		}

		bc = append(cl, code...)
	}

	if len(bc) > junctionIDLen {
		b := blake2b.Sum256(bc)
		bc = b[:]
	}

	copy(jd.chainCode[:len(bc)], bc)
	jd.path = code
	return &jd, nil
}
