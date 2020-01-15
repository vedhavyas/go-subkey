package subkey

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"

	sr25519 "github.com/ChainSafe/go-schnorrkel"
	"github.com/btcsuite/btcutil/base58"
	"github.com/gtank/merlin"
	"golang.org/x/crypto/blake2b"
)

const (
	DevPhrase           = "bottom drive obey lake curtain smoke basket hold race lonely fit walk"
	DevAddress          = "5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV"
	MiniSecretKeyLength = 32
	SecretKeyLength     = 64
	JunctionIdLen       = 32
)

var re = regexp.MustCompile(`^(?P<phrase>[\d\w ]+)?(?P<path>(//?[^/]+)*)(///(?P<password>.*))?$`)

var reJunction = regexp.MustCompile(`/(/?[^/]+)`)

type DeriveJunction struct {
	path      string
	chainCode [32]byte
	isHard    bool
}

func KeyRingFromURI(suri string) (*sr25519.SecretKey, error) {
	phrase, path, pwd, err := splitSURI(suri)
	if err != nil {
		return nil, err
	}

	secret, err := deriveSecret(phrase, pwd)
	if err != nil {
		return nil, err
	}

	djs, err := deriveJunctions(derivePath(path))
	if err != nil {
		return nil, err
	}

	for _, dj := range djs {
		if dj.isHard {
			ms, err := deriveKeyHard(secret, dj.chainCode)
			if err != nil {
				return nil, err
			}

			secret = ms.ExpandEd25519()
			continue
		}

		secret, err = deriveKeySoft(secret, dj.chainCode)
		if err != nil {
			return nil, err
		}
	}

	return secret, nil
}

func deriveSecret(phrase, pwd string) (secret *sr25519.SecretKey, err error) {
	if b, ok := decodeHex(phrase); ok {
		switch len(b) {
		case MiniSecretKeyLength:
			var mss [32]byte
			copy(mss[:], b)
			ms, err := sr25519.NewMiniSecretKeyFromRaw(mss)
			if err != nil {
				return nil, err
			}

			secret = ms.ExpandEd25519()

		case SecretKeyLength:
			var key, nonce [32]byte
			copy(key[:], b[0:32])
			copy(nonce[:], b[32:64])
			secret = sr25519.NewSecretKey(key, nonce)
		}
	} else {
		ms, err := sr25519.MiniSecretFromMnemonic(phrase, pwd)
		if err != nil {
			return nil, err
		}

		secret = ms.ExpandEd25519()
	}

	return secret, nil
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
	//cb := t.ExtractBytes([]byte("HDKD-chaincode"), MiniSecretKeyLength)
	//ncc := [MiniSecretKeyLength]byte{}
	//copy(ncc[:], cb)
	return sr25519.NewMiniSecretKeyFromRaw(msk)
}

func splitSURI(suri string) (phrase string, pathMap string, password string, err error) {
	if strings.HasPrefix(suri, "//") {
		suri = DevPhrase + suri
	}

	res := re.FindStringSubmatch(suri)
	if res == nil {
		return phrase, pathMap, password, errors.New("invalid URI format")
	}

	return res[1], res[2], res[5], nil
}

func derivePath(path string) (parts []string) {
	res := reJunction.FindAllStringSubmatch(path, -1)
	for _, p := range res {
		parts = append(parts, p[1])
	}
	return parts
}

func decodeHex(uri string) (seed []byte, ok bool) {
	if !strings.HasPrefix(uri, "0x") {
		return nil, false
	}
	uri = strings.TrimPrefix(uri, "0x")
	res, err := hex.DecodeString(uri)
	return res, err == nil
}

func deriveJunctions(codes []string) (djs []*DeriveJunction, err error) {
	for _, code := range codes {
		dj, err := deriveJunction(code)
		if err != nil {
			return nil, err
		}

		djs = append(djs, dj)
	}

	return djs, nil
}

func deriveJunction(code string) (*DeriveJunction, error) {
	var jd DeriveJunction
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

	if len(bc) > JunctionIdLen {
		b := blake2b.Sum256(bc)
		bc = b[:]
	}

	copy(jd.chainCode[:len(bc)], bc)
	jd.path = code
	return &jd, nil
}

const ss58Prefix = "SS58PRE"

func SS58AddressFromVersion(pub *sr25519.PublicKey, network uint8) string {
	addr := pub.Encode()
	cs, err := ss58Checksum(append([]byte{network}, addr[:]...))
	if err != nil {
		return ""
	}

	fb := append([]byte{network}, addr[:]...)
	fb = append(fb, cs[0:2]...)
	return base58.Encode(fb)
}

func ss58Checksum(data []byte) ([]byte, error) {
	hasher, err := blake2b.New(64, nil)
	if err != nil {
		return nil, err
	}

	_, err = hasher.Write([]byte(ss58Prefix))
	if err != nil {
		return nil, err
	}

	_, err = hasher.Write(data)
	if err != nil {
		return nil, err
	}

	return hasher.Sum(nil), nil
}
