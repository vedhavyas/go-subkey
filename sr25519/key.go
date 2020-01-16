package sr25519

import (
	"errors"
	"regexp"

	sr25519 "github.com/ChainSafe/go-schnorrkel"
	"github.com/gtank/merlin"
	"github.com/vedhavyas/go-subkey/common"
)

const (
	// DevPhrase is default phrase used for dev test accounts
	DevPhrase = "bottom drive obey lake curtain smoke basket hold race lonely fit walk"

	// MiniSecretKeyLength is the length of the MiniSecret Key
	MiniSecretKeyLength = 32

	// SecretKeyLength is the length of the SecretKey
	SecretKeyLength = 64
)

var (
	re = regexp.MustCompile(`^(?P<phrase>[\d\w ]+)?(?P<path>(//?[^/]+)*)(///(?P<password>.*))?$`)

	reJunction = regexp.MustCompile(`/(/?[^/]+)`)
)

// KeyRing is a wrapper around sr25519 secret and public
type KeyRing struct {
	secret sr25519.SecretKey
	pub    sr25519.PublicKey
}

// Sign signs the message using sr25519 curve
func (kr *KeyRing) Sign(msg []byte) (signature [64]byte, err error) {
	sig, err := kr.secret.Sign(signingContext(msg))
	if err != nil {
		return signature, err
	}
	return sig.Encode(), nil
}

// Verify verifies the signature.
func (kr *KeyRing) Verify(msg []byte, signature [64]byte) bool {
	sig := new(sr25519.Signature)
	if err := sig.Decode(signature); err != nil {
		return false
	}
	return kr.pub.Verify(sig, signingContext(msg))
}

func signingContext(msg []byte) *merlin.Transcript {
	return sr25519.NewSigningContext([]byte("substrate"), msg)
}

// Public returns the public key in bytes
func (kr *KeyRing) Public() [32]byte {
	return kr.pub.Encode()
}

// Secret returns the secret in bytes.
func (kr *KeyRing) Secret() [32]byte {
	return kr.secret.Encode()
}

// SS58Address returns the SS58Address using the known network format
func (kr *KeyRing) SS58Address(network string, ctype common.ChecksumType) (string, error) {
	return common.SS58Address(kr.pub.Encode(), network, ctype)
}

// SS58AddressFromVersion returns the SS58Address using the version
func (kr *KeyRing) SS58AddressFromVersion(version uint8, ctype common.ChecksumType) (string, error) {
	return common.SS58AddressWithVersion(kr.pub.Encode(), version, ctype)
}

// KeyRingFromURI returns the keypair derived from thee suri.
func KeyRingFromURI(suri string) (*KeyRing, error) {
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

	pub, err := secret.Public()
	if err != nil {
		return nil, err
	}

	return &KeyRing{secret: *secret, pub: *pub}, nil
}

func deriveSecret(phrase, pwd string) (secret *sr25519.SecretKey, err error) {
	if b, ok := common.DecodeHex(phrase); ok {
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

func splitSURI(suri string) (phrase string, pathMap string, password string, err error) {
	res := re.FindStringSubmatch(suri)
	if res == nil {
		return phrase, pathMap, password, errors.New("invalid URI format")
	}

	phrase = res[1]
	if phrase == "" {
		phrase = DevPhrase
	}

	return phrase, res[2], res[5], nil
}

func derivePath(path string) (parts []string) {
	res := reJunction.FindAllStringSubmatch(path, -1)
	for _, p := range res {
		parts = append(parts, p[1])
	}
	return parts
}
