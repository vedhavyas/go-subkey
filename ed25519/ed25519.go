package ed25519

import (
	"bytes"
	"crypto"
	"errors"

	"github.com/ChainSafe/go-schnorrkel"
	"github.com/vedhavyas/go-subkey/common"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"
)

// keyRing is a wrapper around sr25519 secret and public
type keyRing struct {
	secret *ed25519.PrivateKey
	pub    *ed25519.PublicKey
}

// Sign signs the message using sr25519 curve
func (kr keyRing) Sign(msg []byte) (signature []byte, err error) {
	return kr.secret.Sign(nil, msg, crypto.Hash(0))
}

// Verify verifies the signature.
func (kr keyRing) Verify(msg []byte, signature []byte) bool {
	return ed25519.Verify(*kr.pub, msg, signature)
}

// Public returns the public key in bytes
func (kr keyRing) Public() []byte {
	return *kr.pub
}

// SS58Address returns the SS58Address using the known network format
func (kr keyRing) SS58Address(network common.Network, ctype common.ChecksumType) (string, error) {
	return common.SS58AddressWithVersion(*kr.pub, uint8(network), ctype)
}

type Scheme struct{}

func (s Scheme) FromSeed(seed []byte) (common.KeyPair, error) {
	secret := ed25519.NewKeyFromSeed(seed)
	pub := secret.Public().(ed25519.PublicKey)
	return keyRing{
		secret: &secret,
		pub:    &pub,
	}, nil
}

func (s Scheme) FromPhrase(phrase, pwd string) (common.KeyPair, error) {
	seed, err := schnorrkel.SeedFromMnemonic(phrase, pwd)
	if err != nil {
		return nil, err
	}

	return s.FromSeed(seed[:32])
}

func (s Scheme) Derive(pair common.KeyPair, djs []common.DeriveJunction) (common.KeyPair, error) {
	acc := pair.(keyRing).secret.Seed()
	var err error
	for _, dj := range djs {
		if !dj.IsHard {
			return nil, errors.New("soft derivation is not supported")
		}

		acc, err = deriveKeyHard(acc, dj.ChainCode)
		if err != nil {
			return nil, err
		}
	}

	return s.FromSeed(acc)
}

func deriveKeyHard(secret []byte, cc [32]byte) ([]byte, error) {
	var buffer bytes.Buffer
	d := common.NewEncoder(&buffer)
	err := d.Encode("Ed25519HDKD")
	if err != nil {
		return nil, err
	}

	var s [32]byte
	copy(s[:], secret)
	for _, i := range [][32]byte{s, cc} {
		err := d.Encode(i)
		if err != nil {
			return nil, err
		}
	}

	seed := blake2b.Sum256(buffer.Bytes())
	return seed[:], nil
}
