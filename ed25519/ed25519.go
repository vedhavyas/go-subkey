package ed25519

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"

	"github.com/ChainSafe/go-schnorrkel"
	"github.com/vedhavyas/go-subkey"
	"github.com/vedhavyas/go-subkey/scale"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"
)

type pubKey struct {
	key *ed25519.PublicKey
}

func (pub pubKey) Verify(msg []byte, signature []byte) bool {
	return ed25519.Verify(*pub.key, msg, signature)
}

func (pub pubKey) Public() []byte {
	return *pub.key
}

func (pub pubKey) AccountID() []byte {
	return pub.Public()
}

func (pub pubKey) SS58Address(network uint16) string {
	return subkey.SS58Encode(pub.AccountID(), network)
}

type keyRing struct {
	secret *ed25519.PrivateKey
	pub    pubKey
}

func (kr keyRing) Sign(msg []byte) (signature []byte, err error) {
	return kr.secret.Sign(nil, msg, crypto.Hash(0))
}

func (kr keyRing) Verify(msg []byte, signature []byte) bool {
	return kr.pub.Verify(msg, signature)
}

func (kr keyRing) Public() []byte {
	return kr.pub.Public()
}

func (kr keyRing) Seed() []byte {
	return kr.secret.Seed()
}

func (kr keyRing) AccountID() []byte {
	return kr.pub.AccountID()
}

func (kr keyRing) SS58Address(network uint16) string {
	return kr.pub.SS58Address(network)
}

type Scheme struct{}

func (s Scheme) String() string {
	return "Ed25519"
}

func (s Scheme) Generate() (subkey.KeyPair, error) {
	pub, secret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return keyRing{
		secret: &secret,
		pub:    pubKey{key: &pub},
	}, nil
}

func (s Scheme) FromSeed(seed []byte) (subkey.KeyPair, error) {
	secret := ed25519.NewKeyFromSeed(seed)
	pub := secret.Public().(ed25519.PublicKey)
	return keyRing{
		secret: &secret,
		pub:    pubKey{key: &pub},
	}, nil
}

func (s Scheme) FromPhrase(phrase, pwd string) (subkey.KeyPair, error) {
	seed, err := schnorrkel.SeedFromMnemonic(phrase, pwd)
	if err != nil {
		return nil, err
	}

	return s.FromSeed(seed[:32])
}

func (s Scheme) Derive(pair subkey.KeyPair, djs []subkey.DeriveJunction) (subkey.KeyPair, error) {
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
	d := scale.NewEncoder(&buffer)
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

func (s Scheme) FromPublicKey(bytes []byte) (subkey.PublicKey, error) {
	key := ed25519.PublicKey(bytes)
	return pubKey{key: &key}, nil
}
