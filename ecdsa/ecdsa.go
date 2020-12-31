package ecdsa

import (
	"bytes"
	"crypto/ecdsa"
	"errors"

	"github.com/ChainSafe/go-schnorrkel"
	secp256k1 "github.com/ethereum/go-ethereum/crypto"
	"github.com/vedhavyas/go-subkey"
	"github.com/vedhavyas/go-subkey/scale"
	"golang.org/x/crypto/blake2b"
)

type keyRing struct {
	secret *ecdsa.PrivateKey
	pub    *ecdsa.PublicKey
}

func (kr keyRing) Sign(msg []byte) (signature []byte, err error) {
	digest := blake2b.Sum256(msg)
	return secp256k1.Sign(digest[:], kr.secret)
}

func (kr keyRing) Verify(msg []byte, signature []byte) bool {
	digest := blake2b.Sum256(msg)
	signature = signature[:64]
	return secp256k1.VerifySignature(kr.Public(), digest[:], signature)
}

func (kr keyRing) Seed() []byte {
	return secp256k1.FromECDSA(kr.secret)
}

func (kr keyRing) Public() []byte {
	return secp256k1.CompressPubkey(kr.pub)
}

func (kr keyRing) AccountID() []byte {
	account := blake2b.Sum256(kr.Public())
	return account[:]
}

func (kr keyRing) SS58Address(network uint8) (string, error) {
	return subkey.SS58Address(kr.AccountID(), network)
}

func (kr keyRing) SS58AddressWithAccountIDChecksum(network uint8) (string, error) {
	return subkey.SS58AddressWithAccountIDChecksum(kr.AccountID(), network)
}

type Scheme struct{}

func (s Scheme) String() string {
	return "Ecdsa"
}

func (s Scheme) Generate() (subkey.KeyPair, error) {
	secret, err := secp256k1.GenerateKey()
	if err != nil {
		return nil, err
	}

	return keyRing{
		secret: secret,
		pub:    secret.Public().(*ecdsa.PublicKey),
	}, nil
}

func (s Scheme) FromSeed(seed []byte) (subkey.KeyPair, error) {
	secret := secp256k1.ToECDSAUnsafe(seed)
	pub := secret.Public().(*ecdsa.PublicKey)
	return keyRing{
		secret: secret,
		pub:    pub,
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
	acc := secp256k1.FromECDSA(pair.(keyRing).secret)
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
	err := d.Encode("Secp256k1HDKD")
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
