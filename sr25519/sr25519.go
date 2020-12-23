package sr25519

import (
	"errors"

	sr25519 "github.com/ChainSafe/go-schnorrkel"
	"github.com/gtank/merlin"
	"github.com/vedhavyas/go-subkey/common"
)

const (
	// MiniSecretKeyLength is the length of the MiniSecret Key
	MiniSecretKeyLength = 32

	// SecretKeyLength is the length of the SecretKey
	SecretKeyLength = 64

	SignatureLength = 64
)

// keyRing is a wrapper around sr25519 secret and public
type keyRing struct {
	secret *sr25519.SecretKey
	pub    *sr25519.PublicKey
}

// Sign signs the message using sr25519 curve
func (kr keyRing) Sign(msg []byte) (signature []byte, err error) {
	sig, err := kr.secret.Sign(signingContext(msg))
	if err != nil {
		return signature, err
	}

	s := sig.Encode()
	return s[:], nil
}

// Verify verifies the signature.
func (kr keyRing) Verify(msg []byte, signature []byte) bool {
	var sigs [SignatureLength]byte
	copy(sigs[:], signature)
	sig := new(sr25519.Signature)
	if err := sig.Decode(sigs); err != nil {
		return false
	}
	return kr.pub.Verify(sig, signingContext(msg))
}

func signingContext(msg []byte) *merlin.Transcript {
	return sr25519.NewSigningContext([]byte("substrate"), msg)
}

// Public returns the public key in bytes
func (kr keyRing) Public() []byte {
	pub := kr.pub.Encode()
	return pub[:]
}

// SS58Address returns the SS58Address using the known network format
func (kr keyRing) SS58Address(network common.Network, ctype common.ChecksumType) (string, error) {
	pub := kr.pub.Encode()
	return common.SS58AddressWithVersion(pub[:], uint8(network), ctype)
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

type Scheme struct{}

func (s Scheme) FromSeed(seed []byte) (common.KeyPair, error) {
	switch len(seed) {
	case MiniSecretKeyLength:
		var mss [32]byte
		copy(mss[:], seed)
		ms, err := sr25519.NewMiniSecretKeyFromRaw(mss)
		if err != nil {
			return nil, err
		}

		return keyRing{
			secret: ms.ExpandEd25519(),
			pub:    ms.Public(),
		}, nil

	case SecretKeyLength:
		var key, nonce [32]byte
		copy(key[:], seed[0:32])
		copy(nonce[:], seed[32:64])
		secret := sr25519.NewSecretKey(key, nonce)
		pub, err := secret.Public()
		if err != nil {
			return nil, err
		}

		return keyRing{
			secret: secret,
			pub:    pub,
		}, nil
	}

	return nil, errors.New("invalid seed length")
}

func (s Scheme) FromPhrase(phrase, pwd string) (common.KeyPair, error) {
	ms, err := sr25519.MiniSecretFromMnemonic(phrase, pwd)
	if err != nil {
		return nil, err
	}

	secret := ms.ExpandEd25519()
	pub, err := secret.Public()
	if err != nil {
		return nil, err
	}

	return keyRing{
		secret: secret,
		pub:    pub,
	}, nil
}

func (s Scheme) Derive(pair common.KeyPair, djs []common.DeriveJunction) (common.KeyPair, error) {
	kr := pair.(keyRing)
	secret := kr.secret
	var err error
	for _, dj := range djs {
		if dj.IsHard {
			ms, err := deriveKeyHard(secret, dj.ChainCode)
			if err != nil {
				return nil, err
			}

			secret = ms.ExpandEd25519()
			continue
		}

		secret, err = deriveKeySoft(secret, dj.ChainCode)
		if err != nil {
			return nil, err
		}
	}

	pub, err := secret.Public()
	if err != nil {
		return nil, err
	}

	return &keyRing{secret: secret, pub: pub}, nil
}
