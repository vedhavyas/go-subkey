package subkey

import (
	sr25519 "github.com/ChainSafe/go-schnorrkel"
	"github.com/gtank/merlin"
)

// Sign signs the given message with sr25519 secret.
func Sign(secret [32]byte, msg []byte) (sig [64]byte, err error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return sig, err
	}

	s, err := key.Sign(signingContext(msg))
	if err != nil {
		return sig, err
	}

	return s.Encode(), nil
}

// Verify verifies the signature with sr25519 secret.
func Verify(secret [32]byte, sig [64]byte, msg []byte) bool {
	key, err := decodeSecret(secret)
	if err != nil {
		return false
	}

	pub, err := key.Public()
	if err != nil {
		return false
	}

	s := new(sr25519.Signature)
	if err := s.Decode(sig); err != nil {
		return false
	}

	return pub.Verify(s, signingContext(msg))
}

func decodeSecret(secret [32]byte) (*sr25519.SecretKey, error) {
	key := new(sr25519.SecretKey)
	err := key.Decode(secret)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func signingContext(msg []byte) *merlin.Transcript {
	return sr25519.NewSigningContext([]byte("substrate"), msg)
}
