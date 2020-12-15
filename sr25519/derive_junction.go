package sr25519

import (
	sr25519 "github.com/ChainSafe/go-schnorrkel"
	"github.com/gtank/merlin"
)

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
