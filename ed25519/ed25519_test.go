package ed25519

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vedhavyas/go-subkey"
)

func fromHex(t *testing.T, hex string) []byte {
	bytes, success := subkey.DecodeHex(hex)
	assert.True(t, success)
	return bytes
}

func TestFromPublicKeyVerifyGood(t *testing.T) {
	addr := "5FA9nQDVg267DEd8m1ZypXLBnvN7SFxYwV7ndqSYGiN9TTpu"
	msg := fromHex(t, "0xDEADBEEF")
	sig := fromHex(t, "52fdcf101e08376f7e0a837f656eefa0c8f40cfa8b3e97bec598ec70f019edd29c2572b417cb9dc351cbc68a4586e1f968d8198118e4b656d0b1ce8d73106404")

	network, pubkeyBytes, err := subkey.SS58Decode(addr)
	assert.NoError(t, err)
	pubkey, err := Scheme{}.FromPublicKey(pubkeyBytes)
	assert.NoError(t, err)
	assert.Equal(t, pubkey.SS58Address(network), addr)
	assert.True(t, pubkey.Verify(msg, sig))
}

func TestVerifyBad(t *testing.T) {
	addr := "5FA9nQDVg267DEd8m1ZypXLBnvN7SFxYwV7ndqSYGiN9TTpu"
	badAddr := "5GoNkf6WdbxCFnPdAnYYQyCjAKPJgLNxXwPjwTh6DGg6gN3E"
	msg := fromHex(t, "0xDEADBEEF")
	badMsg := fromHex(t, "0xBADDBEEF")
	sig := fromHex(t, "52fdcf101e08376f7e0a837f656eefa0c8f40cfa8b3e97bec598ec70f019edd29c2572b417cb9dc351cbc68a4586e1f968d8198118e4b656d0b1ce8d73106404")
	badSig := fromHex(t, "02fdcf101e08376f7e0a837f656eefa0c8f40cfa8b3e97bec598ec70f019edd29c2572b417cb9dc351cbc68a4586e1f968d8198118e4b656d0b1ce8d73106404")

	_, pubkeyBytes, err := subkey.SS58Decode(addr)
	assert.NoError(t, err)
	pubkey, err := Scheme{}.FromPublicKey(pubkeyBytes)
	assert.NoError(t, err)
	assert.True(t, pubkey.Verify(msg, sig))
	assert.False(t, pubkey.Verify(badMsg, sig))
	assert.False(t, pubkey.Verify(msg, badSig))
	assert.False(t, pubkey.Verify(badMsg, badSig))

	_, badPubkeyBytes, err := subkey.SS58Decode(badAddr)
	assert.NoError(t, err)
	badPubkey, err := Scheme{}.FromPublicKey(badPubkeyBytes)
	assert.NoError(t, err)
	assert.False(t, badPubkey.Verify(msg, sig))
}
