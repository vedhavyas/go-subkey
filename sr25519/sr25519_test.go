package sr25519

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vedhavyas/go-subkey/v2"
)

func fromHex(t *testing.T, hex string) []byte {
	bytes, success := subkey.DecodeHex(hex)
	assert.True(t, success)
	return bytes
}

func TestFromPublicKeyVerifyGood(t *testing.T) {
	addr := "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
	msg := fromHex(t, "0xDEADBEEF")
	sig := fromHex(t, "dc7cf771e1989a5c3cddca30ec5efaeff9a5c14a36c3c032510019e7144e0375f9207ef6745390ca3dc76b307b26f60125c942e2b7fb23100cc79402a12dde8b")

	network, pubkeyBytes, err := subkey.SS58Decode(addr)
	assert.NoError(t, err)
	pubkey, err := Scheme{}.FromPublicKey(pubkeyBytes)
	assert.NoError(t, err)
	assert.Equal(t, pubkey.SS58Address(network), addr)
	assert.True(t, pubkey.Verify(msg, sig))
}

func TestVerifyBad(t *testing.T) {
	addr := "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
	badAddr := "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
	msg := fromHex(t, "0xDEADBEEF")
	badMsg := fromHex(t, "0xBADDBEEF")
	sig := fromHex(t, "dc7cf771e1989a5c3cddca30ec5efaeff9a5c14a36c3c032510019e7144e0375f9207ef6745390ca3dc76b307b26f60125c942e2b7fb23100cc79402a12dde8b")
	badSig := fromHex(t, "0c7cf771e1989a5c3cddca30ec5efaeff9a5c14a36c3c032510019e7144e0375f9207ef6745390ca3dc76b307b26f60125c942e2b7fb23100cc79402a12dde8b")

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
