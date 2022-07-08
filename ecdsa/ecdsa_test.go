package ecdsa

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
	ss58PubKey := "KW39r9CJjAVzmkf9zQ4YDb2hqfAVGdRqn53eRqyruqpxAP5YL"
	addr := "5C7C2Z5sWbytvHpuLTvzKunnnRwQxft1jiqrLD5rhucQ5S9X"
	msg := fromHex(t, "0xDEADBEEF")
	sig := fromHex(t, "9f04ffd6c579e5460417c4b7a21441c39a0a0eb6a5c4a8cad288f538863950930f47c4014dbfc411f9486d432f55b875a0ff5c08ff15708120ae96b4a6e92b3800")

	network, pubkeyBytes, err := subkey.SS58Decode(ss58PubKey)
	assert.NoError(t, err)

	pubkey, err := Scheme{}.FromPublicKey(pubkeyBytes)
	assert.NoError(t, err)
	assert.Equal(t, pubkey.Public(), pubkeyBytes)
	assert.Equal(t, subkey.SS58Encode(pubkey.Public(), network), ss58PubKey)
	assert.Equal(t, pubkey.SS58Address(network), addr)

	assert.True(t, pubkey.Verify(msg, sig))
}

func TestVerifyBad(t *testing.T) {
	ss58PubKey := "KW39r9CJjAVzmkf9zQ4YDb2hqfAVGdRqn53eRqyruqpxAP5YL"
	badSs58PubKey := "KWByAN7WfZABWS5AoWqxriRmF5f2jnDqy3rB5pfHLGkY93ibN"
	msg := fromHex(t, "0xDEADBEEF")
	badMsg := fromHex(t, "0xBADDBEEF")
	sig := fromHex(t, "9f04ffd6c579e5460417c4b7a21441c39a0a0eb6a5c4a8cad288f538863950930f47c4014dbfc411f9486d432f55b875a0ff5c08ff15708120ae96b4a6e92b3800")
	badSig := fromHex(t, "0f04ffd6c579e5460417c4b7a21441c39a0a0eb6a5c4a8cad288f538863950930f47c4014dbfc411f9486d432f55b875a0ff5c08ff15708120ae96b4a6e92b3800")

	_, pubkeyBytes, err := subkey.SS58Decode(ss58PubKey)
	assert.NoError(t, err)
	pubkey, err := Scheme{}.FromPublicKey(pubkeyBytes)
	assert.NoError(t, err)
	assert.True(t, pubkey.Verify(msg, sig))
	assert.False(t, pubkey.Verify(badMsg, sig))
	assert.False(t, pubkey.Verify(msg, badSig))
	assert.False(t, pubkey.Verify(badMsg, badSig))

	_, badPubkeyBytes, err := subkey.SS58Decode(badSs58PubKey)
	assert.NoError(t, err)
	badPubkey, err := Scheme{}.FromPublicKey(badPubkeyBytes)
	assert.NoError(t, err)
	assert.False(t, badPubkey.Verify(msg, sig))
}
