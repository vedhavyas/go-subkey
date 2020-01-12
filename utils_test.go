package subkey

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_splitURI(t *testing.T) {
	tests := []struct {
		suri, phrase, path, password string
		err                          bool
	}{
		{
			suri:     "bottom drive obey lake curtain smoke basket hold race lonely fit walk///password",
			phrase:   "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
			path:     "",
			password: "password",
		},
		{
			suri:     "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
			phrase:   "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
			path:     "",
			password: "",
		},
		{
			suri:     "bottom drive obey lake curtain smoke basket hold race lonely fit walk/foo",
			phrase:   "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
			path:     "/foo",
			password: "",
		},
		{
			suri:     "bottom drive obey lake curtain smoke basket hold race lonely fit walk//foo",
			phrase:   "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
			path:     "//foo",
			password: "",
		},
		{
			suri:     "bottom drive obey lake curtain smoke basket hold race lonely fit walk//foo/bar",
			phrase:   "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
			path:     "//foo/bar",
			password: "",
		},
		{
			suri:     "bottom drive obey lake curtain smoke basket hold race lonely fit walk/foo//bar",
			phrase:   "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
			path:     "/foo//bar",
			password: "",
		},
		{
			suri:     "bottom drive obey lake curtain smoke basket hold race lonely fit walk//foo/bar//42/69",
			phrase:   "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
			path:     "//foo/bar//42/69",
			password: "",
		},
		{
			suri:     "bottom drive obey lake curtain smoke basket hold race lonely fit walk//foo/bar//42/69///password",
			phrase:   "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
			path:     "//foo/bar//42/69",
			password: "password",
		},
	}

	for _, c := range tests {
		phrase, path, password, err := splitSURI(c.suri)
		if err != nil {
			assert.True(t, c.err)
			continue
		}

		assert.Equal(t, c.phrase, phrase)
		assert.Equal(t, c.path, path)
		assert.Equal(t, c.password, password)
	}
}

func TestKeyRingFromURI(t *testing.T) {
	tests := []struct {
		suri      string
		publicKey string
		err       bool
	}{
		{
			suri:      "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
			publicKey: "0x46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a",
		},

		{
			suri:      "bottom drive obey lake curtain smoke basket hold race lonely fit walk///password",
			publicKey: "0xb69355deefa7a8f33e9297f5af22e680f03597a99d4f4b1c44be47e7a2275802",
		},

		{
			suri:      "bottom drive obey lake curtain smoke basket hold race lonely fit walk/foo",
			publicKey: "0x40b9675df90efa6069ff623b0fdfcf706cd47ca7452a5056c7ad58194d23440a",
		},

		{
			suri:      "bottom drive obey lake curtain smoke basket hold race lonely fit walk//foo",
			publicKey: "0x547d4a55642ec7ebadc0bd29b6e570b8c926059b3c0655d4948075e9a7e6f31e",
		},

		{
			suri:      "bottom drive obey lake curtain smoke basket hold race lonely fit walk//foo/bar",
			publicKey: "0x3841947ffcde6f5fef26fb68b59bb8665637e30e32ec2051f99cf6b9c674fe09",
		},

		{
			suri:      "bottom drive obey lake curtain smoke basket hold race lonely fit walk/foo//bar",
			publicKey: "0xdc142f7476a7b0aa262aeccf207f1d18daa90762db393006741e8a31f39dbc53",
		},

		{
			suri:      "bottom drive obey lake curtain smoke basket hold race lonely fit walk//foo/bar//42/69",
			publicKey: "0xa2e56b06407a6d1e819d2fc33fa0ec604b29c2e868b70b3696bb049b8725934b",
		},

		{
			suri:      "bottom drive obey lake curtain smoke basket hold race lonely fit walk//foo/bar//42/69///password",
			publicKey: "0x0e0d24e3e1ff2c07f269c99e2e0df8681fda1851ac42fc846ca2daaa90cd8f14",
		},
	}

	for _, c := range tests {
		s, err := KeyRingFromURI(c.suri)
		if err != nil {
			assert.True(t, c.err)
			continue
		}

		pub, err := s.Public()
		assert.NoError(t, err)
		pubb := pub.Encode()
		assert.Equal(t, c.publicKey, "0x"+hex.EncodeToString(pubb[:]))
	}
}
