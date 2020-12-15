package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitURI(t *testing.T) {
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

		{
			suri:     "/Alice",
			phrase:   DevPhrase,
			path:     "/Alice",
			password: "",
		},

		{
			suri:     "/Alice///password",
			phrase:   DevPhrase,
			path:     "/Alice",
			password: "password",
		},

		{
			suri:     "//Alice///password",
			phrase:   DevPhrase,
			path:     "//Alice",
			password: "password",
		},

		{
			suri:     "//Alice",
			phrase:   DevPhrase,
			path:     "//Alice",
			password: "",
		},
	}

	for _, c := range tests {
		phrase, path, password, err := SplitURI(c.suri)
		if err != nil {
			assert.True(t, c.err)
			continue
		}

		assert.Equal(t, c.phrase, phrase)
		assert.Equal(t, c.path, path)
		assert.Equal(t, c.password, password)
	}
}
