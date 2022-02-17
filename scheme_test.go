package subkey_test

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vedhavyas/go-subkey"
	"github.com/vedhavyas/go-subkey/ecdsa"
	"github.com/vedhavyas/go-subkey/ed25519"
	"github.com/vedhavyas/go-subkey/sr25519"
)

//nolint:funlen
func TestDerive(t *testing.T) {
	testsMap := map[subkey.Scheme][]struct {
		uri       string
		seed      string
		publicKey string
		accountID string
		ss58Addr  string
		network   uint16
		err       bool
	}{
		sr25519.Scheme{}: {
			{
				uri:       "crowd swamp sniff machine grid pretty client emotion banana cricket flush soap",
				seed:      "0x18446f2d685492c3086391aabe8f5e235c3c2e02521985650f0c97052237e717",
				publicKey: "0x88af895626c47cf1235ec3898d238baeb41adca3117b9a77bc2f6b78eca0771b",
				ss58Addr:  "5F9vWoiazEhfxSxCG8nUuDhh5fqNtPnSxp2BrhPsuLqEQASi",
				network:   42,
			},

			{
				uri:       "0x18446f2d685492c3086391aabe8f5e235c3c2e02521985650f0c97052237e717",
				seed:      "0x18446f2d685492c3086391aabe8f5e235c3c2e02521985650f0c97052237e717",
				publicKey: "0x88af895626c47cf1235ec3898d238baeb41adca3117b9a77bc2f6b78eca0771b",
				ss58Addr:  "5F9vWoiazEhfxSxCG8nUuDhh5fqNtPnSxp2BrhPsuLqEQASi",
				network:   42,
			},

			{
				uri:       "crowd swamp sniff machine grid pretty client emotion banana cricket flush soap///password",
				seed:      "0xd2dbfa26295528f3893430047b773e5bc5457b02c520c5d80bb83366d42de032",
				publicKey: "0x5c2d57c4cfa7df7a9d0e9546bb575045f5ec14e9771de8bc907910c84cd5de2a",
				ss58Addr:  "5E9ZjRM9VdqES5JhbABVpvgCstaE7J5x3cE7sTKMGG5TF8tZ",
				network:   42,
			},
			{
				uri:       "crowd swamp sniff machine grid pretty client emotion banana cricket flush soap/foo",
				publicKey: "0x287061f5973551d070ccc62fb4563a0be2e6324ce183c456850e342aa021f94d",
				ss58Addr:  "5CyjA4yQrQtJBs7jC4D6S672y3Ez4Shd3se6VXB4JBkdGwUZ",
				network:   42,
			},
			{
				uri:       "crowd swamp sniff machine grid pretty client emotion banana cricket flush soap//foo",
				seed:      "0x5e42b0ed6e2e5f415ff7b40aeda2c7d620c48b680483340866d0b413af33c2ee",
				publicKey: "0x04bd4f94429371e044509d22f8a6d33ab9c336bf54ef6b38eba0cc3a4f125e5a",
				ss58Addr:  "5CAvHXaqNRwbbL4B3MoQJdam8JmotCGAF8kTpgWhR9ahhJYS",
				network:   42,
			},
			{
				uri:       "crowd swamp sniff machine grid pretty client emotion banana cricket flush soap//foo//42",
				seed:      "0xec3cea90f177012d75ed1ec96372567777a5615c96cc85462152f8007c7f4205",
				publicKey: "0xde4255b281cda3580a7aad6d2c7efd990e6b31569ab1a0a8adc18b32e4fa510f",
				ss58Addr:  "5H68C9rPXxtbsAZMznJaLJWfg1GXDuf3yAgjZoMYcfGxZ6Db",
				network:   42,
			},
			{
				uri:       "crowd swamp sniff machine grid pretty client emotion banana cricket flush soap//foo/bar",
				publicKey: "0x0c6febc87c461f8ddceb295d90c3ba999b1e93c2bdd13145b265512d06729449",
				ss58Addr:  "5CM1gMJkyRoE7txkdHv31y6H4yPMKCALSDpaeaE8BpDVwrht",
				network:   42,
			},
			{
				uri:       "crowd swamp sniff machine grid pretty client emotion banana cricket flush soap/foo//bar",
				publicKey: "0xe4535b3b8e259badc3c78128bfafe0b50df625862edaff7c9d68999a0811865b",
				ss58Addr:  "5HE5Y6MDZvy9QJsmgjrnJHiSqsYRTrfBLrzLvHQC3f9PM6TR",
				network:   42,
			},
			{
				uri:       "crowd swamp sniff machine grid pretty client emotion banana cricket flush soap//foo/bar//42/69",
				publicKey: "0x68a5a8f7e29ffcae1d15518b180f6e4f1132b45ffd565cb7953045faf07c8809",
				ss58Addr:  "5ERv3mLP7CX1CViNc6NUQaePBJMkf6BELffpMfXjXjj28SNo",
				network:   42,
			},
			{
				uri:       "crowd swamp sniff machine grid pretty client emotion banana cricket flush soap//foo/bar//42/69///password",
				publicKey: "0x4055514cd4ddcc7b23024839b68190f3f71bc262eb038145262bfe087bbb5429",
				ss58Addr:  "5DX4GQQm9rSHVcqaG9CgxdZLsj8buBxcRWEYYcHrRXe4epZg",
				network:   42,
			},
		},
		ed25519.Scheme{}: {
			{
				uri:       "crowd swamp sniff machine grid pretty client emotion banana cricket flush soap",
				seed:      "0x18446f2d685492c3086391aabe8f5e235c3c2e02521985650f0c97052237e717",
				publicKey: "0xe4631cda48cb885f3a6d0b521d3278ec3e834dd2e1766f7edb8e1386535cc217",
				ss58Addr:  "5HEADZuqsQzNPxGySd74DGPhfm8vFFPVGaKPWkQigJgtv41f",
				network:   42,
			},

			{
				uri:       "0x18446f2d685492c3086391aabe8f5e235c3c2e02521985650f0c97052237e717",
				seed:      "0x18446f2d685492c3086391aabe8f5e235c3c2e02521985650f0c97052237e717",
				publicKey: "0xe4631cda48cb885f3a6d0b521d3278ec3e834dd2e1766f7edb8e1386535cc217",
				ss58Addr:  "5HEADZuqsQzNPxGySd74DGPhfm8vFFPVGaKPWkQigJgtv41f",
				network:   42,
			},

			{
				uri:       "crowd swamp sniff machine grid pretty client emotion banana cricket flush soap///password",
				seed:      "0xd2dbfa26295528f3893430047b773e5bc5457b02c520c5d80bb83366d42de032",
				publicKey: "0x261a29a2b6f690f394d339dc6e09f7f8fa85a3ed82b7567e2bb2a79c33651eef",
				ss58Addr:  "5CvfSyhefVmXnmQ2c4ff6h4EBuhNqaRpjoEHyMD8JWdnpH7y",
				network:   42,
			},
			{
				uri:       "crowd swamp sniff machine grid pretty client emotion banana cricket flush soap//foo",
				seed:      "0x833f823fbc06b721890c56ecb5dc3972039b2e84bb8b6776e801d95e5dcdd18d",
				publicKey: "0x986f6247a100aee1aaaadb215fc681f95a64a86fd1f12d4360514f9be7769f40",
				ss58Addr:  "5FWaDvLD9wuZRiLzCxECXdrc57Xavjh5WMvC54ufMQmvPTxD",
				network:   42,
			},
			{
				uri:       "crowd swamp sniff machine grid pretty client emotion banana cricket flush soap//foo//42",
				seed:      "0x5a9060fb4a7441903228e7e7138a95ecc7f84ce4f153b37325a87b5f35829df1",
				publicKey: "0x7a16bd534b1aab9d420d5ca544927ccff88f76e39b063faee502b63f7a2fb394",
				ss58Addr:  "5EpnTJ2E731sTG9WnHNS2cbcppriXx7RF8nmRSaBHWg5hRSr",
				network:   42,
			},
			{
				uri:       "crowd swamp sniff machine grid pretty client emotion banana cricket flush soap//foo//42///password",
				seed:      "0x21346646d89dfcf14d69152583ccd30f3ebc385f0b112c54b477be16ff4fcfb9",
				publicKey: "0x34f7460f79c0c4947dfe1b4176ff8cf974883ed2f2a5c716ed89bd16b11e05dc",
				ss58Addr:  "5DG9oWqVMaxTn7LksujDvYPQEcU19yGiEkgAEHFYoBtYudM9",
				network:   42,
			},
		},
		ecdsa.Scheme{}: {
			{
				uri:       "crowd swamp sniff machine grid pretty client emotion banana cricket flush soap",
				seed:      "0x18446f2d685492c3086391aabe8f5e235c3c2e02521985650f0c97052237e717",
				publicKey: "0x033d2d207f8d5a3269fae4609fadde7ec2ce384d36170132636739bbf05d59cf4f",
				accountID: "0x8857761f773009d28daeca8cdbead6328bc18d238b5d7465420c987e9543da2b",
				ss58Addr:  "5F9UMJqrtQ2k2i4tP3qcdvCttunoQLdTtDyDSShoSgFRhFfC",
				network:   42,
			},

			{
				uri:       "0x18446f2d685492c3086391aabe8f5e235c3c2e02521985650f0c97052237e717",
				seed:      "0x18446f2d685492c3086391aabe8f5e235c3c2e02521985650f0c97052237e717",
				publicKey: "0x033d2d207f8d5a3269fae4609fadde7ec2ce384d36170132636739bbf05d59cf4f",
				accountID: "0x8857761f773009d28daeca8cdbead6328bc18d238b5d7465420c987e9543da2b",
				ss58Addr:  "5F9UMJqrtQ2k2i4tP3qcdvCttunoQLdTtDyDSShoSgFRhFfC",
				network:   42,
			},

			{
				uri:       "crowd swamp sniff machine grid pretty client emotion banana cricket flush soap///password",
				seed:      "0xd2dbfa26295528f3893430047b773e5bc5457b02c520c5d80bb83366d42de032",
				publicKey: "0x032682ae5c64e88d008edef86313909f928feb337abe73c3279e7c0941e9f78073",
				accountID: "0xecf9fd593d24d7d0b7dc4cb41177ea6935e4f99e5274302eb7ddd821cc7ff02f",
				ss58Addr:  "5HRRRLS5sPdMHTDUfPShrwVgqRBnaVVkDskEtShcBPdhZdSr",
				network:   42,
			},
			{
				uri:       "crowd swamp sniff machine grid pretty client emotion banana cricket flush soap//foo",
				seed:      "0x1e489c9526180c5fa2d03b98880ef6489fb7026fecb1695e2cc0140e8a62acd4",
				publicKey: "0x038254160e975003f46afa848dccd40962a70e2fe233e6eacf1d16dcc4dfd4b26a",
				accountID: "0xae27f3f58ad1dd5a8b2cc051d0740082ac7e6d9f65a1b0f4be9b4ecce90106b7",
				ss58Addr:  "5G144J3pcwW8q22RMpUEY6e9AeviTK4LLbFWzigYekPfVS4T",
				network:   42,
			},
			{
				uri:       "crowd swamp sniff machine grid pretty client emotion banana cricket flush soap//foo//42",
				seed:      "0x55b559fa98d42b2bf7c4f7e428774d639e877ad1d33162d662004a0c834d6eeb",
				publicKey: "0x0357af8e3e095a0f348fef65b78839a8dc4b4c959f24c4a5a0125f3989cc0a90d0",
				accountID: "0x67be6fa968bad671e5421692c5e7031625446b0a4412840b9107bca4e4dbf523",
				ss58Addr:  "5EQjMsU88KFTjtd35oujweATPy9nPE5wvLjoMaKWho3NWJok",
				network:   42,
			},
			{
				uri:       "crowd swamp sniff machine grid pretty client emotion banana cricket flush soap//foo//42///password",
				seed:      "0x6ea8835d60351a39a1e2293b2902d7bd6e12e526e72c46f4fda4a233809c4379",
				publicKey: "0x0220bf156d0432c5abe371b1c46b6eef730668405957ed044a64b7f926fd90c6a3",
				accountID: "0x948f80da32015cb04b47405d1ad2e77bda020416c6094ab0300a71625f082149",
				ss58Addr:  "5FRVaDUQMhpm1vBK5Y5EjdoNhv5tZRTBRgq8eoD1meRse6om",
				network:   42,
			},
		},
	}

	for scheme, tests := range testsMap {
		for _, c := range tests {
			t.Run(fmt.Sprintf("%s-%s", scheme, c.uri), func(t *testing.T) {
				s, err := subkey.DeriveKeyPair(scheme, c.uri)
				if err != nil {
					assert.True(t, c.err)
					return
				}

				pub := s.Public()
				assert.Equal(t, c.publicKey, subkey.EncodeHex(pub))
				if c.accountID != "" {
					assert.Equal(t, c.accountID, subkey.EncodeHex(s.AccountID()))
				}
				seed := subkey.EncodeHex(s.Seed())
				if s.Seed() == nil {
					seed = ""
				}
				assert.Equal(t, c.seed, seed)
				gotSS58Addr := s.SS58Address(c.network)
				assert.Equal(t, c.ss58Addr, gotSS58Addr)
			})
		}
	}
}

func Test_Generate_Sign_Verify(t *testing.T) {
	msg := []byte(strings.Repeat("as", rand.Intn(100))) //nolint:gosec
	verify := func(kr subkey.KeyPair) {
		sig, err := kr.Sign(msg)
		assert.NoError(t, err)
		assert.True(t, kr.Verify(msg, sig))
	}
	t.Run("sr25519", func(t *testing.T) {
		kr, err := sr25519.Scheme{}.Generate()
		assert.NoError(t, err)
		verify(kr)
	})
	t.Run("ed25519", func(t *testing.T) {
		kr, err := ed25519.Scheme{}.Generate()
		assert.NoError(t, err)
		verify(kr)
	})
	t.Run("ecdsa", func(t *testing.T) {
		kr, err := ecdsa.Scheme{}.Generate()
		assert.NoError(t, err)
		verify(kr)
	})
}
