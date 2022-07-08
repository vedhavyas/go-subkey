package subkey

import (
	"reflect"
	"strings"
	"testing"
)

func TestAddressInfo(t *testing.T) {
	tests := []struct {
		name    string
		address string
		prefix  uint16
		pub     string
	}{
		{"TestAddressInfo_Alice_Substrate", "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", 42, "0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"},
		{"TestAddressInfo_Alice_Heiko", "hJKzPoi3MQnSLvbShxeDmzbtHncrMXe5zwS3Wa36P6kXeNpcv", 110, "0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"},
		{"TestAddressInfo_Alice_Contextfree", "a7SvTrjvshEMePMEZpEkYMekuZMPpDwMNqfUx8N8ScEEQYfM8", 11820, "0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, pubbz, err := SS58Decode(tt.address)
			if err != nil {
				t.Errorf("Decoding %v failed with %v", tt.address, err)
			}
			if !reflect.DeepEqual(prefix, tt.prefix) {
				t.Errorf("ss58.Decode() prefix = %v, want %v", prefix, tt.prefix)
			}
			reencoded := SS58Encode(pubbz, prefix)
			if !reflect.DeepEqual(reencoded, tt.address) {
				t.Errorf("Address did not roundtrip: Started with %v and ended with %v", tt.address, reencoded)
			}
			hexpub := EncodeHex(pubbz)
			if !reflect.DeepEqual(hexpub, tt.pub) {
				t.Errorf("ss58.Decode() pubkey = %v, want %v", hexpub, tt.pub)
			}

			decoded, _ := DecodeHex(tt.pub)
			if !reflect.DeepEqual(pubbz, decoded) {
				t.Errorf("DecodeHexPubKey()= %v, want %v", decoded, pubbz)
			}
		})
	}

	// Test bad checksum
	_, _, err := SS58Decode("a8SvTrjvshEMePMEZpEkYMekuZMPpDwMNqfUx8N8ScEEQYfM8")
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("Expected checksum mismatch but got '%v'", err)
	}
}
