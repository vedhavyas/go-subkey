package common

import (
	"fmt"

	"github.com/decred/base58"
	"golang.org/x/crypto/blake2b"
)

// ChecksumType represents the one or more checksum types.
// More here: https://github.com/paritytech/substrate/wiki/External-Address-Format-(SS58)#checksum-types
// TODO(ved): Maybe we can add these types to the known list ?
type ChecksumType int

type Network uint8

const (
	ss58Prefix = "SS58PRE"

	// ErrUnknownNetwork error when network is not a known network.
	ErrUnknownNetwork = Error("Unknown Network")

	// SS58Checksum uses the concat(address-type, address) as blake2b hash pre-image
	SS58Checksum ChecksumType = iota

	// AccountIDChecksum uses the address as the blake2b hash pre-image
	AccountID
)

const (
	Substrate Network = 42
	Polkadot          = 0
	Kusama            = 2
	Dothereum         = 20
	Kulupu            = 16
	Edgeware          = 7
)

// SS58Address derives ss58 address from the address, network version, and checksumType
func SS58AddressWithVersion(addr [32]byte, version uint8, ctype ChecksumType) (string, error) {
	var cbuf []byte
	switch ctype {
	case SS58Checksum:
		cbuf = append([]byte{version}, addr[:]...)
	case AccountID:
		cbuf = addr[:]
	default:
		return "", fmt.Errorf("unknown checksum type: %v", ctype)
	}

	cs, err := ss58Checksum(append(cbuf))
	if err != nil {
		return "", err
	}

	fb := append([]byte{version}, addr[:]...)
	fb = append(fb, cs[0:2]...)
	return base58.Encode(fb), nil
}

// https://github.com/paritytech/substrate/wiki/External-Address-Format-(SS58)#checksum-types
func ss58Checksum(data []byte) ([]byte, error) {
	hasher, err := blake2b.New(64, nil)
	if err != nil {
		return nil, err
	}

	_, err = hasher.Write([]byte(ss58Prefix))
	if err != nil {
		return nil, err
	}

	_, err = hasher.Write(data)
	if err != nil {
		return nil, err
	}

	return hasher.Sum(nil), nil
}
