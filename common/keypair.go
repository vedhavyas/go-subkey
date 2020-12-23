package common

// KeyPair is the secret and public key
type KeyPair interface {
	Signer
	Verifier

	// Seed returns the seed of the pair
	Seed() []byte

	// Public returns the pub key in bytes.
	Public() []byte

	// AccountID returns the accountID for this key
	AccountID() []byte

	// SS58Address returns the Base58 string.
	// uses SS58Checksum checksum type
	// SS58Checksum uses the concat(network, accountID) as blake2b hash pre-image
	// More here: https://github.com/paritytech/substrate/wiki/External-Address-Format-(SS58)#checksum-types
	SS58Address(network uint8) (string, error)

	// SS58AddressWithAccountIDChecksum returns the Base58 string.
	// uses AccountID checksum type
	// AccountIDChecksum uses the accountID as the blake2b hash pre-image
	// More here: https://github.com/paritytech/substrate/wiki/External-Address-Format-(SS58)#checksum-types
	SS58AddressWithAccountIDChecksum(network uint8) (string, error)
}

type Signer interface {
	// Sign signs the message and returns the signature.
	Sign(msg []byte) ([]byte, error)
}

type Verifier interface {
	// Verify verifies the signature.
	Verify(msg []byte, signature []byte) bool
}
