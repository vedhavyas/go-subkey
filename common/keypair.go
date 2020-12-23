package common

// KeyPair is the secret and public key
type KeyPair interface {
	Signer
	Verifier

	// Public returns the secret in bytes.
	Public() []byte

	// SS58Address returns the Base58 string of the address.
	// network: must be one of the known networks
	SS58Address(network Network, ctype ChecksumType) (string, error)
}

type Signer interface {
	// Sign signs the message and returns the signature.
	Sign(msg []byte) ([]byte, error)
}

type Verifier interface {
	// Verify verifies the signature.
	Verify(msg []byte, signature []byte) bool
}
