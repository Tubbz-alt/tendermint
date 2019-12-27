package crypto

import (
	"github.com/tendermint/tendermint/crypto/tmhash"
	"github.com/tendermint/tendermint/libs/bytes"
)

const (
	// AddressSize is the size of a pubkey address.
	AddressSize = tmhash.TruncatedSize
)

// An address is a []byte, but hex-encoded even in JSON.
// []byte leaves us the option to change the address length.
// Use an alias so Unmarshal methods (with ptr receivers) are available too.
type Address = bytes.HexBytes

func AddressHash(bz []byte) Address {
	return Address(tmhash.SumTruncated(bz))
}

type PubKeyInterface interface {
	Address() Address
	Bytes() ([]byte, error)
	VerifyBytes(msg []byte, sig []byte) bool
	Equals(PubKeyInterface) bool
}

type PrivKeyInterface interface {
	Bytes() ([]byte, error)
	Sign(msg []byte) ([]byte, error)
	PubKey() PubKeyInterface
	Equals(PrivKeyInterface) bool
}

type Symmetric interface {
	Keygen() []byte
	Encrypt(plaintext []byte, secret []byte) (ciphertext []byte)
	Decrypt(ciphertext []byte, secret []byte) (plaintext []byte, err error)
}