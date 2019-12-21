package sr25519

import (
	"bytes"
	"fmt"

	"github.com/gogo/protobuf/proto"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/tmhash"

	schnorrkel "github.com/ChainSafe/go-schnorrkel"
)

var _ crypto.PubKeyInterface = PubKeySr25519{}

// PubKeySr25519Size is the number of bytes in an Sr25519 public key.
const PubKeySr25519Size = 32

// PubKeySr25519 implements crypto.PubKey for the Sr25519 signature scheme.
type PubKeySr25519 [PubKeySr25519Size]byte

// Address is the SHA256-20 of the raw pubkey bytes.
func (pubKey PubKeySr25519) Address() crypto.Address {
	return crypto.Address(tmhash.SumTruncated(pubKey[:]))
}

// Bytes marshals the PubKey using proto encoding.
func (pubKey PubKeySr25519) Bytes() ([]byte, error) {
	pKey := crypto.PubKey{
		Key: &crypto.PubKey_Sr25519{pubKey[:]},
	}

	return proto.Marshal(&pKey)
}

func (pubKey PubKeySr25519) VerifyBytes(msg []byte, sig []byte) bool {
	// make sure we use the same algorithm to sign
	if len(sig) != PubKeySr25519Size {
		return false
	}
	var sig64 [SignatureSize]byte
	copy(sig64[:], sig)

	publicKey := &(schnorrkel.PublicKey{})
	err := publicKey.Decode(pubKey)
	if err != nil {
		return false
	}

	signingContext := schnorrkel.NewSigningContext([]byte{}, msg)

	signature := &(schnorrkel.Signature{})
	err = signature.Decode(sig64)
	if err != nil {
		return false
	}

	return publicKey.Verify(signature, signingContext)
}

func (pubKey PubKeySr25519) String() string {
	return fmt.Sprintf("PubKeySr25519{%X}", pubKey[:])
}

// Equals - checks that two public keys are the same time
// Runs in constant time based on length of the keys.
func (pubKey PubKeySr25519) Equals(other crypto.PubKeyInterface) bool {
	if otherEd, ok := other.(PubKeySr25519); ok {
		return bytes.Equal(pubKey[:], otherEd[:])
	}
	return false
}
