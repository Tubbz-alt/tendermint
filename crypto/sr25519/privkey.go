package sr25519

import (
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/gogo/protobuf/proto"
	"github.com/tendermint/tendermint/crypto"

	schnorrkel "github.com/ChainSafe/go-schnorrkel"
)

// PrivKeySr25519Size is the number of bytes in an Sr25519 private key.
const PrivKeySr25519Size = 32

var _ crypto.PrivKeyInterface = PrivKeySr25519{}

// PrivKeySr25519 implements crypto.PrivKey.
type PrivKeySr25519 [PrivKeySr25519Size]byte

// Bytes marshals the privkey using amino encoding.
func (privKey PrivKeySr25519) Bytes() ([]byte, error) {
	pKey := crypto.PrivKey{
		Key: &crypto.PrivKey_Sr25519{privKey[:]},
	}

	return proto.Marshal(&pKey)
}

// Sign produces a signature on the provided message.
func (privKey PrivKeySr25519) Sign(msg []byte) ([]byte, error) {
	secretKey := &(schnorrkel.SecretKey{})
	err := secretKey.Decode(privKey)
	if err != nil {
		return []byte{}, err
	}

	signingContext := schnorrkel.NewSigningContext([]byte{}, msg)

	sig, err := secretKey.Sign(signingContext)
	if err != nil {
		return []byte{}, err
	}

	sigBytes := sig.Encode()
	return sigBytes[:], nil
}

// PubKey gets the corresponding public key from the private key.
func (privKey PrivKeySr25519) PubKey() crypto.PubKeyInterface {

	secretKey := &(schnorrkel.SecretKey{})
	err := secretKey.Decode(privKey)
	if err != nil {
		panic(fmt.Sprintf("Invalid private key: %v", err))
	}

	pubkey, _ := secretKey.Public()

	return PubKeySr25519(pubkey.Encode())
}

// Equals - you probably don't need to use this.
// Runs in constant time based on length of the keys.
func (privKey PrivKeySr25519) Equals(other crypto.PrivKeyInterface) bool {
	if otherEd, ok := other.(PrivKeySr25519); ok {
		return subtle.ConstantTimeCompare(privKey[:], otherEd[:]) == 1
	}
	return false
}

// GenPrivKey generates a new sr25519 private key.
// It uses OS randomness in conjunction with the current global random seed
// in tendermint/libs/common to generate the private key.
func GenPrivKey() PrivKeySr25519 {
	return genPrivKey(crypto.CReader())
}

// genPrivKey generates a new sr25519 private key using the provided reader.
func genPrivKey(rand io.Reader) PrivKeySr25519 {
	var seed [64]byte

	out := make([]byte, 64)
	_, err := io.ReadFull(rand, out)
	if err != nil {
		panic(err)
	}

	copy(seed[:], out)

	return schnorrkel.NewMiniSecretKey(seed).ExpandEd25519().Encode()
}

// GenPrivKeyFromSecret hashes the secret with SHA2, and uses
// that 32 byte output to create the private key.
// NOTE: secret should be the output of a KDF like bcrypt,
// if it's derived from user input.
func GenPrivKeyFromSecret(secret []byte) PrivKeySr25519 {
	seed := crypto.Sha256(secret) // Not Ripemd160 because we want 32 bytes.
	var bz [PrivKeySr25519Size]byte
	copy(bz[:], seed)
	privKey, _ := schnorrkel.NewMiniSecretKeyFromRaw(bz)
	return privKey.ExpandEd25519().Encode()
}
