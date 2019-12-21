package crypto

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"io"

	"golang.org/x/crypto/ed25519"

	proto "github.com/gogo/protobuf/proto"
	"github.com/tendermint/tendermint/crypto/tmhash"
)

//-------------------------------------

var _ PrivKeyInterface = PrivKeyEd25519{}

const (
	PrivKeyAminoName = "tendermint/PrivKeyEd25519"
	PubKeyAminoName  = "tendermint/PubKeyEd25519"
	// Size of an Edwards25519 signature. Namely the size of a compressed
	// Edwards25519 point, and a field element. Both of which are 32 bytes.
	SignatureSize = 64
)

// var cdc = amino.NewCodec()

// PrivKeyEd25519 implements crypto.PrivKey.
type PrivKeyEd25519 [64]byte

// // Bytes marshals the privkey using amino encoding.
// func (privKey PrivKeyEd25519) Bytes() []byte {
// 	return cdc.MustMarshalBinaryBare(privKey)
// }

func (privKey PrivKeyEd25519) Marshal(pk []byte) ([]byte, error) {
	pKey := PrivKey{
		PrivKey: &PrivKey_Ed25519{pk},
	}

	return proto.Marshal(&pKey)
}

func (privKey PrivKeyEd25519) Unmarshal(bz []byte, dest *PrivKeyInterface) error {
	var pk PrivKey
	err := proto.Unmarshal(bz, &pk)
	if err != nil {
		return err
	}
	key, ok := pk.PrivKey.(PrivKeyInterface)
	if !ok {
		return fmt.Errorf("deserialized account %+v does not implement PrivKeyInterface", key)
	}
	*dest = key
	return nil
}

// Sign produces a signature on the provided message.
// This assumes the privkey is wellformed in the golang format.
// The first 32 bytes should be random,
// corresponding to the normal ed25519 private key.
// The latter 32 bytes should be the compressed public key.
// If these conditions aren't met, Sign will panic or produce an
// incorrect signature.
func (privKey PrivKeyEd25519) Sign(msg []byte) ([]byte, error) {
	signatureBytes := ed25519.Sign(privKey[:], msg)
	return signatureBytes, nil
}

// PubKey gets the corresponding public key from the private key.
func (privKey PrivKeyEd25519) PubKey() PubKeyInterface {
	privKeyBytes := [64]byte(privKey)
	initialized := false
	// If the latter 32 bytes of the privkey are all zero, compute the pubkey
	// otherwise privkey is initialized and we can use the cached value inside
	// of the private key.
	for _, v := range privKeyBytes[32:] {
		if v != 0 {
			initialized = true
			break
		}
	}

	if !initialized {
		panic("Expected PrivKeyEd25519 to include concatenated pubkey bytes")
	}

	var pubkeyBytes [PubKeyEd25519Size]byte
	copy(pubkeyBytes[:], privKeyBytes[32:])
	return PubKeyEd25519(pubkeyBytes)
}

// Equals - you probably don't need to use this.
// Runs in constant time based on length of the keys.
func (privKey PrivKeyEd25519) Equals(other PrivKeyInterface) bool {
	if otherEd, ok := other.(PrivKeyEd25519); ok {
		return subtle.ConstantTimeCompare(privKey[:], otherEd[:]) == 1
	}

	return false
}

// GenPrivKey generates a new ed25519 private key.
// It uses OS randomness in conjunction with the current global random seed
// in tendermint/libs/common to generate the private key.
func GenPrivKey() PrivKeyEd25519 {
	return genPrivKey(CReader())
}

// genPrivKey generates a new ed25519 private key using the provided reader.
func genPrivKey(rand io.Reader) PrivKeyEd25519 {
	seed := make([]byte, 32)
	_, err := io.ReadFull(rand, seed)
	if err != nil {
		panic(err)
	}

	privKey := ed25519.NewKeyFromSeed(seed)
	var privKeyEd PrivKeyEd25519
	copy(privKeyEd[:], privKey)
	return privKeyEd
}

// GenPrivKeyFromSecret hashes the secret with SHA2, and uses
// that 32 byte output to create the private key.
// NOTE: secret should be the output of a KDF like bcrypt,
// if it's derived from user input.
func GenPrivKeyFromSecret(secret []byte) PrivKeyEd25519 {
	seed := Sha256(secret) // Not Ripemd160 because we want 32 bytes.

	privKey := ed25519.NewKeyFromSeed(seed)
	var privKeyEd PrivKeyEd25519
	copy(privKeyEd[:], privKey)
	return privKeyEd
}

//-------------------------------------

var _ PubKeyInterface = PubKeyEd25519{}

// PubKeyEd25519Size is the number of bytes in an Ed25519 signature.
const PubKeyEd25519Size = 32

// PubKeyEd25519 implements PubKey for the Ed25519 signature scheme.
type PubKeyEd25519 [PubKeyEd25519Size]byte

func (cdc PubKeyEd25519) Marshal(pk []byte) ([]byte, error) {
	pKey := PubKey{
		PubKey: &PubKey_Ed25519{pk},
	}

	return proto.Marshal(&pKey)
}

func (cdc PubKeyEd25519) Unmarshal(bz []byte, dest *PubKeyInterface) error {
	var pk PubKey
	err := proto.Unmarshal(bz, &pk)
	if err != nil {
		return err
	}
	key, ok := pk.PubKey.(PubKeyInterface)
	if !ok {
		return fmt.Errorf("deserialized account %+v does not implement PrivKeyInterface", key)
	}
	*dest = key
	return nil
}

// Address is the SHA256-20 of the raw pubkey bytes.
func (pubKey PubKeyEd25519) Address() Address {
	return Address(tmhash.SumTruncated(pubKey[:]))
}

// Bytes marshals the PubKey using amino encoding.
// func (pubKey PubKeyEd25519) Bytes() []byte {
// 	bz, err := cdc.MarshalBinaryBare(pubKey)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return bz
// }

func (pubKey PubKeyEd25519) VerifyBytes(msg []byte, sig []byte) bool {
	// make sure we use the same algorithm to sign
	if len(sig) != SignatureSize {
		return false
	}
	return ed25519.Verify(pubKey[:], msg, sig)
}

func (pubKey PubKeyEd25519) String() string {
	return fmt.Sprintf("PubKeyEd25519{%X}", pubKey[:])
}

// nolint: golint
func (pubKey PubKeyEd25519) Equals(other PubKeyInterface) bool {
	if otherEd, ok := other.(PubKeyEd25519); ok {
		return bytes.Equal(pubKey[:], otherEd[:])
	}

	return false
}
