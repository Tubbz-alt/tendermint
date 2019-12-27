package crypto

import (
	fmt "fmt"
	"github.com/tendermint/tendermint/crypto/ed25519"
	"github.com/tendermint/tendermint/crypto/secp256k1"
	"github.com/tendermint/tendermint/crypto/sr25519"
)

func MarshalPubKey(pki PubKeyInterface) ([]byte, error) {
	var asOneof isPubKey_Key
	switch pki := pki.(type) {
	case ed25519.PubKeyEd25519:
		asOneof = &PubKey_Ed25519{Ed25519: pki[:]}
	case sr25519.PubKeySr25519:
		asOneof = &PubKey_Sr25519{Sr25519: pki[:]}
	case secp256k1.PubKeySecp256k1:
		asOneof = &PubKey_Secp256K1{Secp256K1: pki[:]}
	}
	protoKey := PubKey{
		Key: asOneof,
	}
	return protoKey.Marshal()
}

func UnmarshalPubKey(bz []byte, dest *PubKeyInterface) error {
	var protoKey PubKey
	err := protoKey.Unmarshal(bz)
	if err != nil {
		return err
	}
	switch asOneof := protoKey.Key.(type) {
	// TODO
	}
	return fmt.Errorf("couldn't unmarshal pubkey %+v", protoKey)
}

func MarshalPrivKey(pki PrivKeyInterface) ([]byte, error) {
	asOneof, ok := pki.(isPrivKey_Key)
	if !ok {
		return nil, fmt.Errorf("key %+v not handled by codec", pki)
	}

	protoKey := PrivKey{
		Key: asOneof,
	}
	return protoKey.Marshal()
}

func UnmarshalPrivKey(bz []byte, dest *PrivKeyInterface) error {
	var protoKey PrivKey
	err := protoKey.Unmarshal(bz)
	if err != nil {
		return err
	}
	key, ok := protoKey.Key.(PrivKeyInterface)
	if !ok {
		return fmt.Errorf("deserialized key %+v does not implement privKey interface", key)
	}
	*dest = key
	return nil
}
