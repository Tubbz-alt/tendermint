package crypto

import fmt "fmt"

func MarshalPubKey(pki PubKeyInterface) ([]byte, error) {
	asOneof, ok := pki.(isPubKey_Key)
	if !ok {
		return nil, fmt.Errorf("key %+v not handled by codec", pki)
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
	acc, ok := protoKey.Key.(PubKeyInterface)
	if !ok {
		return fmt.Errorf("deserialized account %+v does not implement Account interface", acc)
	}
	*dest = acc
	return nil
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
