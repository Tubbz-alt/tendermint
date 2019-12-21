package crypto_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/ed25519"
)

func TestEncoding(t *testing.T) {
	pKey := ed25519.GenPrivKey()
	bz, err := crypto.MarshalPrivKey(pKey)
	fmt.Println(bz)
	require.NoError(t, err)
	require.NotNil(t, bz)

}

func TestDecoding(t *testing.T) {
	pk := ed25519.GenPrivKey()

	bz, _ := pk.Bytes()
	var c crypto.PrivKeyInterface
	// var ed ed25519.PrivKeyEd25519
	crypto.UnmarshalPrivKey(bz, &c)
	fmt.Println(c)

}

//
