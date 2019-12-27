package crypto_test

import (
	fmt "fmt"
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

	var c crypto.PrivKeyInterface
	err = crypto.UnmarshalPrivKey(bz, &c)
	require.NoError(t, err)
	require.NotNil(t, bz)

}
