package ikey

import (
	"fmt"

	"github.com/apache/mynewt-artifact/sec"
	"github.com/pkg/errors"
)

type Desc struct {
	Private   bool
	Algorithm string
	PubBytes  []byte
	Hash      []byte
}

func signKeyToDesc(key sec.PubSignKey, private bool) (Desc, error) {
	var alg string
	if key.Rsa != nil {
		alg = fmt.Sprintf("RSA-%d", key.Rsa.Size()*8)
	} else if key.Ec != nil {
		alg = fmt.Sprintf("ECDSA-%d", key.Ec.X.BitLen())
	} else {
		alg = "ED25519"
	}

	pubBytes, err := key.Bytes()
	if err != nil {
		return Desc{}, err
	}

	return Desc{
		Private:   private,
		Algorithm: alg,
		PubBytes:  pubBytes,
		Hash:      sec.RawKeyHash(pubBytes),
	}, nil
}

func KeyBytesToDesc(keyBytes []byte) (Desc, error) {
	pubsk, err := sec.ParsePubSignKey(keyBytes)
	if err == nil {
		return signKeyToDesc(pubsk, false)
	}

	privsk, err := sec.ParsePrivSignKey(keyBytes)
	if err == nil {
		return signKeyToDesc(privsk.PubKey(), true)
	}

	return Desc{}, errors.Errorf("unrecognized key type")
}
