package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	_ "crypto/sha256"
	_ "crypto/sha512"

	"golang.org/x/crypto/hkdf"
)

func chk(err error) {
	if err != nil {
		panic(err)
	}
}

func from_hex(s string) []byte {
	b, err := hex.DecodeString(s)
	chk(err)
	return b
}

type CipherSuite struct {
	ID      uint16
	Name    string
	Nk      int
	Nn      int
	Hash    crypto.Hash
	NewAEAD func(key []byte) cipher.AEAD
}

func newGCM(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	chk(err)

	gcm, err := cipher.NewGCM(block)
	chk(err)

	return gcm
}

var (
	AES_GCM_128_SHA256 = CipherSuite{
		ID:      0x0003,
		Name:    "AES_GCM_128_SHA256",
		Nk:      16,
		Nn:      12,
		Hash:    crypto.SHA256,
		NewAEAD: newGCM,
	}
	AES_GCM_256_SHA512 = CipherSuite{
		ID:      0x0004,
		Name:    "AES_GCM_256_SHA512",
		Nk:      32,
		Nn:      12,
		Hash:    crypto.SHA512,
		NewAEAD: newGCM,
	}
)

func (suite CipherSuite) Extract(ikm, salt []byte) []byte {
	return hkdf.Extract(suite.Hash.New, ikm, salt)
}

func (suite CipherSuite) Expand(prk, info []byte, size int) []byte {
	out := make([]byte, size)
	r := hkdf.Expand(suite.Hash.New, prk, info)
	r.Read(out)
	return out
}

// Cases:
// * KID=0x07, CTR=0, 1, 2
// * KID=0xffff, CTR=0
// * KID=0xffff, CTR=0x0100
var (
	baseKeys = map[uint16][]byte{
		AES_GCM_128_SHA256.ID: from_hex("101112131415161718191a1b1c1d1e1f"),
		AES_GCM_256_SHA512.ID: from_hex("202122232425262728292a2b2c2d2e2f" +
			"303132333435363738393a3b3c3d3e3f"),
	}

	plaintext         = from_hex("00010203")
	header_7_0        = from_hex("1700")
	header_7_1        = from_hex("1701")
	header_7_2        = from_hex("1702")
	header_long_short = from_hex("1affff00")
	header_long_long  = from_hex("2affff0100")
)

func protect(suite CipherSuite, ctr uint64, header []byte) []byte {
	baseKey := baseKeys[suite.ID]
	secret := suite.Extract(baseKey, []byte("SFrame10"))
	key := suite.Expand(secret, []byte("key"), suite.Nk)
	salt := suite.Expand(secret, []byte("salt"), suite.Nn)

	nonce := make([]byte, suite.Nn)
	binary.BigEndian.PutUint64(nonce[suite.Nn-8:], ctr)
	for i := range nonce {
		nonce[i] ^= salt[i]
	}

	aead := suite.NewAEAD(key)
	ct := aead.Seal(nil, nonce, plaintext, header)
	return append(header, ct...)
}

func main() {
	suites := []CipherSuite{AES_GCM_128_SHA256, AES_GCM_256_SHA512}
	for _, suite := range suites {
		ct_7_0 := protect(suite, 0, header_7_0)
		ct_7_1 := protect(suite, 1, header_7_1)
		ct_7_2 := protect(suite, 2, header_7_2)
		ct_long_short := protect(suite, 0, header_long_short)
		ct_long_long := protect(suite, 0x0100, header_long_long)

		fmt.Printf("{ CipherSuite::%s,\n", suite.Name)
		fmt.Printf("  {\n")
		fmt.Printf("    from_hex(\"%x\"),\n", baseKeys[suite.ID])
		fmt.Printf("    from_hex(\"%x\"),\n", ct_7_0)
		fmt.Printf("    from_hex(\"%x\"),\n", ct_7_1)
		fmt.Printf("    from_hex(\"%x\"),\n", ct_7_2)
		fmt.Printf("    from_hex(\"%x\"),\n", ct_long_short)
		fmt.Printf("    from_hex(\"%x\"),\n", ct_long_long)
		fmt.Printf("  } },\n")
	}
}
