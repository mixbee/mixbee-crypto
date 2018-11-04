package keypair

// Conversion between PrivateKey and WIF.
// Only ECDSA keys with curve P-256 supported.

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	base58 "github.com/itchyny/base58-go"
	"github.com/mixbee/mixbee-crypto/ec"
)

func Key2WIF(key PrivateKey) ([]byte, error) {
	data := SerializePrivateKey(key)
	if len(data) < 34 || data[0] != byte(PK_ECDSA) || data[1] != byte(P256) {
		return nil, errors.New("only ECDSA P-256 keys support WIF")
	}
	buf := data[1:34]
	buf[0] = 0x80
	buf = append(buf, 0x01)
	sum := sha256.Sum256(buf)
	sum = sha256.Sum256(sum[:])
	buf = append(buf, sum[:4]...)
	bi := new(big.Int).SetBytes(buf)
	clearBytes(data)
	clearBytes(buf)
	return base58.BitcoinEncoding.Encode([]byte(bi.Text(10)))
}

func WIF2Key(wif []byte) (PrivateKey, error) {
	buf, err := base58.BitcoinEncoding.Decode(wif)
	if err != nil {
		return nil, err
	}
	bi, ok := new(big.Int).SetString(string(buf), 10)
	clearBytes(buf)
	if !ok || bi == nil {
		return nil, errors.New("parse WIF error, invalid base58 data")
	}
	buf = bi.Bytes()
	pos := len(buf) - 4
	if pos != 34 {
		return nil, fmt.Errorf("invalid length: %d", pos)
	}
	sum := sha256.Sum256(buf[:pos])
	sum = sha256.Sum256(sum[:])
	if !bytes.Equal(sum[:4], buf[pos:]) {
		return nil, errors.New("invalid WIF data, checksum failed")
	}
	pri := ec.ConstructPrivateKey(buf[1:pos-1], elliptic.P256())
	clearBytes(buf)
	return &ec.PrivateKey{Algorithm: ec.ECDSA, PrivateKey: pri}, nil
}

func clearBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
