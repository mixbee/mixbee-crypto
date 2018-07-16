package sm2

import (
	"crypto/elliptic"
	"sync"
)

var initonce sync.Once

// SM2Curve is the curve interface used in sm2 algorithm.
// It extends elliptic.Curve by adding a function ABytes().
type SM2Curve interface {
	elliptic.Curve

	// ABytes returns the little endian byte sequence of parameter A.
	ABytes() []byte
}

// SM2P256V1 returns the sm2p256v1 curve.
func SM2P256V1() elliptic.Curve {
	initonce.Do(initP256)
	return p256
}
