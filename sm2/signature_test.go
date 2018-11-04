

package sm2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/mixbee/mixbee-crypto/sm3"
)

var d_hex = "5be7e4b09a761bf5562ddf8e6a33184e00d0c09c942c6adbad1141d5d08431f0"
var x_hex = "bed1c52a2bb67d2cc82b0d099c5832b7886e21828c3745f84990c249cf8d5890"
var y_hex = "762a3a2e07c0e4ef2dee435d4f2b76d8892b42e77727eef72b9cbfa29c5eb76b"
var r_hex = "6e833daf8bd2cb5b09786a0ad5e6e5617242f8e60938f64afd11285e9d719a51"
var s_hex = "bdf93e24fe552d716f9ef1e1ae477af8f39a06b5d86222e76cbe5f14c0f063b1"
var msg = []byte("test message")

func restorePublicKey() *ecdsa.PublicKey {
	x, _ := new(big.Int).SetString(x_hex, 16)
	y, _ := new(big.Int).SetString(y_hex, 16)
	return &ecdsa.PublicKey{
		Curve: SM2P256V1(),
		X:     x,
		Y:     y,
	}
}

func restoreSignature() (r, s *big.Int) {
	r, _ = new(big.Int).SetString(r_hex, 16)
	s, _ = new(big.Int).SetString(s_hex, 16)
	return
}

func TestVerify(t *testing.T) {
	pub := restorePublicKey()
	r, s := restoreSignature()

	if !Verify(pub, "", msg, sm3.New(), r, s) {
		t.Error("verification failed")
	}
}

func TestSignAndVerify(t *testing.T) {
	pri, _ := ecdsa.GenerateKey(SM2P256V1(), rand.Reader)
	hasher := sm3.New()
	r, s, err := Sign(rand.Reader, pri, "", msg, hasher)
	if err != nil {
		t.Fatalf("signing error: %s", err)
	}

	if !Verify(&pri.PublicKey, "", msg, hasher, r, s) {
		t.Error("verification failed")
	}
}

func BenchmarkSign(b *testing.B) {
	pri, _ := ecdsa.GenerateKey(SM2P256V1(), rand.Reader)
	hasher := sm3.New()

	for i := 0; i < b.N; i++ {
		Sign(rand.Reader, pri, "", msg, hasher)
	}
}

func BenchmarkVerify(b *testing.B) {
	pub := restorePublicKey()
	r, s := restoreSignature()
	hasher := sm3.New()

	for i := 0; i < b.N; i++ {
		Verify(pub, "", msg, hasher, r, s)
	}
}
