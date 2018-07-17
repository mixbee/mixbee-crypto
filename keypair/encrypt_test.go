package keypair

import (
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ontio/ontology-crypto/ec"
)

var d = "3e47428fd73f915a7937bf1f8d3bffc27a45dbb6ef4e57bd9513c1a8bfbcbfd4"
var pwd = []byte("test password")
var pwd1 = []byte("new password")
var addr = "test address"
var keyjson = `{
  "address":"test address",
  "enc-alg":"aes-256-gcm",
  "key":"7qt5d2sdRb40QfH55KaRkNBbcAN9bKhurGwUVQ/7d68bsbGJSgldC/SoKNaqEp6t",
  "algorithm":"ECDSA",
  "salt":"f9IdwXxGK77/4x1whpBl1g==",
  "parameters":{"curve":"P-256"}
}`

func TestDecrypt(t *testing.T) {
	var pro ProtectedKey
	json.Unmarshal([]byte(keyjson), &pro)
	err := testDecrypt(&pro, pwd)
	if err != nil {
		t.Fatal(err)
	}
}

func testDecrypt(prot *ProtectedKey, pass []byte) error {
	pri, err := DecryptPrivateKey(prot, pass)
	if err != nil {
		return err
	}

	v, ok := pri.(*ec.PrivateKey)
	if !ok {
		return errors.New("decryption error: wrong key type")
	}
	if v.Algorithm != ec.ECDSA {
		return errors.New("decryption error: wrong algorithm")
	}
	if v.D.Text(16) != d {
		return errors.New("decryption error: d value is wrong, " + hex.EncodeToString(v.D.Bytes()))
	}
	return nil
}

func TestEncryptPrivate(t *testing.T) {
	D, _ := hex.DecodeString(d)
	pri := &ec.PrivateKey{
		Algorithm:  ec.ECDSA,
		PrivateKey: ec.ConstructPrivateKey(D, elliptic.P256()),
	}
	var pro ProtectedKey
	json.Unmarshal([]byte(keyjson), &pro)

	c, err := EncryptPrivateKey(pri, addr, pwd)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("address:", c.Address)
	t.Log("algorithm:", c.Alg)
	t.Log("parameter:", c.Param)

	_, err = json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}

	err = testDecrypt(c, pwd)
	if err != nil {
		t.Fatal(err)
	}
}

func TestReencrypt(t *testing.T) {
	var pro ProtectedKey
	json.Unmarshal([]byte(keyjson), &pro)

	sp0 := GetScryptParameters()
	sp1 := &ScryptParam{
		N:     4096,
		R:     8,
		P:     8,
		DKLen: 64,
	}

	pro1, err := ReencryptPrivateKey(&pro, pwd, pwd1, sp0, sp1)
	if err != nil {
		t.Fatal(err)
	}

	pri, err := DecryptWithCustomScrypt(pro1, pwd1, sp1)
	if err != nil {
		t.Fatal(err)
	}

	v, ok := pri.(*ec.PrivateKey)
	if !ok {
		t.Fatal("key type error")
	}
	if v.D.Text(16) != d {
		t.Fatal("decrypted key value error")
	}
}
