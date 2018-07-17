package main

import (
	"github.com/mixbee/mixbee-crypto/keypair"
	s "github.com/mixbee/mixbee-crypto/signature"
	"log"
)

type Account struct {
	PrivateKey keypair.PrivateKey
	PublicKey  keypair.PublicKey
	SigScheme  s.SignatureScheme
}

func main()  {
	names := []string{
		"",   // 默认使用 SHA256withECDSA
		"SHA224withECDSA",
		"SHA256withECDSA",
		"SHA384withECDSA",
		"SHA512withECDSA",
		"SHA3-224withECDSA",
		"SHA3-256withECDSA",
		"SHA3-384withECDSA",
		"SHA3-512withECDSA",
		"RIPEMD160withECDSA",
		"SM3withSM2",
		"SHA512withEdDSA",
	}

	accounts := make([]*Account, len(names))
	for k,v := range names {
		accounts[k] = NewAccount(v)
		log.Println("accounts[K]", accounts[k])
	}


}

func NewAccount(encrypt string) *Account  {
	/**
	对 PK_ECDSA， PK_SM2， PK_EDDSA 三种算法的支持
	PK_ECDSA (P224, P256, P384, P521)

	PK_SM2 (类似ECDSA， SM2P256V1)

	PK_EDDSA (ED25519)

	 */

	var pkAlgorithm keypair.KeyType
	var params interface{}
	var scheme s.SignatureScheme
	var err error
	if "" != encrypt {
		scheme, err = s.GetScheme(encrypt)
	} else {
		scheme = s.SHA256withECDSA
	}
	if err != nil {
		log.Println("unknown signature scheme, use SHA256withECDSA as default.")
		scheme = s.SHA256withECDSA
	}

	switch scheme {
	case s.SHA224withECDSA, s.SHA3_224withECDSA:
		pkAlgorithm = keypair.PK_ECDSA  // PK_ECDSA
		params = keypair.P224
	case s.SHA256withECDSA, s.SHA3_256withECDSA, s.RIPEMD160withECDSA:
		pkAlgorithm = keypair.PK_ECDSA  // PK_ECDSA
		params = keypair.P256
	case s.SHA384withECDSA, s.SHA3_384withECDSA:
		pkAlgorithm = keypair.PK_ECDSA  // PK_ECDSA
		params = keypair.P384
	case s.SHA512withECDSA, s.SHA3_512withECDSA:
		pkAlgorithm = keypair.PK_ECDSA  // PK_ECDSA
		params = keypair.P521
	case s.SM3withSM2:
		pkAlgorithm = keypair.PK_SM2   // PK_SM2
		params = keypair.SM2P256V1
	case s.SHA512withEDDSA:
		pkAlgorithm = keypair.PK_EDDSA  //PK_EDDSA
		params = keypair.ED25519
	}

	pri, pub, _ := keypair.GenerateKeyPair(pkAlgorithm, params)
	buf := keypair.SerializePublicKey(pub)
	// 返序列化的结果
	log.Println("SerializePublicKey ", buf)

	return &Account{
		PrivateKey: pri,
		PublicKey: pub,
		SigScheme: s.SHA256withECDSA,
	}
}
