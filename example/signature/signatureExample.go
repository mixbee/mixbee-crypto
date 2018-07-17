package main


import (
	"github.com/mixbee/mixbee-crypto/keypair"
	s "github.com/mixbee/mixbee-crypto/signature"
	"log"
	"errors"
)



type Account struct {
	PrivateKey keypair.PrivateKey
	PublicKey  keypair.PublicKey
	SigScheme  s.SignatureScheme
}



func main()  {
	acc := NewAccount("")
	data := []byte{1, 2, 3}

	sig, err := Sign(*acc, data)
	if err != nil {
		log.Println("签名失败")
		return
	}
	// 对当个数据签名进行签名消息校验
	err = Verify(acc.PublicKey, data, sig)
	if err != nil {
		log.Println("验签失败")
		return
	}
	log.Println("验签成功")


	// 多重签名验证
	testVerifyMultiSignature()

}

func testVerifyMultiSignature()  {
	data := []byte{1, 2, 3}
	accs := make([]*Account, 0)
	pubkeys := make([]keypair.PublicKey, 0)

	N :=4
	for i:=0; i<N;i++ {
		// 生成 N 个秘钥对
		accs = append(accs, NewAccount(""))
	}

	sigs := make([][]byte, 0)

	for _,acc := range accs {
		sig, _ := Sign(*acc, data)
		sigs = append(sigs, sig)
		pubkeys = append(pubkeys, acc.PublicKey)
	}

	err1 := VerifyMultiSignature(data, pubkeys, N, sigs)
	if err1 != nil {
		log.Println("1  ---- 多重签名校验失败")
	} else {
		log.Println("1  ---- 多重签名成功")
	}


	pubkeys[0], pubkeys[1] = pubkeys[1], pubkeys[0]
	err2 := VerifyMultiSignature(data, pubkeys, N, sigs)
	if err2 != nil {
		log.Println("2 ---- 多重签名校验失败")
	} else {
		log.Println("2  ---- 多重签名成功")
	}

}


// 用账户私钥对数据加密
func Sign(account Account, data []byte) ([]byte, error) {
	signature, err := s.Sign(account.SigScheme, account.PrivateKey, data, nil)
	if err != nil {
		return nil, err
	}
	return s.Serialize(signature)

}

// 用gongyue对签名数据进行校验
func Verify(pubKey keypair.PublicKey, data, signature []byte) error {
	sigObj, err := s.Deserialize(signature)
	if err != nil {
		return errors.New("invalid signature data: " + err.Error())
	}
	if !s.Verify(pubKey, data, sigObj) {
		return errors.New("signature verification failed")
	}
	return nil
}


/**
	 mask      0~n,pubKeys                    0~m, sigs
 +--------++--------+                      +-------------+
 |        ||        |                      |             |
 |  false ||   0    <----------<+---------++     0       |
 +--------++--------+           |          +-------------+
 +--------++--------+           |          +-------------+
 |        ||        |           |          |             |
 |   true ||   1    <-----------+          |     1       |
 +--------++--------+           |          +-------------+
 +--------++--------+           |          +-------------+
 |        ||   2    |           |          |             |
 |   false||        <-----------+          |     2       |
 +--------++--------+           |          +-------------+
 +--------++--------+           |          +-------------+
 |   false||        |           |          |     3       |
 |        ||   3    |<----------+          |             |
 +--------++--------+                      +-------------+

   两层循环对签名数组做校验，对一组签名数据进行校验

 */
func VerifyMultiSignature(data []byte, keys []keypair.PublicKey, m int, sigs [][]byte) error {
	n := len(keys)
	if len(sigs) < m {
		return errors.New("not enough signatures in multi-signature")
	}

	// 未来标示当前key已经成功匹配，不做校验，提高更程序的执行效率
	mask := make([]bool, n)
	for i:=0; i<m ;i++  {
		valid := false

		sig,err := s.Deserialize(sigs[i])

		if err != nil {
			return errors.New("invalid signature data")
		}

		for j :=0;j < n ;j++  {
			if mask[j] {
				continue
			}
			if s.Verify(keys[j], data, sig) {
				mask[j] = true
				valid = true
				break
			}
		}

		if false == valid {
			return errors.New("multi-signature verification failed")
		}
	}
	return nil

}



// 生成公私钥对
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



