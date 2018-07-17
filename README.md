# mixbee-crypto
mixbee-crypto SM2/3/4 library based on Golang




# 算法
## SM1 
为对称加密。其加密强度与AES相当。该算法不公开，调用该算法时，需要通过加密芯片的接口进行调用。

## SM2
> 为非对称加密，基于ECC。该算法已公开。由于该算法基于ECC，故其签名速度与秘钥生成速度都快于RSA。ECC 256位（SM2采用的就是ECC 256位的一种）安全强度比RSA 2048位高，但运算速度快于RSA。

用途：
* 签名、验签计算过程;  
* 加密、解密计算过程;
* 密钥协商计算过程。

## SM3 
消息摘要。可以用MD5作为对比理解。该算法已公开。校验结果为256位。
SM3杂凑算法是我国自主设计的密码杂凑算法，适用于商用密码应用中的数字签名和验证消息认证码的生成与验证以及随机数的生成，可满足多种密码应用的安全需求。为了保证杂凑算法的安全性，其产生的杂凑值的长度不应太短，例如MD5输出128比特杂凑值，输出长度太短，影响其安全性SHA-1算法的输出长度为160比特，SM3算法的输出长度为256比特，因此SM3算法的安全性要高于MD5算法和SHA-1算法。

## SM4
无线局域网标准的分组数据算法。对称加密，密钥长度和分组长度均为128位。


# 使用
具体用法可以参考项目中的 `example`文件中的代码

## `keyPair`秘钥对的使用
支持的算法：
* PK_ECDSA 
实现了 P224, P256, P384, P521

* PK_SM2  ()
SM2P256V1

* PK_EDDSA
ED25519


```
	pri, pub, _ := keypair.GenerateKeyPair(pkAlgorithm, params)

```

## 数据签名

```
// 数据签名
sig, err := signature.Sign(signature.SHA256withECDSA, private, msg, nil)

// 签名校验
ok := signature.Verify(public, msg, sig)

// 多重签名
VerifyMultiSignature(data , keys , m ,sigs)

```

多重签名的验签参考 `example/signature/signatureExample.go` 文件中的 `testVerifyMultiSignature`函数。


# License
Copyright (c) 2018 mixbee