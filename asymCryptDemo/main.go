package main

import (
	"crytoTest/asymCryptDemo/ECC"
)

func main() {
	tx := []byte("rsa hello")

	/* RSA 外部公私钥进行加密解密
	//cipherTxt := RSA.RSAEncrypt(tx)
	//fmt.Println(hex.EncodeToString(cipherTxt))
	//
	//origTxt := RSA.RSADecrypt(cipherTxt)
	//fmt.Println(string(origTxt))

	/* 通过RSA实现数据的加密和解密 */
	//cipherTxt := RSA.RSAEncrypt2(tx)
	//
	//_ = RSA.RSADecrypt2(cipherTxt)

	/* 通过RSA数字签名及验签 */
	//sign := RSA.RSASign(tx)
	//_ = RSA.RSAVerifySign(sign)

	/* 通过DSA实现数据的加密和解密 */
	//sign := DSA.DSASign(tx)
	//_ = DSA.DSAVerify(sign, tx)

	/* 通过ECC实现数据的加密和解密 */
	sign := ECC.Sign(tx)
	_ = ECC.Verify(sign, tx)

}


