package main

import (
	"crytoTest/symCrypDemo/symCryp"
	"fmt"
	"encoding/hex"
)

func main() {
	/* DES key长度必须为8 */
	//key := []byte("12345678")
	//cryted := symCryp.DESEncrypt([]byte("hello yancey"), key)
	//fmt.Println(hex.EncodeToString(cryted))
	//origData := symCryp.DESDectrypt(cryted, key)
	//fmt.Println(string(origData))

	/* 3DES 长度必须为24*/
	tripkey := []byte("123456789012345678901234")
	cryted := symCryp.TripleDesEncrypt([]byte("hello yancey222"), tripkey)
	fmt.Println(hex.EncodeToString(cryted))
	origData := symCryp.TripleDesDecrypt(cryted, tripkey)
	fmt.Println(string(origData))

	/* AES 秘钥长度，要么16,或者 24, 或者32 */
	//aesKey := []byte("1234567890123456")
	//cryted := symCryp.AESEncrypt([]byte("li liyHe"), aesKey)
	//fmt.Println(hex.EncodeToString(cryted))
	//origData := symCryp.AESDecrypt(cryted, aesKey)
	//fmt.Println(string(origData))

}


