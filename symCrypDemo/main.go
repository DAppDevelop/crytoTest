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
	//tripkey := []byte("123456789012345678901234")
	//cryted := symCryp.TripleDesEncrypt([]byte("hello yancey222"), tripkey)
	//fmt.Println(hex.EncodeToString(cryted))
	//origData := symCryp.TripleDesDecrypt(cryted, tripkey)
	//fmt.Println(string(origData))

	/* AES CBC 秘钥长度，要么16,或者 24, 或者32 */
	//aesKey := []byte("123456789012345678901234")
	//cryted := symCryp.AESCBCEncrypt([]byte("Hi goland"), aesKey)
	//fmt.Println(hex.EncodeToString(cryted))
	//origData := symCryp.AESCBCDecrypt(cryted, aesKey)
	//fmt.Println(string(origData))

	/* AES CTR 秘钥长度，要么16,或者 24, 或者32 */
	//aesKey := []byte("12345678901234567890123456789012")
	//cryted := symCryp.AESCTREncrypt([]byte("hello work"), aesKey)
	//fmt.Println(hex.EncodeToString(cryted))
	//origData := symCryp.AESCTRDecrypt(cryted, aesKey)
	//fmt.Println(string(origData))

	/* AES CFB 秘钥长度，要么16,或者 24, 或者32 */
	//aesKey := []byte("12345678901234567890123456789012")
	//cryted := symCryp.AESCFBEncrypt([]byte("hello work"), aesKey)
	//fmt.Println(hex.EncodeToString(cryted))
	//origData := symCryp.AESCFBDecrypt(cryted, aesKey)
	//fmt.Println(string(origData))

	/* AES OFB 秘钥长度，要么16,或者 24, 或者32 */
	aesKey := []byte("12345678901234567890123456789012")
	cryted := symCryp.AESOFBEncrypt([]byte("hello work"), aesKey)
	fmt.Println(hex.EncodeToString(cryted))
	origData := symCryp.AESOFBDecrypt(cryted, aesKey)
	fmt.Println(string(origData))

}


