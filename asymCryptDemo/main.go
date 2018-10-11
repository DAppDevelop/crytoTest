package main

import (
	"crytoTest/asymCryptDemo/RSA"
	"fmt"
	"encoding/hex"
)

func main() {
	cipherTxt := RSA.RSAEncrypt([]byte("rsa hello yeah"))
	fmt.Println(hex.EncodeToString(cipherTxt))

	origTxt := RSA.RSADecrypt(cipherTxt)
	fmt.Println(string(origTxt))
}


