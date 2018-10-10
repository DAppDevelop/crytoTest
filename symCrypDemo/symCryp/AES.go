package symCryp

import (
	"crypto/aes"
	"crypto/cipher"
	"crytoTest/symCrypDemo/pad"
)

func AESEncrypt(origData []byte, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	//按照公钥的长度进行分组补码
	origData = pad.PKCS7Padding(origData, block.BlockSize())

	blockMode := cipher.NewCBCEncrypter(block, key)

	cryted := make([]byte, len(origData))

	blockMode.CryptBlocks(cryted, origData)

	return cryted
}

func AESDecrypt(cryted []byte, key []byte) []byte {
	block, _ := aes.NewCipher(key)

	blockMode := cipher.NewCBCDecrypter(block, key)

	origData := make([]byte, len(cryted))
	blockMode.CryptBlocks(origData, cryted)

	origData = pad.PKCSUnPadding(origData)

	return origData
}
