package symCryp

import (
	"crypto/aes"
	"crypto/cipher"
	"crytoTest/symCrypDemo/pad"
	"io"
	"crypto/rand"
)

func AESCBCEncrypt(origData []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	//按照公钥的长度进行分组补码
	origData = pad.PKCS7Padding(origData, block.BlockSize())

	cryted := make([]byte, aes.BlockSize + len(origData))
	//向iv切片数组初始化rand.Reader（随机内存流）
	iv := cryted[:block.BlockSize()]
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		panic(err)
	}
	blockMode := cipher.NewCBCEncrypter(block, iv)

	blockMode.CryptBlocks(cryted[aes.BlockSize:], origData)

	return cryted
}

func AESCBCDecrypt(cryted []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	iv := cryted[:block.BlockSize()]
	cryted = cryted[block.BlockSize():]

	blockMode := cipher.NewCBCDecrypter(block, iv)

	origData := make([]byte, len(cryted))
	blockMode.CryptBlocks(origData, cryted)

	origData = pad.PKCSUnPadding(origData)

	return origData
}

func AESCTREncrypt(origData []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	//CTR模式不用补码
	cryted := make([]byte, aes.BlockSize + len(origData))
	iv := cryted[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		panic(err)
	}

	stream := cipher.NewCTR(block, iv)

	//流处理
	stream.XORKeyStream(cryted[aes.BlockSize:], origData)

	return cryted
}

func AESCTRDecrypt(cryted []byte, key []byte)  []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	iv := cryted[:aes.BlockSize]
	cryted = cryted[aes.BlockSize:]

	origData := make([]byte, len(cryted))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(origData, cryted)

	return origData
}

func AESCFBEncrypt(origData []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	//CTR模式不用补码
	cryted := make([]byte, aes.BlockSize + len(origData))
	iv := cryted[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)

	//流处理
	stream.XORKeyStream(cryted[aes.BlockSize:], origData)

	return cryted
}

func AESCFBDecrypt(cryted []byte, key []byte)  []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	iv := cryted[:aes.BlockSize]
	cryted = cryted[aes.BlockSize:]

	origData := make([]byte, len(cryted))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(origData, cryted)

	return origData
}


func AESOFBEncrypt(origData []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	//CTR模式不用补码
	cryted := make([]byte, aes.BlockSize + len(origData))
	iv := cryted[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		panic(err)
	}

	stream := cipher.NewOFB(block, iv)

	//流处理
	stream.XORKeyStream(cryted[aes.BlockSize:], origData)

	return cryted
}

func AESOFBDecrypt(cryted []byte, key []byte)  []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	iv := cryted[:aes.BlockSize]
	cryted = cryted[aes.BlockSize:]

	origData := make([]byte, len(cryted))
	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(origData, cryted)

	return origData
}









