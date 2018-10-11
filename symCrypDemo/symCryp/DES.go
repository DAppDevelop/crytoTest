package symCryp

import (
	"crypto/des"
	"log"
	"crypto/cipher"
	"crytoTest/symCrypDemo/pad"
	"io"
	"crypto/rand"
)

//DES加密
func DESEncrypt(origData []byte, key []byte) []byte {
	//DES加密中key长度必须为8
	block, err := des.NewCipher(key)//生成加密用的block
	if err != nil {
		log.Panic(err)
	}
	//补码
	origData = pad.PKCS5Padding(origData)
	//加密明文
	crypted := make([]byte, block.BlockSize() + len(origData))
	//向iv切片数组初始化rand.Reader（随机内存流）
	iv := crypted[:block.BlockSize()]
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		panic(err)
	}

	//设置加密模式CBC （还有ECB,CBC,CFB,OFB,CTR) 部分模式(ECB和CBC)需要最后一块在加密前进行填充
	blockMode := cipher.NewCBCEncrypter(block, iv)

	blockMode.CryptBlocks(crypted[block.BlockSize():], origData)

	return crypted
}


//DES解密
func DESDectrypt(cryted []byte, key []byte) []byte  {
	block, err := des.NewCipher(key)
	if err != nil {
		log.Panic(err)
	}
	iv := cryted[:block.BlockSize()]
	cryted = cryted[block.BlockSize():]

	//blockMode设置成对应的模式
	blockMode := cipher.NewCBCDecrypter(block, iv)

	origData := make([]byte, len(cryted))

	blockMode.CryptBlocks(origData, cryted)

	//去码
	origData = pad.PKCSUnPadding(origData)

	return origData
}

//3DES 加密
func TripleDesEncrypt(origData []byte, key []byte) []byte {
	//3DES加密中key的长度必须24
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		log.Panic(err)
	}

	//补码
	origData = pad.PKCS5Padding(origData)
	crypted := make([]byte, block.BlockSize() + len(origData))
	//向iv切片数组初始化rand.Reader（随机内存流）
	iv := crypted[:block.BlockSize()]
	io.ReadFull(rand.Reader, iv)

	blockMode := cipher.NewCBCEncrypter(block, iv)

	blockMode.CryptBlocks(crypted[block.BlockSize():], origData)

	return crypted
}


//3DES 解密
func TripleDesDecrypt(cryted []byte, key []byte) []byte  {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		log.Panic(err)
	}

	iv := cryted[:block.BlockSize()]
	cryted = cryted[block.BlockSize():]

	//blockMode设置成对应的模式
	blockMode := cipher.NewCBCDecrypter(block, iv)

	origData := make([]byte, len(cryted))

	blockMode.CryptBlocks(origData, cryted)
	//去码
	origData = pad.PKCSUnPadding(origData)

	return origData
}