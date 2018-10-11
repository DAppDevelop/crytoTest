package pad

import "bytes"

//PKCS5Padding 要求分组长度只能为8
func PKCS5Padding(cipherTxt []byte) []byte {
	return pkcsPadding(cipherTxt, 8)
}
//PKCS7Padding 要求分组的长度可以[1-255]
func PKCS7Padding(cipherTxt []byte, blockSize int) []byte {
	return pkcsPadding(cipherTxt, blockSize)
}

//补码
func pkcsPadding(cipherTxt []byte, blockSize int) []byte {
	//计算要添加的数字
	padNumber := blockSize - len(cipherTxt)%blockSize
	//重复padNumber个padNUmber
	padTxt := bytes.Repeat([]byte{byte(padNumber)},padNumber);
	//将padTxt 添加到cipherTxt后
	cipherTxt = append(cipherTxt, padTxt...)

	return cipherTxt
}

//去码
func PKCSUnPadding(cipherTxt []byte) []byte {
	//获得补码的数字
	l := len(cipherTxt)
	padNumber := int(cipherTxt[l-1])
	//删除补码数字个补码数字
	return cipherTxt[:l-padNumber]
}
