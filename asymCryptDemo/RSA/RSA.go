package RSA

import (
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"crypto/rand"
	"crypto/md5"
	"fmt"
	"encoding/hex"
	"crypto"
)

//生明私钥
//私钥只能使用，而且要保存好，避免丢失，私钥可以用做解密，也可以用作数字签名
var priKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCe0Y0YiZOrruG3O9N5sovpqmZD6DZIbnyBjCZZ88SVFJop+rDQ
B92lsLXZHCk29etigrhzr4VUk6ERjH25SwasVnutns93W3LLsmfhMV1uVsclPMgz
IqkDni9OVIAAWqn0ZOkjOTtyUzzhiqp24kb0Wqi7KDhnFtZ+YTlsbAlM3wIDAQAB
AoGARVlJXCKO6dO2WfV0tVpCf+jZOOPH+D7OfR7+jB7GgzZ4zsXZuS0GGtibv07t
rEMb4mskMde9x52jIm+PYn6hTaVlOqblRNybdvk8poioh0qQpoZsLYJy2c0/aZ4V
0kP6JmJSMe8R6UkHPSM89Z8KJ7ji+6Bv8WpZF3MCJXhgRKkCQQDMhyFfasMUwPyH
qp0pE48wGUCu+TZV0NFrfIVHJjrfSIvx6bVbm43WblCF/NultCCUQfLZgu6WDb4m
lJ1pKmc1AkEAxsmQLHcErnZOVUwquyhsjjDbhKIElhfqDww3kDIqX6v+iVbKeDVN
C7gewlXyzCVFYGDIworD3kWAPUcGuHZiQwJBAI2WapL8fKpMY0Wj5gJ+qNx6Tt4S
ZfwIgEFxxW4Y2B6kwUSqLsOJLyqn2ZS4FHJk/TzFXtIXIwW748wfi8027pUCQHIs
SLNRNI4jgwA4u/48zISqiRpXl/zBBXzZDnyyY2YJuisVfzqlmnfVq00A4m/gJEWj
sQsTekYKcwo+5hxCWlMCQCW7IpUCbVCuclMRZF7RwkOX87t9BLbSfb7Es+OLupgW
nndJIWMi8xYFKvLCXn+jVh8k/lGaqoDcJJLPVL6OP7s=
-----END RSA PRIVATE KEY-----`)

//声明公钥
//公钥可以公开给所有人使用，可以用作加密，可以用作验签
var pubKey = []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCe0Y0YiZOrruG3O9N5sovpqmZD
6DZIbnyBjCZZ88SVFJop+rDQB92lsLXZHCk29etigrhzr4VUk6ERjH25SwasVnut
ns93W3LLsmfhMV1uVsclPMgzIqkDni9OVIAAWqn0ZOkjOTtyUzzhiqp24kb0Wqi7
KDhnFtZ+YTlsbAlM3wIDAQAB
-----END PUBLIC KEY-----`)

var privKey2 *rsa.PrivateKey
var pubKey2 rsa.PublicKey

func RSAEncrypt(origData []byte) []byte {
	//公钥加密
	block, _ := pem.Decode(pubKey)
	//解析公钥
	pubInterface, _ := x509.ParsePKIXPublicKey(block.Bytes)
	//加载公钥
	pub := pubInterface.(*rsa.PublicKey)
	//加密明文
	bits, _ := rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
	//bits为加密的密文
	return bits
}

func RSADecrypt(origData []byte) []byte {
	block, _ := pem.Decode(priKey)
	//解析私钥
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	//解密
	bts, _ := rsa.DecryptPKCS1v15(rand.Reader, priv, origData)

	return bts
}

func RSAEncrypt2(origData []byte) []byte {
	//生成公私钥
	privKey2, _ = rsa.GenerateKey(rand.Reader, 1024)
	pubKey2 = privKey2.PublicKey

	cipherTxt, _ := rsa.EncryptOAEP(md5.New(), rand.Reader, &pubKey2, origData, nil)
	fmt.Println(hex.EncodeToString(cipherTxt))
	return cipherTxt
}

func RSADecrypt2(cipherTxt []byte) []byte {
	origData, _ := rsa.DecryptOAEP(md5.New(), rand.Reader, privKey2, cipherTxt, nil)
	fmt.Println(string(origData))
	return origData
}

//rsa 生成签名
func RSASign(origData []byte) []byte {
	//生成公私钥
	privKey2, _ = rsa.GenerateKey(rand.Reader, 1024)
	pubKey2 = privKey2.PublicKey

	//将要签名的数据散列
	h := md5.New()
	h.Write(origData)
	hashed := h.Sum(nil)

	//通过pss函数，实现对明文hello world的签名
	//pss函数可以添加杂质，能够使得签名过程更安全
	opts := rsa.PSSOptions{rsa.PSSSaltLengthAuto, crypto.MD5}
	//实现签名
	sign, _ := rsa.SignPSS(rand.Reader, privKey2, crypto.MD5, hashed, &opts)
	sign = append(sign, hashed...)
	fmt.Println(hex.EncodeToString(sign))
	return sign
}

//rsa 验证签名
func RSAVerifySign(sign []byte) bool  {
	hashed := sign[len(sign)-md5.Size:]
	sign = sign[:len(sign)-md5.Size]
	opts := rsa.PSSOptions{rsa.PSSSaltLengthAuto, crypto.MD5}
	err := rsa.VerifyPSS(&pubKey2, crypto.MD5, hashed, sign, &opts)
	if err != nil {
		return false
	}
	fmt.Println("验签成功！！")
	return true
}