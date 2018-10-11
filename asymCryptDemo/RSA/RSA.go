package RSA

import (
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"crypto/rand"
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