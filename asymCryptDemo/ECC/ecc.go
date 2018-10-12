package ECC

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"fmt"
)

var priv *ecdsa.PrivateKey
var pub ecdsa.PublicKey

func Sign(message []byte) []byte {
	//生成私钥
	priv, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	//创建公钥
	pub = priv.PublicKey

	//散列明文
	hashed := sha256.Sum256(message)

	//签名
	r, s , _ :=  ecdsa.Sign(rand.Reader, priv, hashed[:])

	//fmt.Println(len(r.Bytes()))
	//fmt.Println(len(s.Bytes()))
	//r, s 长度是一样的
	return append(r.Bytes(), s.Bytes()...)
}

func Verify(sign []byte, message []byte) bool {
	//获取R, S
	rByte := sign[:len(sign)/2]
	sByte := sign[len(sign)/2:]

	r := new(big.Int)
	r.SetBytes(rByte)

	s := new(big.Int)
	s.SetBytes(sByte)
	//散列明文
	hashed := sha256.Sum256(message)

	if ecdsa.Verify(&pub, hashed[:], r, s) {
		fmt.Println("ecc 验签成功")
		return true
	}

	return false

}