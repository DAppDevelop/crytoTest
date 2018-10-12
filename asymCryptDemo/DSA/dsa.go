package DSA

import (
	"crypto/dsa"
	"crypto/rand"
	"fmt"
	"math/big"
)

var priv dsa.PrivateKey
var pub dsa.PublicKey

//DSA只能被用于数字签名
func DSASign(message []byte) []byte {
	//设置私钥参数
	var param dsa.Parameters
	dsa.GenerateParameters(&param, rand.Reader, dsa.L1024N160)
	//创建私钥
	priv.Parameters = param

	//生产私钥
	dsa.GenerateKey(&priv, rand.Reader)

	//创建公钥
	pub = priv.PublicKey

	//签名
	r,s,_ := dsa.Sign(rand.Reader, &priv, message)


	return append(r.Bytes(), s.Bytes()...)
}

func DSAVerify(sign []byte, message []byte) bool {
	rByte := sign[:len(sign)/2]
	sByte := sign[len(sign)/2:]
	r := new(big.Int)
	r.SetBytes(rByte)

	s := new(big.Int)
	s.SetBytes(sByte)
	if dsa.Verify(&pub, message, r, s) {
		fmt.Println("验签成功！！")
		return true
	}

	return false
}
