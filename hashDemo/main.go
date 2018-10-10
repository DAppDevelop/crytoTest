package main

import (
	"fmt"
	"encoding/hex"
	"os"
	"io"
	"crypto/md5"
	"crypto/sha256"
	"golang.org/x/crypto/ripemd160"
)

func main() {
	md5Demo()
	sha256Demo()
	ripemd160Demo()
}

func md5Demo()  {
	fmt.Println("md5:")
	data := []byte("yancey chan")
	//第一种方法
	s := fmt.Sprintf("%x", md5.Sum(data));
	fmt.Println(s)

	//第二种方法
	h := md5.New()
	h.Write(data)
	s = hex.EncodeToString(h.Sum(nil))
	fmt.Println(s)

	//hash 文件
	h2 := md5.New()
	f, _ := os.Open("test.txt")
	io.Copy(h2, f)
	s = hex.EncodeToString(h2.Sum(nil))
	fmt.Println(s)
	fmt.Println()
}

func sha256Demo()  {
	fmt.Println("sha256:")
	data := []byte("yancey chan")
	//第一种方法
	s := fmt.Sprintf("%x", sha256.Sum256(data))
	fmt.Println(s)

	//第二种方法
	h := sha256.New()
	h.Write(data)
	s = hex.EncodeToString(h.Sum(nil))
	fmt.Println(s)

	//文件
	h2 := sha256.New()
	f,_ := os.Open("test.txt")
	io.Copy(h2,f)
	s = hex.EncodeToString(h2.Sum(nil))
	fmt.Println(s)

	fmt.Println()
}


//如果利用ripemd160加密，需要引入三方库
//引入三方法库的步骤
//1,进入gopath下，创建golang.org目录
//2,进入golang.org，创建x目录
//3,进入x目录，并在翻墙情况下,在github上下载三方库
//git clone https://github.com/golang/crypto.git


//以上的三个步骤可以通过一行命令在终端直接实现
//cd $GOPATH/src $ mkdir golang.org $ cd golang.org $ mkdir x $ cd x $ git clone https://github.com/golang/crypto.git
func ripemd160Demo()  {
	fmt.Println("ripemd160:")
	data := []byte("yancey chan")
	//只有一种写法
	h := ripemd160.New()
	h.Write(data)
	s := hex.EncodeToString(h.Sum(nil))
	fmt.Println(s)

	fmt.Println()

}



