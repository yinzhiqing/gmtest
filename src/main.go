package main
import (
    "bytes"
	"fmt"
	"log"
	"io/ioutil"
	"os"
	"crypto/rand"
)
import "github.com/tjfoc/gmsm/sm2"

func tjfoc_sm2() {
    //priv, err := sm2.GenerateKey() // 生成密钥对
	priv, err := sm2.ReadPrivateKeyFromPem("priv.pem", nil) // 读取密钥
	if err != nil {
		log.Fatal(err)
	}
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("priv: %x", priv)
    msg := []byte("Tongji Fintech Research Institute")
    pub := &priv.PublicKey
    ciphertxt, err := pub.Encrypt(msg)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("pub: %x", pub)
    fmt.Println("加密结果:%x\n",ciphertxt)
    plaintxt,err :=  priv.Decrypt(ciphertxt)
    if err != nil {
        log.Fatal(err)
    }
    if !bytes.Equal(msg,plaintxt){
        log.Fatal("原文不匹配")
    }

    r,s,err := sm2.Sign(priv, msg)
    if err != nil {
        log.Fatal(err)
    }
    isok := sm2.Verify(pub,msg,r,s)
    fmt.Printf("Verified: %v\n", isok)
    fmt.Println("hello !")
}

func openssl() {

	msg := []byte("test")
	privKey, err := sm2.ReadPrivateKeyFromPem("priv.pem", nil) // 读取密钥
	if err != nil {
		log.Fatal(err)
	}
    pubKey := &privKey.PublicKey

    /*
	ok, err := sm2.WritePrivateKeytoPem("priv-wt.pem", privKey, nil) // 生成密钥文件
	if ok != true {
		log.Fatal(err)
	}

	pubKey, _ := priv.Public().(*sm2.PublicKey)
	ok, err = sm2.WritePublicKeytoPem("pub.pem", pubKey, nil) // 生成公钥文件
	if ok != true {
		log.Fatal(err)
	}

	err = ioutil.WriteFile("ifile", msg, os.FileMode(0644)) // 生成测试文件
	if err != nil {
		log.Fatal(err)
	}
	privKey, err := sm2.ReadPrivateKeyFromPem("priv.pem", nil) // 读取密钥
	if err != nil {
		log.Fatal(err)
	}
	pubKey, err = sm2.ReadPublicKeyFromPem("pub.pem", nil) // 读取公钥
	if err != nil {
		log.Fatal(err)
	}
    */

	msg, _ = ioutil.ReadFile("plan.txt")                // 从文件读取数据
	sign, err := privKey.Sign(rand.Reader, msg, nil) // 签名
	sign, err = privKey.SignDataToSignDigit(nil, msg, nil) // 签名
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("ofile", sign, os.FileMode(0644))
	if err != nil {
		log.Fatal(err)
	}
	//signdata, _ := ioutil.ReadFile("ofile")
    signdata, _ := ioutil.ReadFile("sm2_file.sign")
    ok := privKey.Verify(msg, signdata) // 密钥验证
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}
	ok = pubKey.Verify(msg, signdata) // 公钥验证
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}
}

func main() {
    //tjfoc_sm2()
    openssl()
}
