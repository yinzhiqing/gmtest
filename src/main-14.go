package main
import (
	"fmt"
	"log"
	"io/ioutil"
	"os"
	"crypto/rand"
    //"bytes"
)
import "github.com/tjfoc/gmsm/sm2"
import "github.com/tjfoc/gmsm/sm3"
import "github.com/tjfoc/gmsm/x509"

func openssl() {
	msg := []byte("test")

    /*
    priv, err := ioutil.ReadFile("priv.pem")                // 从文件读取数据
	if err != nil {
		log.Fatal(err)
	}
    */
    priv, err := sm2.GenerateKey(rand.Reader) // 生成密钥对
	fmt.Println(priv)
	if err != nil {
		log.Fatal(err)
	}
	privPem, err := x509.WritePrivateKeyToPem(priv, nil) // 生成密钥文件
	if err != nil {
		log.Fatal(err)
	}
	privKey, err := x509.ReadPrivateKeyFromPem(privPem, nil) // 读取密钥
	if err != nil {
		log.Fatal(err)
	}

    fmt.Printf("is sm2 privkey: %v\n", privKey.Curve.IsOnCurve(privKey.X, privKey.Y)) // 验证是否为sm2的曲线

    pubKey := &privKey.PublicKey

	//ok, err := sm2.WritePrivateKeytoPem("priv-wt.pem", privKey, nil) // 生成密钥文件
	//if ok != true {
	//	log.Fatal(err)
	//}

	//pubKey, _ := priv.Public().(*sm2.PublicKey)
	//ok, err = sm2.WritePublicKeytoPem("pub.pem", pubKey, nil) // 生成公钥文件
	//if ok != true {
	//	log.Fatal(err)
	//}

	//err = ioutil.WriteFile("ifile", msg, os.FileMode(0644)) // 生成测试文件
	//if err != nil {
	//	log.Fatal(err)
	//}
	//privKey, err := sm2.ReadPrivateKeyFromPem("priv.pem", nil) // 读取密钥
	//if err != nil {
	//	log.Fatal(err)
	//}
	//pubKey, err = sm2.ReadPublicKeyFromPem("pub.pem", nil) // 读取公钥
	//if err != nil {
	//	log.Fatal(err)
	//}

	msg, _ = ioutil.ReadFile("msg.txt")                // 从文件读取数据
	sign, err := privKey.Sign(rand.Reader, msg, nil) // 签名
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("ofile", sign, os.FileMode(0644))
	if err != nil {
		log.Fatal(err)
	}
	//signdata, _ := ioutil.ReadFile("ofile")
    signdata, _ := ioutil.ReadFile("sm2.sign")
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

func byteToString(b []byte) string {
    ret := ""
    for i := 0; i < len(b); i++ {
        ret += fmt.Sprintf("%02x", b[i])
    }
    fmt.Println("ret = ", ret)
    return ret
}
func gen_hash() {
    msg := []byte("test")
    err := ioutil.WriteFile("ifile", msg, os.FileMode(0644)) // 生成测试文件
    if err != nil {
        log.Fatal(err)
    }
    msg, err = ioutil.ReadFile("msg.txt")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("msg: %s\n", msg)
    hash1 := sm3.Sm3Sum(msg)
    fmt.Println(hash1)
    fmt.Printf("sm3sum: %s\n", byteToString(hash1))
}
func main() {
    fmt.Printf("version 1.4")
    //tjfoc_sm2()
    gen_hash()

    openssl()
}
