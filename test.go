package main

import (
	"./libbls/bls/bls"
	"fmt"
)

func main() {
	bls.Init(bls.CurveFp254BNb)
	var sk bls.SecretKey
	sk.SetByCSPRNG()
	fmt.Println("sk==>", sk.GetHexString())

}
