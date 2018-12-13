package main

import (
	"fmt"
	"github.com/zhenhanyijiu/tbls/tbls"
)

func main() {
	signShare, _ := tbls.GenBlsSignShares(4)
	seed, _ := tbls.GenSeedFromBls(signShare.SignShares)
	fmt.Println("seed==", seed)
}
