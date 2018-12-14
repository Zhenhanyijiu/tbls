package main

import (
	"fmt"
	"github.com/zhenhanyijiu/tbls/tbls"
)

func main() {
	var blsGroupPoint tbls.BlsGroupPoint
	tbls.InitBlsGroup(4, &blsGroupPoint)
	for index, blsMember := range blsGroupPoint.BlsMembers {
		fmt.Println("index==", index)
		blsMember.GetBlsMember()
	}
	blsSharePoint, thresSign, randSeed := tbls.GenBlsSignShares(&blsGroupPoint, 0)
	signShare := map[string]string{}
	i := 0
	for memberID, signSh := range blsSharePoint.SignShares {
		if i < 3 {
			signShare[memberID] = signSh
		}
	}
	thresSign1, _ := tbls.GenThresholdSign(signShare)
	fmt.Println("\nSignShares=====", blsSharePoint.SignShares)
	fmt.Println("ThresholdSign==", thresSign)
	fmt.Println("ThresholdSign1=", thresSign1)
	fmt.Println("randSees=======", randSeed)
}
