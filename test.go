package main

import (
	"fmt"
	"github.com/zhenhanyijiu/tbls/tbls"
	"github.com/zhenhanyijiu/tbls/tbls/combine"
)

func main() {
	var blsGroupPoint tbls.BlsGroupPoint
	tbls.InitBlsGroup(4, &blsGroupPoint)
	for index, blsMember := range blsGroupPoint.BlsMembers {
		fmt.Println("index==", index)
		blsMember.GetBlsMember()
	}
	blsSharePoint, thresSign, randSeed := tbls.GenBlsSignShares(&blsGroupPoint, 0)
	signShare := make([]string, 3)
	signMember := make([]string, 3)

	for i := 0; i < 3; i++ {
		signShare[i] = blsSharePoint.SignShares[i]
		signMember[i] = blsSharePoint.SignMemberIDs[i]
	}
	thresSign1, _ := tbls.GenThresholdSign(signShare, signMember)
	fmt.Println("\nSignShares=====", blsSharePoint.SignShares)
	fmt.Println("ThresholdSign==", thresSign)
	fmt.Println("ThresholdSign1=", thresSign1)
	fmt.Println("randSees=======", randSeed)
	_, _, err := tbls.RandChoiceShares(blsSharePoint, 5, 3)
	fmt.Println("error=", err, "\n")

	combine.Test10Base()
}
