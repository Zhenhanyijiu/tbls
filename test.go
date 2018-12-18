package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/zhenhanyijiu/tbls/tbls"
	"io"
)

var (
	groupSize        = 6
	thresholdValue   = groupSize/2 + 1
	randSignShareNum = 4
)

func main() {
	var blsGroupPoint tbls.BlsGroupPoint
	tbls.InitBlsGroup(groupSize, &blsGroupPoint)
	for index, blsMember := range blsGroupPoint.BlsMembers {
		fmt.Println("index==", index)
		blsMember.GetBlsMember()
	}
	blsSharePoint, thresSign, randSeed := tbls.GenBlsSignShares(&blsGroupPoint, 0)
	signShare := make([]string, randSignShareNum)
	signMember := make([]string, randSignShareNum)

	for i := 0; i < randSignShareNum; i++ {
		signShare[i] = blsSharePoint.SignShares[i]
		signMember[i] = blsSharePoint.SignMemberIDs[i]
	}
	thresSign1, _ := tbls.GenThresholdSign(signShare, signMember)
	fmt.Println("\nSignShares=====", blsSharePoint.SignShares)
	fmt.Println("ThresholdSign==", thresSign)
	fmt.Println("ThresholdSign1=", thresSign1)
	fmt.Println("randSees=======", randSeed)
	signShare, signMember, resultCombine, err := tbls.RandChoiceShares(blsSharePoint, randSignShareNum, thresholdValue)
	if err == nil {
		fmt.Println("resultCombine=", resultCombine)
		thresSign1, _ := tbls.GenThresholdSign(signShare, signMember)
		fmt.Println("ThresholdSign1=", thresSign1, "\n")

		for i := 0; i < len(resultCombine); i++ {
			for j := 0; j < randSignShareNum; j++ {
				signShare[j] = blsSharePoint.SignShares[resultCombine[0][j]]
				signMember[j] = blsSharePoint.SignMemberIDs[resultCombine[0][j]]
			}
			thresSign1, _ := tbls.GenThresholdSign(signShare, signMember)
			fmt.Println("ThresholdSign1=", thresSign1)
		}
	} else {
		fmt.Println("threshold signature test failed")
	}
	//combine.Test10Base()
	buf := make([]byte, 32)
	n, err := io.ReadFull(rand.Reader, buf)
	fmt.Println("n=", n, "err=", err, "buf=", buf)
	text1 := []byte("123")
	text2 := []byte("456")
	h1 := sha256.New()
	h1.Write(text1)
	h1.Write(text2)
	res1 := h1.Sum(nil)
	fmt.Println("res1=", res1)

	h2 := sha256.New()
	tx3 := []byte("123456")
	h2.Write(tx3)
	//sha256.Write(text2)
	res2 := h2.Sum(nil)
	fmt.Println("res2=", res2)

	h3 := sha256.New()
	h3.Write(text1)
	//h3.Write(text2)
	res3 := h3.Sum(nil)
	fmt.Println("res3=", res3)

}
