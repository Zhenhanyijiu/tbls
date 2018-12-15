package tbls

import (
	"fmt"
	"github.com/zhenhanyijiu/tbls/libbls/bls/bls"
	"github.com/zhenhanyijiu/tbls/tbls/combine"
)

const (
	GroupSize = 4
)

func Init() error {
	return bls.Init(bls.CurveFp254BNb)
}

type BlsSignSharePoint struct {
	SignShares     []string `json:"sign_shares"`
	SignMemberIDs  []string `json:"sign_menber_IDs"`
	ThresholdValue int      `json:"threshold_value"`
}
type BlsGroupPoint struct {
	BlsMembers     []BlsMember
	ThresholdValue int
}

func InitBlsGroup(groupSize int, blsGroupPoint *BlsGroupPoint) {
	bls.Init(bls.CurveFp254BNb)
	if groupSize <= 0 {
		fmt.Println("GroupSize is invalid!")
	}
	thresValue := groupSize/2 + 1
	groupMemberIDs := make([]string, groupSize)
	receiveCommitments := make(map[string][]string, groupSize)
	simBlsMembers := make([]BlsMember, groupSize)

	//generate groupsize bls member
	for i := 0; i < groupSize; i++ {
		simBlsMembers[i] = RandBlsMember()
		groupMemberIDs[i] = simBlsMembers[i].memberID
		simBlsMembers[i].receiveSecretShares = make([]string, groupSize)
	}

	//output
	fmt.Println("ThresholdValue=", thresValue)
	for i := 0; i < groupSize; i++ {
		//fmt.Println("simBlsMembers[i]", "index=", i, "memberID=", simBlsMembers[i].memberID, "priva0=", simBlsMembers[i].priva0.GetHexString())
	}

	for i := 0; i < groupSize; i++ {
		//generate polynomial coefficient
		simBlsMembers[i].polyCoeffs = make([]string, thresValue)
		polyCoeffs := simBlsMembers[i].priva0.GetMasterSecretKey(thresValue)
		for index, coeff := range polyCoeffs {
			simBlsMembers[i].polyCoeffs[index] = coeff.GetHexString()
		}
		//for index, coeff := range simBlsMembers[i].polyCoeffs {
		//	//fmt.Println("simBlsMembers[i]", "index=", i, "i=", index, "ai=", coeff)
		//}
		//generate commitment for polynomial coeefficient
		simBlsMembers[i].commitment = make([]string, thresValue)
		coeffComs := bls.GetMasterPublicKey(polyCoeffs)
		for index, com := range coeffComs {
			simBlsMembers[i].commitment[index] = com.GetHexString()
		}
		receiveCommitments[simBlsMembers[i].memberID] = simBlsMembers[i].commitment

		//fmt.Println("memberID=", simBlsMembers[i].memberID, "commitment", receiveCommitments[simBlsMembers[i].memberID])

		//generate secret shares
		var targetID bls.ID
		var sk bls.SecretKey
		secShares := make([]string, groupSize)
		for j := 0; j < groupSize; j++ {
			targetID.SetHexString(groupMemberIDs[j])
			if thresValue == 1 {
				secShares[j] = simBlsMembers[j].priva0.GetHexString()
			} else {
				sk.Set(polyCoeffs, &targetID)
				secShares[j] = sk.GetHexString()
			}
		}
		simBlsMembers[i].secretShares = secShares

		//fmt.Println("simBlsMembers[i].secretShares==", simBlsMembers[i].secretShares)
	}

	//DKG,receive secret shares
	for i := 0; i < groupSize; i++ {
		for index, share := range simBlsMembers[i].secretShares {
			simBlsMembers[index].receiveSecretShares[i] = share
		}

	}

	for i := 0; i < groupSize; i++ {
		//fmt.Println("receiveSecretShares==", simBlsMembers[i].receiveSecretShares)
	}
	//generate group public key
	pks := []bls.PublicKey{}
	for _, commitment := range receiveCommitments {
		var pk bls.PublicKey
		pk.SetHexString(commitment[0])
		pks = append(pks, pk)
	}
	for i := 0; i < groupSize; i++ {
		//fmt.Println("pks==", pks[i].GetHexString())
	}

	gpk := GenGroupPubKey(pks)

	//generate public key aggregate
	pubKeyAggs := GenPubKeyAggerate(&receiveCommitments, thresValue)

	//generate secret key aggregate
	for i := 0; i < groupSize; i++ {
		secKeys := make([]bls.SecretKey, groupSize)
		for index, recShare := range simBlsMembers[i].receiveSecretShares {
			var secKey bls.SecretKey
			secKey.SetHexString(recShare)
			secKeys[index] = secKey
		}
		var secretAgg bls.SecretKey
		secretAgg = SeckeyAggregate(secKeys)
		simBlsMembers[i].secretAggregate = secretAgg.GetHexString()
		simBlsMembers[i].groupPubKey = gpk.GetHexString()
		simBlsMembers[i].pubKeyAggregates = pubKeyAggs
		//fmt.Println("secretAggregate==", simBlsMembers[i].secretAggregate)
		//fmt.Println("groupPubKey======", simBlsMembers[i].groupPubKey)
		//fmt.Println("pubKeyAggregates=", simBlsMembers[i].pubKeyAggregates)
	}
	blsGroupPoint.BlsMembers = simBlsMembers
	blsGroupPoint.ThresholdValue = thresValue
}

//generate pkAgg used for sig share verification
func GenPubKeyAggerate(receiveComsPoint *map[string][]string, thresValue int) map[string]string {
	var tempID bls.ID
	var tempPK bls.PublicKey

	pkSum := make([]bls.PublicKey, thresValue)
	for i := 0; i < thresValue; i++ {
		//initial pk for zero
		pkSum[i].SetHexString("0")
	}
	for _, commitment := range *receiveComsPoint {
		for index, com := range commitment {
			tempPK.SetHexString(com)
			pkSum[index].Add(&tempPK)
		}
	}

	pubKeyAgg := make(map[string]string, len(*receiveComsPoint))
	for memberID, _ := range *receiveComsPoint {
		tempID.SetHexString(memberID)

		if thresValue > 1 {
			tempPK.Set(pkSum, &tempID)
		} else {
			tempPK = pkSum[0]
		}
		pubKeyAgg[memberID] = tempPK.GetHexString()
	}
	return pubKeyAgg
}

func GenBlsSignShares(blsGroupPoint *BlsGroupPoint, height int64) (blsSignSharePoint *BlsSignSharePoint, thresSign string, randSeed string) {
	bls.Init(bls.CurveFp254BNb)
	if height < 0 {
		fmt.Println("height is invalid!")
		return nil, "ThresholdSign", "RandSeed"
	}
	initMessage := "201812121348"
	nextMessge := initMessage
	groupSize := len(blsGroupPoint.BlsMembers)
	signShares := make([]string, groupSize)
	signMemberIDs := make([]string, groupSize)
	for heig := 0; int64(heig) <= height; heig++ {

		if heig > 0 {
			nextMessge = thresSign + randSeed
		}
		for index, blsMember := range blsGroupPoint.BlsMembers {
			var secretAgg bls.SecretKey
			secretAgg.SetHexString(blsMember.secretAggregate)
			signShares[index] = secretAgg.Sign(nextMessge).GetHexString()
			signMemberIDs[index] = blsMember.memberID
		}

		thresSign, _ = GenThresholdSign(signShares, signMemberIDs)
		randSeed = GenerateSeed(thresSign)
	}

	blsSignSharePoint = &BlsSignSharePoint{
		SignShares:     signShares,
		SignMemberIDs:  signMemberIDs,
		ThresholdValue: blsGroupPoint.ThresholdValue,
	}
	return blsSignSharePoint, thresSign, randSeed
}

func GenThresholdSign(signShares []string, signMemberIDs []string) (string, error) {
	bls.Init(bls.CurveFp254BNb)
	//signVec := []string{}
	//memberIDVec := []string{}
	//for memberID, signShare := range signShares {
	//	memberIDVec = append(memberIDVec, memberID)
	//	signVec = append(signVec, signShare)
	//}
	return SigRecover(signShares, signMemberIDs), nil
}

func RandChoiceShares(blsSignSharePoint *BlsSignSharePoint, randSignShareNum int, thresValue int) (randSignShares []string, randSignMemberIDs []string, resultCombine [][]int, err error) {
	groupSize := len(blsSignSharePoint.SignShares)
	if randSignShareNum < thresValue || randSignShareNum > groupSize {
		//err := errors.New("Random choice sign shares number invalid!!")
		err := fmt.Errorf("Random choice sign shares number invalid!!")
		return nil, nil, nil, err
	}
	//combination
	randSignShares = make([]string, randSignShareNum)
	randSignMemberIDs = make([]string, randSignShareNum)
	numArray := make([]int, groupSize)
	for index, _ := range blsSignSharePoint.SignShares {
		numArray[index] = index
	}

	indexs := combine.CombineResult(groupSize, randSignShareNum)
	resultCombine = combine.FindNumsByIndexs(numArray, indexs)

	for i := 0; i < randSignShareNum; i++ {
		randSignShares[i] = blsSignSharePoint.SignShares[resultCombine[0][i]]
		randSignMemberIDs[i] = blsSignSharePoint.SignMemberIDs[resultCombine[0][i]]
	}
	return randSignShares, randSignMemberIDs, resultCombine, nil
}

type BlsMember struct {
	memberID            string
	priva0              bls.SecretKey
	polyCoeffs          []string
	commitment          []string
	secretShares        []string
	receiveSecretShares []string
	secretAggregate     string
	groupPubKey         string
	pubKeyAggregates    map[string]string
}

func (blsMember *BlsMember) GetBlsMember() {
	fmt.Println("memberID=============", blsMember.memberID)
	fmt.Println("priva0===============", blsMember.priva0.GetHexString())
	fmt.Println("polyCoeffs===========", blsMember.polyCoeffs)
	fmt.Println("commitment===========", blsMember.commitment)
	fmt.Println("secretShares=========", blsMember.secretShares)
	fmt.Println("receiveSecretShares==", blsMember.receiveSecretShares)
	fmt.Println("groupPubKey==========", blsMember.groupPubKey)
	fmt.Println("pubKeyAggregates=====", blsMember.pubKeyAggregates)
	fmt.Println("secretAggregate======", blsMember.secretAggregate)
}
func RandBlsMember() BlsMember {
	var priva0 bls.SecretKey
	priva0.SetByCSPRNG()
	pubkey := priva0.GetPublicKey()
	pkstr := pubkey.GetHexString()
	memberID := pkstr[2:42]
	return BlsMember{
		memberID: memberID,
		priva0:   priva0,
	}
}
