package tbls

import (
	"fmt"
	"github.com/zhenhanyijiu/tbls/libbls/bls/bls"
)

const (
	GroupSize = 4
)

func Init() error {
	return bls.Init(bls.CurveFp254BNb)
}

type BlsSharePoint struct {
	SignShares     map[string]string `json:"sign_shares"`
	ThresholdValue int               `json:"threshold_value"`
}
type BlsGroupPoint struct {
	blsMembers     []BlsMember
	ThresholdValue int
}

func InitBlsGroup(groupSize int, blsGroupPoint *BlsGroupPoint) {
	bls.Init(bls.CurveFp254BNb)
	if groupSize <= 0 {
		fmt.Println("GroupSize is invalid!")
	}
	thresValue := groupSize/2 + 1
	groupMemberIDs := make([]string, groupSize)
	receiveCommitments := map[string][]string{}

	simBlsMembers := make([]BlsMember, groupSize)
	//generate groupsize bls member
	for i := 0; i < groupSize; i++ {
		simBlsMembers[i] = RandBlsMember()
		groupMemberIDs[i] = simBlsMembers[i].memberID
		simBlsMembers[i].receiveSecretShares = make([]string, groupSize)
	}

	for i := 0; i < groupSize; i++ {
		//generate polynomial coefficient
		simBlsMembers[i].polyCoeffs = make([]string, thresValue)
		polyCoeffs := simBlsMembers[i].priva0.GetMasterSecretKey(thresValue)
		for index, coeff := range polyCoeffs {
			simBlsMembers[i].polyCoeffs[index] = coeff.GetHexString()
		}
		//generate commitment for polynomial coeefficient
		simBlsMembers[i].commitment = make([]string, thresValue)
		coeffComs := bls.GetMasterPublicKey(polyCoeffs)
		for index, com := range coeffComs {
			simBlsMembers[i].commitment[index] = com.GetHexString()
		}
		receiveCommitments[groupMemberIDs[i]] = simBlsMembers[i].commitment

		//generate secret shares
		var targetID bls.ID
		var sk bls.SecretKey
		secShares := make([]string, groupSize)
		for i := 0; i < groupSize; i++ {
			targetID.SetHexString(groupMemberIDs[i])
			if thresValue == 1 {
				secShares[i] = simBlsMembers[i].priva0.GetHexString()
			} else {
				sk.Set(polyCoeffs, &targetID)
				secShares[i] = sk.GetHexString()
			}
		}
		simBlsMembers[i].secretShares = secShares
	}

	//DKG,receive secret shares
	for i := 0; i < groupSize; i++ {
		for index, share := range simBlsMembers[i].secretShares {
			simBlsMembers[index].receiveSecretShares[i] = share
		}
	}

	//generate group public key
	pks := make([]bls.PublicKey, groupSize)
	i := 0
	for _, commitment := range receiveCommitments {
		var pk bls.PublicKey
		pk.SetHexString(commitment[0])
		pks[i] = pk
		i++
	}
	gpk := GenGroupPubKey(pks)

	//generate public key aggregate
	pubKeyAggs := GenPubKeyAggerate(&receiveCommitments, thresValue)

	//generate secret key aggregate
	for i := 0; i < groupSize; i++ {
		secKeys := make([]bls.SecretKey, thresValue)
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
	}
	blsGroupPoint.blsMembers = simBlsMembers
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

func GenBlsSignShares(blsGroupPoint *BlsGroupPoint, height int64) (*BlsSharePoint, string, string) {
	bls.Init(bls.CurveFp254BNb)
	if height < 0 {
		fmt.Println("height is invalid!")
		return nil, "ThresholdSign", "RandSeed"
	}
	initMessage := "201812121348"
	nextMessge := initMessage
	groupSize := len(blsGroupPoint.blsMembers)
	signShares := make(map[string]string, groupSize)
	var thresSign string
	var randSeed string
	for heig := 0; int64(heig) <= height; heig++ {

		if heig > 0 {
			nextMessge = thresSign + randSeed
		}
		for _, blsMember := range blsGroupPoint.blsMembers {
			var secretAgg bls.SecretKey
			secretAgg.SetHexString(blsMember.secretAggregate)
			signShares[blsMember.memberID] = secretAgg.Sign(nextMessge).GetHexString()
		}

		thresSign, _ = GenThresholdSign(signShares)
		randSeed = GenerateSeed(thresSign)
	}

	return &BlsSharePoint{
		SignShares:     signShares,
		ThresholdValue: blsGroupPoint.ThresholdValue,
	}, thresSign, randSeed
}

func GenThresholdSign(signShares map[string]string) (string, error) {
	bls.Init(bls.CurveFp254BNb)
	signVec := []string{}
	memberIDVec := []string{}
	for memberID, signShare := range signShares {
		memberIDVec = append(memberIDVec, memberID)
		signVec = append(signVec, signShare)
	}
	return SigRecover(signVec, memberIDVec), nil
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
