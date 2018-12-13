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

func InitBls(groupSize int, blsGroupPoint *BlsGroupPoint) {
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

func GenBlsSignShares(groupSize int) (*BlsSharePoint, error) {
	bls.Init(bls.CurveFp254BNb)
	thresValue := 0
	if groupSize == 2 {
		thresValue = 2
	} else {
		thresValue = (groupSize + 1) / 2
	}

	groupNodeID := make([]string, groupSize)
	receiveCommitment := map[string][]string{}

	simBlsStructs := make([]BlsMember, groupSize)
	for i := 0; i < groupSize; i++ {
		simBlsStructs[i] = RandBlsMember()
		groupNodeID[i] = simBlsStructs[i].memberID
		simBlsStructs[i].receiveSecretShares = make([]string, groupSize)
	}

	for i := 0; i < groupSize; i++ {
		simBlsStructs[i].polyCoeffs = make([]string, thresValue)
		coeffPoly := simBlsStructs[i].priva0.GetMasterSecretKey(thresValue)
		for index, v := range coeffPoly {
			simBlsStructs[i].polyCoeffs[index] = v.GetHexString()
		}

		simBlsStructs[i].commitment = make([]string, thresValue)
		commits := bls.GetMasterPublicKey(coeffPoly)
		for index, v := range commits {
			simBlsStructs[i].commitment[index] = v.GetHexString()
		}
		receiveCommitment[groupNodeID[i]] = simBlsStructs[i].commitment

		//generate secret shares
		var targetID bls.ID
		var sk bls.SecretKey
		skShare := make([]string, groupSize)
		for i := 0; i < groupSize; i++ {
			targetID.SetHexString(groupNodeID[i])
			if thresValue == 1 {
				skShare[i] = simBlsStructs[i].priva0.GetHexString()
			} else {
				sk.Set(coeffPoly, &targetID)
				skShare[i] = sk.GetHexString()
			}
		}
		simBlsStructs[i].secretShares = skShare
	}

	for i := 0; i < groupSize; i++ {
		for index, share := range simBlsStructs[i].secretShares {
			simBlsStructs[index].receiveSecretShares[i] = share
		}
	}

	initMessage := "201812121348"
	signShares := map[string]string{}
	for i := 0; i < groupSize; i++ {
		sk := []bls.SecretKey{}
		for _, v := range simBlsStructs[i].receiveSecretShares {
			var skSource bls.SecretKey
			skSource.SetHexString(v)
			sk = append(sk, skSource)
		}
		var skAgg bls.SecretKey
		skAgg = SeckeyAggregate(sk)
		simBlsStructs[i].secretAggregate = skAgg.GetHexString()

		signShares[simBlsStructs[i].memberID] = skAgg.Sign(initMessage).GetHexString()
	}

	return &BlsSharePoint{
		SignShares:     signShares,
		ThresholdValue: thresValue,
	}, nil
}

func GenSeedFromBls(signShares map[string]string) (string, error) {
	bls.Init(bls.CurveFp254BNb)
	signSlice := []string{}
	groupNodeID := []string{}
	for nodeID, sign := range signShares {
		groupNodeID = append(groupNodeID, nodeID)
		signSlice = append(signSlice, sign)
	}
	return GenerateSeed(SigRecover(signSlice, groupNodeID)), nil
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
