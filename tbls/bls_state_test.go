package tbls

import (
	cs "github.com/tendermint/tendermint/consensus"
	"github.com/tendermint/tendermint/consensus/tbls"
	"github.com/tendermint/tendermint/types"
	"strings"
)

//--------------------------------------------------------------------------------
//MockBLS
// MockBLS implements Generating verifiablely random number.
// Only use it for testing.

type MockBLS struct {
	thresholdNum int
	nodeID       string
	priva0       tbls.SecretKey
	coeffPoly    []string
	privkPKE     string
	skAgg        string
	pkAggVec     map[string]string
	groupPK      string
}

func NewMockBLS(nodeID string, groupNum int) *MockBLS {
	tbls.Init(tbls.CurveFp254BNb)
	mockBls := &MockBLS{
		nodeID: nodeID,
	}

	if groupNum == 2 {
		mockBls.thresholdNum = 2
	} else {
		mockBls.thresholdNum = (groupNum + 1) / 2
	}

	mockBls.priva0.SetByCSPRNG()
	coeffPoly := mockBls.priva0.GetMasterSecretKey(mockBls.thresholdNum)
	for _, coeff := range coeffPoly {
		mockBls.coeffPoly = append(mockBls.coeffPoly, coeff.GetHexString())
	}
	var prvk PrivateKeyPKE
	prvk.GenerateKeyPKE()
	mockBls.privkPKE = prvk.GetHexString()
	return mockBls
}

//--------------------------------------------------------------------------------
func (mbls *MockBLS) GetCommitment() types.CommitmentType {
	tbls.Init(tbls.CurveFp254BNb)
	var commits []tbls.PublicKey
	var coeffPoly []tbls.SecretKey
	for _, coeff := range mbls.coeffPoly {
		var tmpsk tbls.SecretKey
		tmpsk.SetHexString(coeff)
		coeffPoly = append(coeffPoly, tmpsk)
	}
	commits = tbls.GetMasterPublicKey(coeffPoly)
	commitmentStr := types.CommitmentType{}
	for _, v := range commits {
		commitmentStr.Commitment = append(commitmentStr.Commitment, v.GetHexString())
	}
	var prvk PrivateKeyPKE
	prvk.SetHexString(mbls.privkPKE)
	commitmentStr.ComSig, _ = SignPKE(&prvk, strings.Join(commitmentStr.Commitment, ""))
	return commitmentStr
}

//--------------------------------------------------------------------------------
func (mbls *MockBLS) GenerateSkShare(groupNodeID []string) []string {
	skShare := make([]string, len(groupNodeID))
	var targetID tbls.ID
	var coeff []tbls.SecretKey
	var sk tbls.SecretKey
	for _, cf := range mbls.coeffPoly {
		sk.SetHexString(cf)
		coeff = append(coeff, sk)
	}
	for i, v := range groupNodeID {
		targetID.SetHexString(v)
		sk.Set(coeff, &targetID)
		skShare[i] = sk.GetHexString()
	}
	return skShare
}

//--------------------------------------------------------------------------------
func SignShares(msg string, height int64, mblsVec ...*MockBLS) []*cs.BLSSignMessage {
	sigVec := []*cs.BLSSignMessage{}
	for _, mb := range mblsVec {
		sig := signBLS(mb.skAgg, msg)
		signMsg := &cs.BLSSignMessage{
			Height: height,
			NodeID: mb.nodeID,
			Sign:   sig,
		}
		sigVec = append(sigVec, signMsg)
	}
	return sigVec
}

//-------------------------------------------------------------------------------
func AddSignShares(conR *cs.ConsensusReactor, sigVec ...*cs.BLSSignMessage) {
	for _, sigMsg := range sigVec {
		conR.blsS.peerBLSMsgQueue <- msgInfo{Msg: sigMsg}
	}
}

//-------------------------------------------------------------------------------
func MockAddSignShares(conR *cs.ConsensusReactor, msg string, height int64, mblsVec ...*MockBLS) {
	sigVec := SignShares(msg, height, mblsVec...)
	AddSignShares(conR, sigVec...)
}

//-------------------------------------------------------------------------------
func MockAddCommitments(conR *cs.ConsensusReactor, mblsVec ...*MockBLS) {
	blsInitMsgs := Commitments(mblsVec...)
	AddCommitments(conR, blsInitMsgs...)
}

//-------------------------------------------------------------------------------
func AddCommitments(conR *cs.ConsensusReactor, blsInitMsgs ...*cs.BLSInitMessage) {
	for _, blsInitM := range blsInitMsgs {
		conR.blsI.peerBLSInitMsgQueue <- msgInfo{Msg: blsInitM}
	}
}

//-------------------------------------------------------------------------------
func Commitments(mblsVec ...*MockBLS) []*cs.BLSInitMessage {
	blsInitMsgs := []*cs.BLSInitMessage{}
	for _, mb := range mblsVec {
		com := mb.GetCommitment()
		blsInitMsg := &cs.BLSInitMessage{
			NodeID: mb.nodeID,
			Commit: &com,
		}
		blsInitMsgs = append(blsInitMsgs, blsInitMsg)
	}
	return blsInitMsgs
}

//-------------------------------------------------------------------------------
func MockAddInitFinishMsg(conR *cs.ConsensusReactor, mblsVec ...*MockBLS) {
	blsInitFinishMsgs := InitFinishMsg(mblsVec...)
	AddInitFinishMsg(conR, blsInitFinishMsgs...)
}

//-------------------------------------------------------------------------------
func AddInitFinishMsg(conR *cs.ConsensusReactor, blsInitFinishMsgs ...*cs.BLSInitFinishMessage) {
	for _, blsFinidhM := range blsInitFinishMsgs {
		conR.blsI.peerBLSInitMsgQueue <- msgInfo{Msg: blsFinidhM}
	}
}

//-------------------------------------------------------------------------------
func InitFinishMsg(mblsVec ...*MockBLS) []*cs.BLSInitFinishMessage {
	blsInitFinishMsgs := []*cs.BLSInitFinishMessage{}
	for _, mb := range mblsVec {
		var sk PrivateKeyPKE
		sk.SetHexString(mb.privkPKE)
		finishSign, _ := SignPKE(&sk, "Finished")
		blsFinishMsg := &cs.BLSInitFinishMessage{
			NodeID:        mb.nodeID,
			FinishMsg:     "Finished",
			FinishMsgSign: finishSign,
		}
		blsInitFinishMsgs = append(blsInitFinishMsgs, blsFinishMsg)
	}
	return blsInitFinishMsgs
}

//-------------------------------------------------------------------------------
func MockAddInitSKShareMsg(conR *cs.ConsensusReactor, mblsVec ...*MockBLS) {
	blsSKShareMsgs := InitSKShareMsg(conR, mblsVec...)
	AddInitSKShareMsg(conR, blsSKShareMsgs...)
}

//-------------------------------------------------------------------------------
func AddInitSKShareMsg(conR *cs.ConsensusReactor, blsSKShareMsgs ...*cs.BLSShareMessage) {
	for _, blsSKShareMsg := range blsSKShareMsgs {
		conR.blsI.peerBLSInitMsgQueue <- msgInfo{Msg: blsSKShareMsg}
	}
}

//-------------------------------------------------------------------------------
func InitSKShareMsg(conR *cs.ConsensusReactor, mblsVec ...*MockBLS) []*cs.BLSShareMessage {
	blsSKShareMsgs := make([]*cs.BLSShareMessage, len(mblsVec))
	skShareAndSigns := genSKShareForID(conR, mblsVec...)
	for i, mb := range mblsVec {
		blsSKShareMsg := &cs.BLSShareMessage{
			SrcID:     FindID(conR.blsI.groupNodeID, mb.nodeID),
			DesID:     0,
			SKShareCt: skShareAndSigns[i],
		}
		blsSKShareMsgs[i] = blsSKShareMsg
	}
	return blsSKShareMsgs
}

func genSKShareForID(conR *cs.ConsensusReactor, mblsVec ...*MockBLS) []*types.SKShareCtAndSign {
	bi := conR.blsI
	skShareCtAndSigns := make([]*types.SKShareCtAndSign, len(mblsVec))
	var idtmp tbls.ID
	idtmp.SetHexString(bi.nodeID)
	for i, mb := range mblsVec {
		var share tbls.SecretKey
		coeff := make([]tbls.SecretKey, len(mb.coeffPoly))
		for i, v := range mb.coeffPoly {
			share.SetHexString(v)
			coeff[i] = share
		}
		share.Set(coeff, &idtmp)
		var pkPKE PublicKeyPKE
		var skPKE PrivateKeyPKE
		//encrypt
		skPKE.SetHexString(bi.privkPKE)
		pkPKE = skPKE.GenPubKeyPKE()
		skSharect, _ := EncryptPKE(&pkPKE, share.GetHexString())
		//signature
		skPKE.SetHexString(mb.privkPKE)
		ctSign, _ := SignPKE(&skPKE, skSharect)
		skShareCtAndSign := &types.SKShareCtAndSign{
			SKShareCt: skSharect,
			CtSign:    ctSign,
		}
		skShareCtAndSigns[i] = skShareCtAndSign
	}
	return skShareCtAndSigns
}

//-------------------------------------------------------------------------------
func (conR *cs.ConsensusReactor) generateBLSParam(mblsVec []*MockBLS) {
	bs := conR.blsS
	bi := conR.blsI
	groupNodeID := bs.GroupNodeID
	groupSize := len(groupNodeID)

	//generate groupPK
	commitment := map[string][]string{}
	for _, mb := range mblsVec {
		tmpcom := mb.GetCommitment()
		commitment[mb.nodeID] = tmpcom.Commitment
	}
	var pksum, pk tbls.PublicKey
	pksum.SetHexString("0")
	for _, com := range commitment {
		pk.SetHexString(com[0])
		pksum.Add(&pk)
	}
	bs.GroupPK = pksum.GetHexString()
	//generate pkAggVec
	bs.PkAggVec = make(map[string]string, groupSize)
	for _, nodeID := range bs.GroupNodeID {
		var tarID tbls.ID
		var pktmp tbls.PublicKey
		tarID.SetHexString(nodeID)
		pksum := make([]tbls.PublicKey, bs.ThresholdNum)
		for i := 0; i < bs.ThresholdNum; i++ {
			pksum[i].SetHexString("0")
		}
		for _, coms := range commitment {
			for i, com := range coms {
				pktmp.SetHexString(com)
				pksum[i].Add(&pktmp)
			}
		}
		pktmp.Set(pksum, &tarID)
		bs.PkAggVec[nodeID] = pktmp.GetHexString()
	}

	//generate skAgg
	receSkshare := make([][]string, groupSize)
	for i := 0; i < groupSize; i++ {
		receSkshare[i] = make([]string, groupSize)
	}
	for i, mb := range mblsVec {
		i_shares := mb.GenerateSkShare(groupNodeID)
		for j, share := range i_shares {
			receSkshare[j][i] = share
		}
	}
	for i, mb := range mblsVec {
		var skvec []tbls.SecretKey
		var sk tbls.SecretKey
		for _, share := range receSkshare[i] {
			sk.SetHexString(share)
			skvec = append(skvec, sk)
		}
		sk.SeckeyAggregate(skvec)
		mb.skAgg = sk.GetHexString()
	}
	bi.skAgg = mblsVec[0].skAgg
	bs.SkAgg = mblsVec[0].skAgg
}

func (conR *cs.ConsensusReactor) setGroupSign0() {
	blsPubkeyJSON := BLSPubkeyJSON{
		GroupPK:      "testPK",
		PubkeyAggVec: map[string]string{},
	}
	result, _ := cdc.MarshalJSONIndent(blsPubkeyJSON, "", "")
	conR.blsS.groupSign[0] = string(result)
	conR.blsS.isSignReady = true
}
