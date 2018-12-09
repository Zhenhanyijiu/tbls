package tbls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/tendermint/go-amino"
	cs "github.com/tendermint/tendermint/consensus"
	"github.com/tendermint/tendermint/consensus/tbls"
	cmn "github.com/tendermint/tendermint/libs/common"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/types"
	"io/ioutil"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var (
	msgQueueSize = 1000
)

const (
	epochBlocks = 200
)

var cdc = amino.NewCodec()

type msgInfo struct {
	Msg    cs.ConsensusMessage `json:"msg"`
	PeerID p2p.ID              `json:"peer_key"`
}

type BLSState struct {
	GroupNodeID  []string          `json:"groupNodeID"`
	ThresholdNum int               `json:"thresholdNum"`
	SkAgg        string            `json:"skAgg"`
	PkAggVec     map[string]string `json:"pkAggVec"`
	GroupPK      string            `json:"groupPK"`
	PreGroupPK   string            `json:"preGroupPK"`
	PrivkPKE     string            `json:"privkPKE"`
	PubKPKE      string            `json:"pubkPKE"`
	PubKeyPKEVec map[string]string `json:"PubKeyPKEVec"`
	NodeIndex    int               `json:"node_index"`
	InitBlsGroup []*types.BLSNode  `json:"init_bls_group"`
	CoeffPloy    []string          `json:"coeff_ploy"`
	filePath     string
	LastHeight   int64

	mtx                 sync.RWMutex
	groupSize           int
	genesisMsg          string
	nodeID              string
	height              int64
	signSlice           map[string]string
	isSignReady         bool
	curSign             string
	groupSign           map[int64]string
	peerBLSMsgQueue     chan msgInfo
	internalBLSMsgQueue chan msgInfo
}

func (bs *BLSState) Init(
	nodeID string,
	genesisMsg string,
	filepath string,
	validators []types.GenesisValidator,
	lastBlockHeight int64,
	lastGroupSign string,
	groupSign string) {

	tbls.Init(tbls.CurveFp254BNb)

	if len(bs.InitBlsGroup) == 0 {
		initBLSGroup := []*types.BLSNode{}
		groupNodeID := []string{}
		pubkPKEVec := map[string]string{}
		sort.Sort(types.GenesisValidatorsByAddress(validators))
		for _, val := range validators {
			groupNodeID = append(groupNodeID, val.BlsPubKey.Address)
			pubkPKEVec[val.BlsPubKey.Address] = val.BlsPubKey.Value

			node := &types.BLSNode{
				Address:   val.BlsPubKey.Address,
				PubKeyPKE: val.BlsPubKey.Value,
			}
			initBLSGroup = append(initBLSGroup, node)
		}

		bs.GroupNodeID = groupNodeID
		bs.PubKeyPKEVec = pubkPKEVec
		bs.InitBlsGroup = initBLSGroup
	}

	bs.LastHeight = lastBlockHeight

	bs.groupSize = len(bs.GroupNodeID)
	//Set threshold num for first bls init
	if bs.ThresholdNum == 0 {
		if bs.groupSize == 2 {
			bs.ThresholdNum = 2
		} else {
			bs.ThresholdNum = (len(bs.GroupNodeID) + 1) / 2
		}
	}

	bs.genesisMsg = genesisMsg
	bs.nodeID = nodeID
	bs.NodeIndex = FindID(bs.GroupNodeID, nodeID)
	bs.filePath = filepath
	bs.signSlice = map[string]string{}
	bs.isSignReady = false
	bs.curSign = ""

	bs.groupSign = map[int64]string{}
	if bs.LastHeight != 0 && groupSign != "" {
		bs.groupSign[bs.LastHeight] = groupSign
	}
	if lastGroupSign != "" {
		bs.groupSign[bs.LastHeight-1] = lastGroupSign
	}

	if bs.LastHeight > 0 && groupSign == "" && bs.groupSize == 1 {
		lastSeed := tbls.GenerateSeed(lastGroupSign)
		mess := lastSeed + lastGroupSign
		bs.groupSign[bs.LastHeight] = signBLS(bs.SkAgg, mess)
	}

	bs.peerBLSMsgQueue = make(chan msgInfo, msgQueueSize)
	bs.internalBLSMsgQueue = make(chan msgInfo, msgQueueSize)
}

func (bs *BLSState) GetPubKPKE() string {
	return bs.PubKPKE
}

func (bs *BLSState) SaveToFile() {
	bs.mtx.Lock()
	defer bs.mtx.Unlock()
	bs.save()
}
func (bs *BLSState) save() {
	outFile := bs.filePath
	if outFile == "" {
		panic("Cannot save BlsState: filePath not set")
	}
	blsStateBytes, err := cdc.MarshalJSONIndent(bs, "", "  ")
	if err != nil {
		panic(err)
	}
	err = cmn.WriteFileAtomic(outFile, blsStateBytes, 0600)
	if err != nil {
		panic(err)
	}
}

func (bs *BLSState) SaveInitParamToBLSState(bi *BLSInit) {
	bs.SkAgg = bi.skAgg
	bs.GroupNodeID = bi.groupNodeID
	bs.groupSize = bi.groupSize
	bs.ThresholdNum = bi.thresholdNum
	bs.PkAggVec = bi.pkAggVec
	bs.GroupPK = bi.groupPK
	bs.NodeIndex = bi.nodeIndex
	bs.SaveToFile()
}

func LoadFileBS(filePath string) *BLSState {
	blsstateJSONBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		cmn.Exit(err.Error())
	}
	blsstate := &BLSState{}
	err = cdc.UnmarshalJSON(blsstateJSONBytes, &blsstate)
	if err != nil {
		cmn.Exit(cmn.Fmt("Error reading BlsSignParam from %v: %v\n", filePath, err))
	}
	return blsstate
}

func GenFileBS(filePath string) *BLSState {
	var prvkPKE PrivateKeyPKE
	prvkPKE.GenerateKeyPKE()
	pubk := prvkPKE.GenPubKeyPKE()
	return &BLSState{
		GroupNodeID:  []string{},
		ThresholdNum: 0,
		SkAgg:        "",
		PkAggVec:     map[string]string{},
		GroupPK:      "",
		PreGroupPK:   "",
		PrivkPKE:     prvkPKE.GetHexString(),
		PubKPKE:      pubk.GetHexString(),
		PubKeyPKEVec: map[string]string{},
		InitBlsGroup: []*types.BLSNode{},
		NodeIndex:    -1,
		filePath:     filePath,
	}
}

type BLSPubkeyJSON struct {
	GroupPK      string            `json:"groupPK"`
	PubkeyAggVec map[string]string `json:"pubkAggVec"`
}

type SKShareInfo struct {
	BitsCount []int
	Bits      []*cmn.BitArray
	Share     [][]*types.SKShareCtAndSign
}

func NewSKShareInfo(groupSize int) *SKShareInfo {
	sKShareInfo := &SKShareInfo{}
	sKShareInfo.BitsCount = make([]int, groupSize)
	sKShareInfo.Bits = make([]*cmn.BitArray, groupSize)
	sKShareInfo.Share = make([][]*types.SKShareCtAndSign, groupSize)
	for i := 0; i < groupSize; i++ {
		sKShareInfo.Share[i] = make([]*types.SKShareCtAndSign, groupSize)
		sKShareInfo.Bits[i] = cmn.NewBitArray(groupSize)
	}
	return sKShareInfo
}

type StoredApprovalSKShareInfo struct {
	BitsColumnCount []int
	BitsLineCount   []int
	Bits            []*cmn.BitArray
}

func NewStoredApprovalSKShareInfo(groupSize int) *StoredApprovalSKShareInfo {
	storedApprovalSKShareInfo := &StoredApprovalSKShareInfo{}
	storedApprovalSKShareInfo.BitsLineCount = make([]int, groupSize)
	storedApprovalSKShareInfo.BitsColumnCount = make([]int, groupSize)
	storedApprovalSKShareInfo.Bits = make([]*cmn.BitArray, groupSize)
	for i := 0; i < groupSize; i++ {
		storedApprovalSKShareInfo.Bits[i] = cmn.NewBitArray(groupSize)
	}
	return storedApprovalSKShareInfo
}

type BLSInit struct {
	mtx sync.RWMutex

	thresholdNum              int
	groupSize                 int
	nodeID                    string
	epoch                     int64
	nodeIndex                 int
	groupNodeID               []string
	priva0                    tbls.SecretKey //coefficient a0
	coeffPoly                 []string       //poly coefficient
	ourCommit                 *types.CommitmentType
	receiveCommitment         map[string]*types.CommitmentType
	skShareCt                 map[string]*types.SKShareCtAndSign //ciphertext for skShare
	receiveSkShare            *SKShareInfo
	approvedSkShare           *types.ApprovedSKShareInfo
	storedApprovalSKShareInfo *StoredApprovalSKShareInfo
	receiveInitFinishMsg      map[string]string
	pkAggVec                  map[string]string
	skAgg                     string
	groupPK                   string
	privkPKE                  string
	pubkPKEVec                map[string]string
	peerBLSInitMsgQueue       chan msgInfo
	internalBLSInitMsgQueue   chan msgInfo
	commitInHeight            int64
}

func NewBLSInit(nodeID string, lastHeight int64, initBlsGroup []*types.BLSNode, privkPKE string, coeffPoly []string) *BLSInit {
	grpNodeID := make([]string, len(initBlsGroup))
	pkPKEVec := make(map[string]string, len(initBlsGroup))
	for index, node := range initBlsGroup {
		grpNodeID[index] = node.Address
		pkPKEVec[node.Address] = node.PubKeyPKE
	}

	bi := &BLSInit{
		nodeID:                  nodeID,
		epoch:                   lastHeight / epochBlocks,
		groupNodeID:             grpNodeID,
		privkPKE:                privkPKE,
		pubkPKEVec:              pkPKEVec,
		coeffPoly:               coeffPoly,
		nodeIndex:               FindID(grpNodeID, nodeID),
		peerBLSInitMsgQueue:     make(chan msgInfo, msgQueueSize),
		internalBLSInitMsgQueue: make(chan msgInfo, msgQueueSize),
	}
	return bi
}

func (bi *BLSInit) Init() {
	bi.groupSize = len(bi.groupNodeID)
	if bi.groupSize == 2 {
		bi.thresholdNum = 2
	} else {
		bi.thresholdNum = (len(bi.groupNodeID) + 1) / 2
	}

	bi.skShareCt = map[string]*types.SKShareCtAndSign{}
	bi.receiveSkShare = NewSKShareInfo(bi.groupSize)
	bi.approvedSkShare = types.NewApprovedSKShareInfo(bi.groupSize)
	bi.storedApprovalSKShareInfo = NewStoredApprovalSKShareInfo(bi.groupSize)
	bi.receiveCommitment = map[string]*types.CommitmentType{}
	bi.receiveInitFinishMsg = map[string]string{}
	bi.pkAggVec = map[string]string{}

	bi.priva0.SetByCSPRNG()
	bi.coeffPoly = []string{}
	coeffPoly := bi.priva0.GetMasterSecretKey(bi.thresholdNum)
	for _, v := range coeffPoly {
		bi.coeffPoly = append(bi.coeffPoly, v.GetHexString())
	}

	//gengerate our commitment
	ourCommit := &types.CommitmentType{
		Commitment: []string{},
		ComSig:     "",
	}
	commits := tbls.GetMasterPublicKey(coeffPoly)
	for _, v := range commits {
		ourCommit.Commitment = append(ourCommit.Commitment, v.GetHexString())
	}
	//complete commitment signature
	var privk PrivateKeyPKE
	privk.SetHexString(bi.privkPKE)
	ourCommit.ComSig, _ = SignPKE(&privk, strings.Join(ourCommit.Commitment, ""))
	bi.ourCommit = ourCommit

	bi.generateSecretShareCt()
}

func (bi *BLSInit) InitStruct() {
	bi.groupSize = len(bi.groupNodeID)
	if bi.groupSize == 2 {
		bi.thresholdNum = 2
	} else {
		bi.thresholdNum = (len(bi.groupNodeID) + 1) / 2
	}

	bi.skShareCt = map[string]*types.SKShareCtAndSign{}
	bi.receiveSkShare = NewSKShareInfo(bi.groupSize)
	bi.approvedSkShare = types.NewApprovedSKShareInfo(bi.groupSize)
	bi.storedApprovalSKShareInfo = NewStoredApprovalSKShareInfo(bi.groupSize)
	bi.receiveCommitment = map[string]*types.CommitmentType{}
	bi.receiveInitFinishMsg = map[string]string{}
	bi.pkAggVec = map[string]string{}

	if len(bi.coeffPoly) != 0 {
		coeffPoly := []tbls.SecretKey{}
		for _, v := range bi.coeffPoly {
			var secKey tbls.SecretKey
			secKey.SetHexString(v)
			coeffPoly = append(coeffPoly, secKey)
		}
		//gengerate our commitment
		ourCommit := &types.CommitmentType{
			Commitment: []string{},
			ComSig:     "",
		}
		commits := tbls.GetMasterPublicKey(coeffPoly)
		for _, v := range commits {
			ourCommit.Commitment = append(ourCommit.Commitment, v.GetHexString())
		}
		//complete commitment signature
		var privk PrivateKeyPKE
		privk.SetHexString(bi.privkPKE)
		ourCommit.ComSig, _ = SignPKE(&privk, strings.Join(ourCommit.Commitment, ""))
		bi.ourCommit = ourCommit

		bi.generateSecretShareCt()
	}
}

func (bi *BLSInit) generateSecretShareCt() {
	var targetID tbls.ID
	var sk tbls.SecretKey
	coeff := []tbls.SecretKey{}
	skShare := map[string]string{}
	for _, v := range bi.coeffPoly {
		sk.SetHexString(v)
		coeff = append(coeff, sk)
	}
	for i := 0; i < bi.groupSize; i++ {
		targetID.SetHexString(bi.groupNodeID[i])
		if bi.thresholdNum == 1 {
			skShare[bi.groupNodeID[i]] = bi.priva0.GetHexString()
		} else {
			sk.Set(coeff, &targetID)
			skShare[bi.groupNodeID[i]] = sk.GetHexString()
		}
	}
	//Encrypt for skahare
	var curNodeSK PrivateKeyPKE
	curNodeSK.SetHexString(bi.privkPKE)
	var targetIDPK PublicKeyPKE
	for targetID, skshare := range skShare {
		targetIDPK.SetHexString(bi.pubkPKEVec[targetID])
		skShareCt, _ := EncryptPKE(&targetIDPK, skshare)
		ctSign, _ := SignPKE(&curNodeSK, skShareCt)
		bi.skShareCt[targetID] = &types.SKShareCtAndSign{
			SKShareCt: skShareCt,
			CtSign:    ctSign,
		}
	}

}

func (bi *BLSInit) seckeyAggregate() {
	sk := []tbls.SecretKey{}
	for _, v := range bi.receiveSkShare.Share[bi.nodeIndex] {
		var skSource tbls.SecretKey
		skSource.SetHexString(v.SKShareCt)
		sk = append(sk, skSource)
	}
	var skAgg tbls.SecretKey
	skAgg.SeckeyAggregate(sk)
	bi.skAgg = skAgg.GetHexString()
}

//the id repesent poly which one was used
func (bi *BLSInit) verifyByCommits(sksrc string, id string) bool {
	var sk tbls.SecretKey
	var nodeID tbls.ID
	sk.SetHexString(sksrc)
	nodeID.SetHexString(bi.nodeID)
	com := make([]tbls.PublicKey, bi.groupSize)
	if id == bi.nodeID {
		for i, v := range bi.ourCommit.Commitment {
			com[i].SetHexString(v)
		}
	} else {
		for i, v := range bi.receiveCommitment[id].Commitment {
			com[i].SetHexString(v)
		}
	}
	if bi.thresholdNum == 1 {
		//var pkfromcom tbls.PublicKey
		//pkfromcom.SetHexString()
		pkfromsk := sk.GetPublicKey()
		return pkfromsk.IsEqual(&com[0])
	} else {
		return sk.IsEqualFromCom(com, &nodeID)
	}
}

func signBLS(sk string, msg string) string {
	var skAgg tbls.SecretKey
	skAgg.SetHexString(sk)
	sig := skAgg.Sign(msg)
	return sig.GetHexString()
}

//find a element in the arrary
func FindID(IDs []string, nodeID string) int {
	return sort.Search(len(IDs), func(i int) bool {
		return bytes.Compare([]byte(nodeID), []byte(IDs[i])) <= 0
	})
}

func HasID(IDs []string, nodeID string) bool {
	idx := sort.Search(len(IDs), func(i int) bool {
		return bytes.Compare([]byte(nodeID), []byte(IDs[i])) <= 0
	})
	return idx < len(IDs) && IDs[idx] == nodeID
}

//initial the pkAggvec of all nodes
func (bi *BLSInit) generatepkAggVec() {
	for i := 0; i < bi.groupSize; i++ {
		bi.pkAggVec[bi.groupNodeID[i]] = bi.generatepkAgg(bi.groupNodeID[i])
	}
}

//generate pkAgg used for sig share verification
func (bi *BLSInit) generatepkAgg(id string) string {

	var idtmp tbls.ID
	var pktmp tbls.PublicKey
	idtmp.SetHexString(id)
	pksum := make([]tbls.PublicKey, bi.thresholdNum)
	for i := 0; i < bi.thresholdNum; i++ {
		pksum[i].SetHexString("0")
	}
	for _, v1 := range bi.receiveCommitment {
		for i, v2 := range v1.Commitment {
			pktmp.SetHexString(v2)
			pksum[i].Add(&pktmp)
		}
	}
	if bi.thresholdNum > 1 {
		pktmp.Set(pksum, &idtmp)
		return pktmp.GetHexString()
	} else {
		return pksum[0].GetHexString()
	}

}

//generate group public key
func (bi *BLSInit) generateGroupPK() {
	var pksum tbls.PublicKey
	var tmp tbls.PublicKey
	pksum.SetHexString("0")
	if bi.thresholdNum > 1 {
		for _, v := range bi.receiveCommitment {
			tmp.SetHexString(v.Commitment[0])
			pksum.Add(&tmp)
		}
	} else {
		tmp.SetHexString(bi.ourCommit.Commitment[0])
		pksum.Add(&tmp)
	}
	bi.groupPK = pksum.GetHexString()
}

//private key for decrypt PKE
type PrivateKeyPKE struct {
	Prv *ecies.PrivateKey
}

//public key for encrypt PKE
type PublicKeyPKE struct {
	Pbk *ecies.PublicKey
}

//Signature type
type Signature struct {
	R, S *big.Int
}

//signature to hexstring
func (sig *Signature) GetHexString() string {
	r := hex.EncodeToString(sig.R.Bytes())
	s := hex.EncodeToString(sig.S.Bytes())
	length := len(r)
	lenflag := len(strconv.Itoa(length))
	if lenflag == 1 {
		return "10" + strconv.Itoa(length) + r + s
	} else {
		return "2" + strconv.Itoa(length) + r + s
	}
}

//hexstring to signature
func (sig *Signature) SetHexString(s string) (err error) {
	var length int
	if s[0:1] == "2" {
		length, _ = strconv.Atoi(s[1:3])

	} else if s[0:2] == "10" {
		length, _ = strconv.Atoi(s[2:3])
	} else {
		err = fmt.Errorf("invalid signature format")
	}
	sig.R, _ = new(big.Int).SetString(s[3:3+length], 16)
	sig.S, _ = new(big.Int).SetString(s[3+length:], 16)
	return
}

//PKE private key generation
func (privk *PrivateKeyPKE) GenerateKeyPKE() error {
	prv, err := ecies.GenerateKey(rand.Reader, ecies.DefaultCurve, nil)
	privk.Prv = prv
	return err
}

//PKE public key generation
func (sk *PrivateKeyPKE) GenPubKeyPKE() PublicKeyPKE {
	var tmp PublicKeyPKE
	tmp.Pbk = &sk.Prv.PublicKey
	return tmp
}

//PKE Encrypt a message
func EncryptPKE(pkepk *PublicKeyPKE, m string) (ct string, err error) {
	ctbyte, err := ecies.Encrypt(rand.Reader, pkepk.Pbk, []byte(m), nil, nil)
	ct = string(ctbyte)
	return
}

//PKE Decrypt a ciphertext
func DecryptPKE(prv *PrivateKeyPKE, ct string) (pt string, err error) {
	ptbyte, err := prv.Prv.Decrypt([]byte(ct), nil, nil)
	pt = string(ptbyte[:])
	return
}

//signature function used for sign commitment
func SignPKE(prv *PrivateKeyPKE, msg string) (sigrt string, err error) {

	prvkecdsa := prv.Prv.ExportECDSA()
	r, s, err := ecdsa.Sign(rand.Reader, prvkecdsa, []byte(msg))
	var sign = Signature{
		R: r,
		S: s,
	}
	sigrt = sign.GetHexString()
	return
}

//verify signature for commitment
func VerifySignPKE(pubk *PublicKeyPKE, msg string, sigrt string) bool {
	pub := pubk.Pbk.ExportECDSA()
	var sig Signature
	sig.SetHexString(sigrt)
	return ecdsa.Verify(pub, []byte(msg), sig.R, sig.S)
}

//convert string to PrivateKeyPKE
func (prvk *PrivateKeyPKE) SetHexString(s string) {
	prvk.Prv = stringToECSK(s)
}

//convert string to ecies.PrivateKey
func stringToECSK(s string) (tmpsk *ecies.PrivateKey) {
	var tmp PublicKeyPKE
	tmpsk = new(ecies.PrivateKey)
	length, _ := strconv.Atoi(s[:3])
	pkstr := s[3 : length+3]
	tmp.SetHexString(pkstr)
	tmpsk.PublicKey = *tmp.Pbk
	prvstr := s[length+3:]
	tmpsk.D, _ = new(big.Int).SetString(prvstr, 16)
	return
}

//convert PrivateKeyPKE to string
func (prvk *PrivateKeyPKE) GetHexString() string {
	var tmp PublicKeyPKE
	tmp.Pbk = &prvk.Prv.PublicKey
	pkstr := tmp.GetHexString()
	str1 := strconv.Itoa(len(pkstr))
	str2 := hex.EncodeToString(prvk.Prv.D.Bytes())
	return str1 + pkstr + str2
}

//convert string to PublicKeyPKE
func (pubk *PublicKeyPKE) SetHexString(pkstr string) {
	pubk.Pbk = stringToECPK(pkstr)

}

//convert string to ecies.PublicKey
func stringToECPK(pkstr string) (pktmp *ecies.PublicKey) {
	lenflag := pkstr[0:1]
	var length int
	if lenflag == "1" {
		length, _ = strconv.Atoi(pkstr[1:2])

	} else {
		length, _ = strconv.Atoi(pkstr[1:3])
	}
	pktmp = new(ecies.PublicKey)
	pktmp.X, _ = new(big.Int).SetString(pkstr[3:length+3], 16)
	pktmp.Y, _ = new(big.Int).SetString(pkstr[length+3:], 16)
	pktmp.Curve = ecies.DefaultCurve
	pktmp.Params = ecies.ParamsFromCurve(ecies.DefaultCurve)
	return

}

//convert PublicKeyPKE to string
func (pubk *PublicKeyPKE) GetHexString() string {
	var length int
	x := pubk.Pbk.X
	y := pubk.Pbk.Y
	length = len(hex.EncodeToString(x.Bytes()))
	st1 := strconv.Itoa(length)
	lenflag := len(st1)
	st2 := hex.EncodeToString(x.Bytes()) + hex.EncodeToString(y.Bytes())
	if lenflag == 1 {
		return "10" + st1 + st2
	} else {
		return "2" + st1 + st2
	}
}
