package tbls

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/zhenhanyijiu/tbls/libbls/bls/bls"
)

//modify by yananyang
//verify secret key from commitment
func IsEqualFromCom(sk *bls.SecretKey, comVec []bls.PublicKey, id *bls.ID) bool {
	var pkfromcom bls.PublicKey
	pkfromsk := sk.GetPublicKey()
	err := pkfromcom.Set(comVec, id)
	if err == nil {
		return pkfromcom.IsEqual(pkfromsk)
	} else {
		fmt.Println("public key from commitment fail")
		return false
	}
}

//aggragate the secret share
func SeckeyAggregate(seck []bls.SecretKey) (sksum bls.SecretKey) {
	sksum.SetHexString("0")
	for _, sk := range seck {
		sksum.Add(&sk)
	}
	return
}

//generate group public
func GenGroupPubKey(pks []bls.PublicKey) (gpk *bls.PublicKey) {
	gpk.SetHexString("0")
	for _, pk := range pks {
		gpk.Add(&pk)
	}
	return
}

//generate seed
func GenerateSeed(sig string) string {
	b := []byte(sig)
	h := sha256.New()
	h.Write(b)
	sr := h.Sum(nil)
	return hex.EncodeToString(sr[:])
}

//sig share verify
func VerifyBLS(pks string, msg string, sigs string) bool {
	var pk bls.PublicKey
	var sig bls.Sign
	sig.SetHexString(sigs)
	pk.SetHexString(pks)
	return sig.Verify(&pk, msg)
}

//recover threshold sig from sig share
func SigRecover(sigrec []string, idrec []string) string {
	sigvec := []bls.Sign{}
	idvec := []bls.ID{}
	var sigrecover bls.Sign
	for _, v := range sigrec {
		var tmp bls.Sign
		tmp.SetHexString(v)
		sigvec = append(sigvec, tmp)
	}
	for _, v := range idrec {
		var tmp bls.ID
		tmp.SetHexString(v)
		idvec = append(idvec, tmp)
	}
	sigrecover.Recover(sigvec, idvec)
	return sigrecover.GetHexString()
}
