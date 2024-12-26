package adaptorSignature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/hl-tang/generic-adaptor-signature-from-trapdoor-commitment/trapdoorCommitment"
)

// AdaptorSigECDSA struct implements the AdaptorSignature interface using ECDSA
type AdaptorSigECDSA struct {
	curve     elliptic.Curve
	tc        trapdoorCommitment.TrapdoorCommitment // the trapdoor commitment scheme that adaptor-sig scheme depends on (good to design as an interface)
	Statement string                                // ck; statement
	Witness   string                                // td; witness
}

// NewAdaptorSigECDSA creates a new instance of AdaptorSigECDSA
func NewAdaptorSigECDSA() *AdaptorSigECDSA {
	tc := trapdoorCommitment.NewTrapdoorCommitDL()
	Y, y := tc.Gen()
	fmt.Println("witness:", y)
	return &AdaptorSigECDSA{
		curve: elliptic.P256(), // Choosing P-256 curve for ECDSA
		// tc:    trapdoorCommitment.NewTrapdoorCommitDL(), // trapdoor commitment scheme is DL
		tc:        tc,
		Statement: Y,
		Witness:   y,
	}
}

func (as *AdaptorSigECDSA) Gen() (*ecdsa.PublicKey, *ecdsa.PrivateKey) {
	priv, _ := ecdsa.GenerateKey(as.curve, rand.Reader)
	return &priv.PublicKey, priv
}

func (as *AdaptorSigECDSA) Sign(sk *ecdsa.PrivateKey, m string) CompleteSignature {
	// Statement, y := as.tc.Gen()
	// fmt.Println("witness:", y)
	c, d := as.tc.Com(as.Statement, m)
	fmt.Println("commitment in Sign:", c)
	fmt.Println("d in Sign:", d)
	mYc_str := strings.Join([]string{m, as.Statement, c}, "")
	mYc_str_hash := sha256.Sum256([]byte(mYc_str))
	sigBar, err := ecdsa.SignASN1(rand.Reader, sk, mYc_str_hash[:])
	if err != nil {
		panic(err)
	}
	return CompleteSignature{
		// sigBar: string(sigBar),
		sigBar:    fmt.Sprintf("%x", sigBar),
		Statement: as.Statement,
		c:         c,
		d:         d,
	}
}

func (as *AdaptorSigECDSA) Ver(pk *ecdsa.PublicKey, m string, sig CompleteSignature) bool {
	if as.tc.Verify(sig.Statement, sig.c, m, sig.d) == false {
		return false
	}
	mYc_str := strings.Join([]string{m, sig.Statement, sig.c}, "")
	mYc_str_hash := sha256.Sum256([]byte(mYc_str))
	sig_bytes, _ := hex.DecodeString(sig.sigBar) // sigBar is a hex string, convert to []byte

	valid := ecdsa.VerifyASN1(pk, mYc_str_hash[:], sig_bytes)
	return valid
}

func (as *AdaptorSigECDSA) PreSign(sk *ecdsa.PrivateKey, m string, Y string) PreSignature {
	m0 := "0"
	// 这里注意c是要和之前的一样的，不然后面的sigBar都和之前不同了
	c, d0 := as.tc.Com(Y, m0)
	// 所以d0的选取绝对不能是随机的
	// 但不知道td的情况下，d求不出
	fmt.Println("commitment in PreSign:", c)

	mYc_str := strings.Join([]string{m, Y, c}, "")
	mYc_str_hash := sha256.Sum256([]byte(mYc_str))
	sigBar, err := ecdsa.SignASN1(rand.Reader, sk, mYc_str_hash[:])
	if err != nil {
		panic(err)
	}

	return PreSignature{
		// sigBar: string(sigBar),
		sigBar:    fmt.Sprintf("%x", sigBar),
		Statement: Y,
		c:         c,
		d0:        d0,
	}
}

func (as *AdaptorSigECDSA) PreVer(pk *ecdsa.PublicKey, m string, Y string, preSig PreSignature) bool {
	if as.tc.Verify(Y, preSig.c, "0", preSig.d0) == false {
		return false
	}
	mYc_str := strings.Join([]string{m, Y, preSig.c}, "")
	mYc_str_hash := sha256.Sum256([]byte(mYc_str))
	sig_bytes, _ := hex.DecodeString(preSig.sigBar) // sigBar is a hex string, convert to []byte

	valid := ecdsa.VerifyASN1(pk, mYc_str_hash[:], sig_bytes)
	return valid
}

func (as *AdaptorSigECDSA) Adapt(pk *ecdsa.PublicKey, m string, preSig PreSignature, y string) CompleteSignature {
	m0 := "0"
	d := as.tc.TrapdoorOpen(y, preSig.c, m0, preSig.d0, m)
	fmt.Println("Adapt d", d)

	return CompleteSignature{
		sigBar:    preSig.sigBar,
		Statement: as.Statement,
		c:         preSig.c,
		d:         d,
	}
}

// Extract trapdoor as the witness
func (as *AdaptorSigECDSA) Ext(pk *ecdsa.PublicKey, m string, Y string, preSig PreSignature, sig CompleteSignature) (string, error) {
	return as.tc.Extract(Y, sig.c, "0", preSig.d0, m, sig.d)
}
