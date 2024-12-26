package adaptorSignature

import (
	"fmt"
	"testing"
)

func TestAdaptorSigECDSA(t *testing.T) {
	as_ecdsa := NewAdaptorSigECDSA()
	pk, sk := as_ecdsa.Gen()
	fmt.Println("pk:", pk)
	fmt.Println("sk:", sk)
	m := "message"

	var sig CompleteSignature = as_ecdsa.Sign(sk, m)
	fmt.Println("signature:", sig)

	valid := as_ecdsa.Ver(pk, m, sig)
	fmt.Println("Verify:", valid)

	var preSig PreSignature = as_ecdsa.PreSign(sk, m, sig.Statement)
	fmt.Println("preSig:", preSig)

	valid = as_ecdsa.PreVer(pk, m, preSig.Statement, preSig)
	fmt.Println("PreVer:", valid)

	adaptor_compSig := as_ecdsa.Adapt(pk, m, preSig, as_ecdsa.Witness)
	fmt.Println("Complete Adaptor Sig:", adaptor_compSig)
	fmt.Println("Ada-sig == Original Sig", adaptor_compSig == sig)
	fmt.Println("Verify Adaptor Sig:", as_ecdsa.Ver(pk, m, adaptor_compSig))

	extractedWitness, err := as_ecdsa.Ext(pk, m, as_ecdsa.Statement, preSig, sig)
	if err != nil {
		fmt.Printf("Error extracting trapdoor: %v\n", err)
	} else {
		fmt.Printf("Extracted Trapdoor: %s\n", extractedWitness)
	}
	extractedWitness, err = as_ecdsa.Ext(pk, m, as_ecdsa.Statement, preSig, adaptor_compSig)
	if err != nil {
		fmt.Printf("Error extracting trapdoor: %v\n", err)
	} else {
		fmt.Printf("Extracted Trapdoor: %s\n", extractedWitness)
	}
}
