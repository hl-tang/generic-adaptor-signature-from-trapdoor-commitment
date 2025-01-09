package main

import (
	"fmt"

	"github.com/hl-tang/generic-adaptor-signature-from-trapdoor-commitment/adaptorSignature"
	"github.com/hl-tang/generic-adaptor-signature-from-trapdoor-commitment/trapdoorCommitment"
)

func main() {
	// Create TrapdoorCommitDL instance
	tc := trapdoorCommitment.NewTrapdoorCommitDL()

	// Key generation
	ck, td := tc.Gen()
	fmt.Printf("Commitment Key: %s\nTrapdoor: %s\n", ck, td)

	// Commit a message
	// m0 := big.NewInt(0)
	m0 := "0"
	c, d0 := tc.Com(ck, m0)
	fmt.Printf("Commitment: %s\nOpening: %s\n", c, d0)

	// Verify commitment
	ver := tc.Verify(ck, c, m0, d0)
	fmt.Printf("Verification result: %v\n", ver)

	// Adapt commitment to a new message
	// m := big.NewInt(100)
	// m := "100"
	m := "message"
	newD := tc.TrapdoorOpen(td, c, m0, d0, m)
	fmt.Printf("New Opening: %s\n", newD)

	// Verify adapted commitment
	verAdapt := tc.Verify(ck, c, m, newD)
	fmt.Printf("Adapted Verification result: %v\n", verAdapt)

	// Extract trapdoor
	extractedTd, err := tc.Extract(ck, c, m0, d0, m, newD)
	if err != nil {
		fmt.Printf("Error extracting trapdoor: %v\n", err)
	} else {
		fmt.Printf("Extracted Trapdoor: %s\n", extractedTd)
	}
	fmt.Println("------------------------------------------------")
	as_ecdsa := adaptorSignature.NewAdaptorSigECDSA()
	pk, sk := as_ecdsa.Gen()
	fmt.Println("pk:", pk)
	fmt.Println("sk:", sk)
	m = "message"

	var sig adaptorSignature.CompleteSignature = as_ecdsa.Sign(sk, m)
	fmt.Println("signature:", sig)

	valid := as_ecdsa.Ver(pk, m, sig)
	fmt.Println("Verify:", valid)

	var preSig adaptorSignature.PreSignature = as_ecdsa.PreSign(sk, m, sig.Statement)
	fmt.Println("preSig:", preSig)

	valid = as_ecdsa.PreVer(pk, m, preSig.Statement, preSig)
	fmt.Println("PreVer:", valid)

	adaptor_compSig := as_ecdsa.Adapt(pk, m, preSig, as_ecdsa.Witness)
	fmt.Println("Complete Adaptor Sig:", adaptor_compSig)
	// fmt.Println("Ada-sig == Original Sig", adaptor_compSig == sig)
	fmt.Println("Verify Adaptor Sig:", as_ecdsa.Ver(pk, m, adaptor_compSig))

	// extractedWitness, err := as_ecdsa.Ext(pk, m, as_ecdsa.Statement, preSig, sig)
	// if err != nil {
	// 	fmt.Printf("Error extracting trapdoor: %v\n", err)
	// } else {
	// 	fmt.Printf("Extracted Trapdoor: %s\n", extractedWitness)
	// }
	extractedWitness, err := as_ecdsa.Ext(pk, m, as_ecdsa.Statement, preSig, adaptor_compSig)
	if err != nil {
		fmt.Printf("Error extracting trapdoor: %v\n", err)
	} else {
		fmt.Printf("Extracted Trapdoor: %s\n", extractedWitness)
	}
}
