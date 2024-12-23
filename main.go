package main

import (
	"fmt"
	"math/big"

	trapdoorcommitment "github.com/hl-tang/generic-adaptor-signature-from-trapdoor-commitment/trapdoorCommitment"
)

func main() {
	// Create TrapdoorCommitDL instance
	tc := trapdoorcommitment.NewTrapdoorCommitDL()

	// Key generation
	ck, td := tc.Gen()
	fmt.Printf("Commitment Key: %s\nTrapdoor: %s\n", ck, td)

	// Commit a message
	m0 := big.NewInt(42)
	c, d0 := tc.Com(ck, m0)
	fmt.Printf("Commitment: %s\nOpening: %s\n", c, d0)

	// Verify commitment
	ver := tc.Verify(ck, c, m0, d0)
	fmt.Printf("Verification result: %v\n", ver)

	// Adapt commitment to a new message
	m := big.NewInt(100)
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
}
