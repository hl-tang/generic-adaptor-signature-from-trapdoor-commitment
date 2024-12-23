package trapdoorcommitment

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// TrapdoorCommitDL struct
// Implements the TrapdoorCommitment interface using discrete logarithms
type TrapdoorCommitDL struct {
	p *big.Int // Large prime
	g *big.Int // Generator
}

// NewTrapdoorCommitDL creates a new TrapdoorCommitDL instance
func NewTrapdoorCommitDL() *TrapdoorCommitDL {
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	g := big.NewInt(2)
	return &TrapdoorCommitDL{p: p, g: g}
}

// Gen generates a commitment key and trapdoor
func (tc *TrapdoorCommitDL) Gen() (*big.Int, *big.Int) {
	td, _ := rand.Int(rand.Reader, tc.p)   // Random trapdoor
	ck := new(big.Int).Exp(tc.g, td, tc.p) // ck = g^td mod p
	return ck, td
}

// Com creates a commitment and opening
func (tc *TrapdoorCommitDL) Com(ck, m *big.Int) (*big.Int, *big.Int) {
	d, _ := rand.Int(rand.Reader, tc.p)                   // Random d
	c1 := new(big.Int).Exp(ck, m, tc.p)                   // g^(td*m) mod p
	c2 := new(big.Int).Exp(tc.g, d, tc.p)                 // g^d mod p
	c := new(big.Int).Mod(new(big.Int).Mul(c1, c2), tc.p) // c = g^(td*m) * g^d mod p
	return c, d
}

// Verify checks if the commitment is valid
func (tc *TrapdoorCommitDL) Verify(ck, c, m, d *big.Int) bool {
	c1 := new(big.Int).Exp(ck, m, tc.p)   // g^(td*m) mod p
	c2 := new(big.Int).Exp(tc.g, d, tc.p) // g^d mod p
	check := new(big.Int).Mod(new(big.Int).Mul(c1, c2), tc.p)
	return check.Cmp(c) == 0 // Check if c == ck^m * g^d mod p
}

// TrapdoorOpen adapts the commitment to a new message
func (tc *TrapdoorCommitDL) TrapdoorOpen(td, c, m0, d0, m *big.Int) *big.Int {
	delta := new(big.Int).Sub(m0, m) // m0 - m
	d := new(big.Int).Add(d0, new(big.Int).Mul(td, delta))
	return d
}

// Extract extracts the trapdoor from commitments
func (tc *TrapdoorCommitDL) Extract(ck, c, m0, d0, m, d *big.Int) (*big.Int, error) {
	// Calculate the difference: d - d0
	numerator := new(big.Int).Sub(d, d0) // (d - d0)
	// Calculate the difference: m0 - m
	denominator := new(big.Int).Sub(m0, m) // (m0 - m)
	// Ensure denominator is not zero
	if denominator.Cmp(big.NewInt(0)) == 0 {
		return nil, fmt.Errorf("division by zero: m0 and m cannot be equal")
	}
	// Compute td = (d - d0) / (m0 - m)
	td := new(big.Int).Div(numerator, denominator) // Perform integer division
	return td, nil
}

// func main() {
// 	// Create TrapdoorCommitDL instance
// 	tc := NewTrapdoorCommitDL()

// 	// Key generation
// 	ck, td := tc.Gen()
// 	fmt.Printf("Commitment Key: %s\nTrapdoor: %s\n", ck, td)

// 	// Commit a message
// 	m0 := big.NewInt(42)
// 	c, d0 := tc.Com(ck, m0)
// 	fmt.Printf("Commitment: %s\nOpening: %s\n", c, d0)

// 	// Verify commitment
// 	ver := tc.Verify(ck, c, m0, d0)
// 	fmt.Printf("Verification result: %v\n", ver)

// 	// Adapt commitment to a new message
// 	m := big.NewInt(100)
// 	newD := tc.TrapdoorOpen(td, c, m0, d0, m)
// 	fmt.Printf("New Opening: %s\n", newD)

// 	// Verify adapted commitment
// 	verAdapt := tc.Verify(ck, c, m, newD)
// 	fmt.Printf("Adapted Verification result: %v\n", verAdapt)

// 	// Extract trapdoor
// 	extractedTd, err := tc.Extract(ck, c, m0, d0, m, newD)
// 	if err != nil {
// 		fmt.Printf("Error extracting trapdoor: %v\n", err)
// 	} else {
// 		fmt.Printf("Extracted Trapdoor: %s\n", extractedTd)
// 	}
// }
