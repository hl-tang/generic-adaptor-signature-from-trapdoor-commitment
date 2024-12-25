package trapdoorCommitment

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// func stringToBigInt(s string) *big.Int {
// 	// convert string to []byte
// 	bytes := []byte(s)
// 	// create a big.Int and use SetBytes() to convert
// 	bigInt := new(big.Int).SetBytes(bytes)
// 	return bigInt
// }

//	func bigIntToString(b *big.Int) string {
//		// get []byte and convert to string
//		return string(b.Bytes())
//	}

func messageToBigInt(msg string) *big.Int {
	hash := sha256.Sum256([]byte(msg))    // hash the message string
	return new(big.Int).SetBytes(hash[:]) // convert the hash to bigInt
}

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
func (tc *TrapdoorCommitDL) Gen() (string, string) {
	td, _ := rand.Int(rand.Reader, tc.p)   // Random trapdoor
	ck := new(big.Int).Exp(tc.g, td, tc.p) // ck = g^td mod p
	// return ck, td
	// return bigIntToString(ck), bigIntToString(td)
	return ck.Text(16), td.Text(16) // Return ck and trapdoor as hex strings
}

// Com creates a commitment and opening
func (tc *TrapdoorCommitDL) Com(ck, m string) (string, string) {
	ck_bigInt := new(big.Int)
	ck_bigInt.SetString(ck, 16)
	// m_bigInt := new(big.Int)
	// m_bigInt.SetString(m, 16)
	m_bigInt := messageToBigInt(m)
	d, _ := rand.Int(rand.Reader, tc.p)                   // Random d
	c1 := new(big.Int).Exp(ck_bigInt, m_bigInt, tc.p)     // g^(td*m) mod p
	c2 := new(big.Int).Exp(tc.g, d, tc.p)                 // g^d mod p
	c := new(big.Int).Mod(new(big.Int).Mul(c1, c2), tc.p) // c = g^(td*m) * g^d mod p
	// return c, d
	// return bigIntToString(c), bigIntToString(d)
	return c.Text(16), d.Text(16) // Return commitment and opening as hex strings
}

// Verify checks if the commitment is valid
func (tc *TrapdoorCommitDL) Verify(ck, c, m, d string) bool {
	ck_bigInt := new(big.Int)
	ck_bigInt.SetString(ck, 16)
	c_bigInt := new(big.Int)
	c_bigInt.SetString(c, 16)
	// m_bigInt := new(big.Int)
	// m_bigInt.SetString(m, 16)
	m_bigInt := messageToBigInt(m)
	d_bigInt := new(big.Int)
	d_bigInt.SetString(d, 16)
	c1 := new(big.Int).Exp(ck_bigInt, m_bigInt, tc.p) // g^(td*m) mod p
	c2 := new(big.Int).Exp(tc.g, d_bigInt, tc.p)      // g^d mod p
	check := new(big.Int).Mod(new(big.Int).Mul(c1, c2), tc.p)
	return check.Cmp(c_bigInt) == 0 // Check if c == ck^m * g^d mod p
}

// TrapdoorOpen adapts the commitment to a new message
func (tc *TrapdoorCommitDL) TrapdoorOpen(td, c, m0, d0, m string) string {
	// m0_bigInt := new(big.Int)
	// m0_bigInt.SetString(m0, 16)
	// m_bigInt := new(big.Int)
	// m_bigInt.SetString(m, 16)
	m0_bigInt := messageToBigInt(m0)
	m_bigInt := messageToBigInt(m)
	d0_bigInt := new(big.Int)
	d0_bigInt.SetString(d0, 16)
	td_bigInt := new(big.Int)
	td_bigInt.SetString(td, 16)
	delta := new(big.Int).Sub(m0_bigInt, m_bigInt) // m0 - m
	d := new(big.Int).Add(d0_bigInt, new(big.Int).Mul(td_bigInt, delta))
	// return d
	// return bigIntToString(d)
	return d.Text(16) // Return new opening as hex string
}

// Extract extracts the trapdoor from commitments
func (tc *TrapdoorCommitDL) Extract(ck, c, m0, d0, m, d string) (string, error) {
	// m0_bigInt := new(big.Int)
	// m0_bigInt.SetString(m0, 16)
	// m_bigInt := new(big.Int)
	// m_bigInt.SetString(m, 16)
	m0_bigInt := messageToBigInt(m0)
	m_bigInt := messageToBigInt(m)
	d0_bigInt := new(big.Int)
	d0_bigInt.SetString(d0, 16)
	d_bigInt := new(big.Int)
	d_bigInt.SetString(d, 16)
	// Calculate the difference: d - d0
	numerator := new(big.Int).Sub(d_bigInt, d0_bigInt) // (d - d0)
	// Calculate the difference: m0 - m
	denominator := new(big.Int).Sub(m0_bigInt, m_bigInt) // (m0 - m)
	// Ensure denominator is not zero
	if denominator.Cmp(big.NewInt(0)) == 0 {
		return "", fmt.Errorf("division by zero: m0 and m cannot be equal")
	}
	// Compute td = (d - d0) / (m0 - m)
	td := new(big.Int).Div(numerator, denominator) // Perform integer division
	return td.Text(16), nil
}
