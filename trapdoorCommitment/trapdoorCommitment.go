package trapdoorcommitment

import "math/big"

// TrapdoorCommitment interface
// Defines the methods for a trapdoor commitment scheme
type TrapdoorCommitment interface {
	Gen() (*big.Int, *big.Int)                              // Key generation: (ck, td)
	Com(ck, m *big.Int) (*big.Int, *big.Int)                // Commit: (c, d)
	Verify(ck, c, m, d *big.Int) bool                       // Verify: 0/1
	TrapdoorOpen(td, c, m0, d0, m *big.Int) *big.Int        // Trapdoor Open: d
	Extract(ck, c, m0, d0, m, d *big.Int) (*big.Int, error) // Extract: td
}
