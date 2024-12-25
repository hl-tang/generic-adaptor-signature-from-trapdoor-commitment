package trapdoorCommitment

// TrapdoorCommitment interface
// Defines the methods for a trapdoor commitment scheme
type TrapdoorCommitment interface {
	Gen() (string, string)                              // Key generation: (ck, td)
	Com(ck, m string) (string, string)                  // Commit: (c, d)
	Verify(ck, c, m, d string) bool                     // Verify: 0/1
	TrapdoorOpen(td, c, m0, d0, m string) string        // Trapdoor Open: d
	Extract(ck, c, m0, d0, m, d string) (string, error) // Extract: td
}
