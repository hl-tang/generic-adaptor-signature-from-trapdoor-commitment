package adaptorSignature

import "crypto/ecdsa"

type CompleteSignature struct {
	sigBar    string
	Statement string // Y
	c         string
	d         string
}

type PreSignature struct {
	sigBar    string
	Statement string // Y
	c         string
	d0        string
}

// AdaptorSignature interface defines the necessary methods for an adaptor signature scheme
type AdaptorSignature interface {
	Gen() (*ecdsa.PublicKey, *ecdsa.PrivateKey)
	Sign(sk *ecdsa.PrivateKey, m string) CompleteSignature
	Ver(pk *ecdsa.PublicKey, m string, sig CompleteSignature) bool
	preSign(sk *ecdsa.PrivateKey, m string, Y string) PreSignature
	preVer(pk *ecdsa.PublicKey, m string, Y string, preSig PreSignature) bool
	Adapt(pk *ecdsa.PublicKey, m string, preSig PreSignature, y string) CompleteSignature
	Ext(pk *ecdsa.PublicKey, m string, Y string, preSig PreSignature, sig CompleteSignature) (string, error) // Extract trapdoor as the witness
}
