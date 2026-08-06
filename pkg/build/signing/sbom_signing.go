package signing

type SbomSigningOptions struct {
	Enabled bool

	signer *Signer
}

func (o SbomSigningOptions) Signer() *Signer {
	return o.signer
}

func NewSbomSigningOptions(signer *Signer) SbomSigningOptions {
	return SbomSigningOptions{
		signer: signer,
	}
}
