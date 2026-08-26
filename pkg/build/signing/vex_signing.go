package signing

type VexSigningOptions struct {
	Enabled bool

	signer *Signer
}

func (o VexSigningOptions) Signer() *Signer {
	return o.signer
}

func NewVexSigningOptions(signer *Signer) VexSigningOptions {
	return VexSigningOptions{
		signer: signer,
	}
}
