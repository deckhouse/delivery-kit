package config

type Sbom struct {
	Use bool
}

func (s *Sbom) GetUse() bool {
	if s == nil {
		return false
	}

	return s.Use
}
