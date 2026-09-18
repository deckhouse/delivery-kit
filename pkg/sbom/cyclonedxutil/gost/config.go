package gost

const (
	PropertyAttackSurface    = "GOST:attack_surface"
	PropertySecurityFunction = "GOST:security_function"
)

type Config struct {
	AttackSurface    GostValue `json:"attackSurface"`
	SecurityFunction GostValue `json:"securityFunction"`
}

type GostValue string

func (v GostValue) String() string {
	return string(v)
}

const (
	GostValueYes       GostValue = "yes"
	GostValueNo        GostValue = "no"
	GostValueIndirect  GostValue = "indirect"
	GostValueUndefined GostValue = ""
)

func DefaultConfig() Config {
	return Config{
		AttackSurface:    GostValueYes,
		SecurityFunction: GostValueYes,
	}
}

func (c Config) Merge(other Config) Config {
	res := c
	if !other.AttackSurface.IsUndefined() {
		res.AttackSurface = other.AttackSurface
	}
	if !other.SecurityFunction.IsUndefined() {
		res.SecurityFunction = other.SecurityFunction
	}
	return res
}

// ForDescendants derives the values carried by everything below the image root.
// An attack surface declared accessible applies to the image as a whole: an
// attacker reaches the packages it contains only through the image, so they are
// exposed indirectly. Every other value, and the security function in all cases,
// applies unchanged down the whole tree.
func (c Config) ForDescendants() Config {
	res := c
	if res.AttackSurface == GostValueYes {
		res.AttackSurface = GostValueIndirect
	}
	return res
}

func IsValidGostValue(v string) bool {
	return v == GostValueYes.String() || v == GostValueNo.String() || v == GostValueIndirect.String()
}

func (v GostValue) IsUndefined() bool {
	return v == GostValueUndefined
}

var gostValuePrecedence = map[GostValue]int{
	GostValueUndefined: 0,
	GostValueNo:        1,
	GostValueIndirect:  2,
	GostValueYes:       3,
}

// Max returns the stronger of two values: yes over indirect over no over undefined.
func Max(a, b GostValue) GostValue {
	if gostValuePrecedence[b] > gostValuePrecedence[a] {
		return b
	}
	return a
}
