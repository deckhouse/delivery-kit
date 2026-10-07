package cyclonedxutil

import (
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
)

// normalizeLicenses puts every license of a list into the field the CycloneDX
// 1.6 schema allows for it. Package sources hand werf a single license string,
// and a string in license.id must be one SPDX identifier: an SPDX expression
// ("Apache-2.0 OR MIT") becomes the expression of the list, free text ("GPLv3")
// becomes license.name. The schema also allows a list to be either several
// licenses or exactly one expression, so a list that ends up with both, or with
// several expressions, is joined into one AND expression when all its members
// are SPDX, and otherwise its expressions degrade to license.name: a license
// list means "all of these apply", and a named license cannot take part in an
// expression.
func normalizeLicenses(licenses *cdx.Licenses) *cdx.Licenses {
	if licenses == nil {
		return nil
	}

	var expressions []string
	var plain cdx.Licenses
	for _, choice := range *licenses {
		switch {
		case choice.Expression != "":
			expressions = append(expressions, choice.Expression)
		case choice.License == nil:
			continue
		case choice.License.ID == "":
			plain = append(plain, choice)
		case spdxLicenseIDKnown(choice.License.ID):
			plain = append(plain, choice)
		case spdxExpressionValid(choice.License.ID):
			expressions = append(expressions, choice.License.ID)
		default:
			license := *choice.License
			license.Name = license.ID
			license.ID = ""
			plain = append(plain, cdx.LicenseChoice{License: &license})
		}
	}

	expressions = lo.Uniq(expressions)
	if len(expressions) == 0 {
		return licensesOrNil(plain)
	}
	if len(expressions) == 1 && len(plain) == 0 {
		return &cdx.Licenses{{Expression: expressions[0]}}
	}

	allSPDX := lo.EveryBy(plain, func(choice cdx.LicenseChoice) bool { return choice.License.ID != "" })
	if !allSPDX {
		for _, expression := range expressions {
			plain = append(plain, cdx.LicenseChoice{License: &cdx.License{Name: expression}})
		}
		return licensesOrNil(plain)
	}

	terms := lo.Map(plain, func(choice cdx.LicenseChoice, _ int) string { return choice.License.ID })
	for _, expression := range expressions {
		if strings.ContainsAny(expression, " (") {
			expression = "(" + expression + ")"
		}
		terms = append(terms, expression)
	}
	return &cdx.Licenses{{Expression: strings.Join(lo.Uniq(terms), " AND ")}}
}

func licensesOrNil(licenses cdx.Licenses) *cdx.Licenses {
	if len(licenses) == 0 {
		return nil
	}
	return &licenses
}

// spdxLicenseIDKnown treats an unreadable embedded list as empty: the id then
// ends up in license.name, which the schema always accepts, and the broken
// schema is reported by the validation that runs on the serialized document.
func spdxLicenseIDKnown(id string) bool {
	known, err := SPDXLicenseIDKnown(id)
	return err == nil && known
}

// spdxExpressionValid reports whether s is a compound SPDX license expression:
// SPDX identifiers or LicenseRef/DocumentRef references combined with AND, OR,
// WITH and parentheses, as SPDX 2.3 annex D defines. A single identifier is
// not an expression here, since a single identifier belongs in license.id.
func spdxExpressionValid(s string) bool {
	tokens := tokenizeSPDXExpression(s)
	if len(tokens) < 3 {
		return false
	}

	parser := spdxExpressionParser{tokens: tokens}
	return parser.parseExpression() && parser.pos == len(tokens)
}

func tokenizeSPDXExpression(s string) []string {
	s = strings.ReplaceAll(s, "(", " ( ")
	s = strings.ReplaceAll(s, ")", " ) ")
	return strings.Fields(s)
}

type spdxExpressionParser struct {
	tokens []string
	pos    int
}

func (p *spdxExpressionParser) peek() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	return p.tokens[p.pos]
}

func (p *spdxExpressionParser) parseExpression() bool {
	if !p.parseTerm() {
		return false
	}
	for p.peek() == "AND" || p.peek() == "OR" {
		p.pos++
		if !p.parseTerm() {
			return false
		}
	}
	return true
}

func (p *spdxExpressionParser) parseTerm() bool {
	switch token := p.peek(); {
	case token == "(":
		p.pos++
		if !p.parseExpression() || p.peek() != ")" {
			return false
		}
		p.pos++
		return true
	case spdxSimpleExpression(token):
		p.pos++
		if p.peek() == "WITH" {
			p.pos++
			exception := p.peek()
			if !spdxLicenseIDKnown(exception) && !spdxLicenseRef(exception) {
				return false
			}
			p.pos++
		}
		return true
	default:
		return false
	}
}

// spdxSimpleExpression accepts an SPDX identifier, with or without the "+"
// suffix meaning "or later", or a license reference.
func spdxSimpleExpression(token string) bool {
	if token == "" {
		return false
	}
	if spdxLicenseIDKnown(token) || spdxLicenseIDKnown(strings.TrimSuffix(token, "+")) {
		return true
	}
	return spdxLicenseRef(token)
}

func spdxLicenseRef(token string) bool {
	if strings.HasPrefix(token, "DocumentRef-") {
		_, token, _ = strings.Cut(token, ":")
	}
	if !strings.HasPrefix(token, "LicenseRef-") {
		return false
	}
	ref := strings.TrimPrefix(token, "LicenseRef-")
	return ref != "" && strings.IndexFunc(ref, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.')
	}) < 0
}
