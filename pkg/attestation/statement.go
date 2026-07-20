package attestation

import (
	"encoding/json"
	"fmt"

	"github.com/in-toto/in-toto-golang/in_toto"
)

const InTotoStatementType = "https://in-toto.io/Statement/v1"

type inTotoStatement struct {
	in_toto.StatementHeader
	Predicate json.RawMessage `json:"predicate"`
}

func WrapInInTotoStatement(predicate []byte, predicateType, repo, digestHex string) ([]byte, error) {
	stmt := inTotoStatement{
		StatementHeader: in_toto.StatementHeader{
			Type:          InTotoStatementType,
			PredicateType: predicateType,
			Subject: []in_toto.Subject{{
				Name:   repo,
				Digest: map[string]string{"sha256": digestHex},
			}},
		},
		Predicate: json.RawMessage(predicate),
	}

	stmtBytes, err := json.Marshal(stmt)
	if err != nil {
		return nil, fmt.Errorf("marshal in-toto statement: %w", err)
	}

	return stmtBytes, nil
}

func UnwrapInTotoStatement(statementJSON []byte) (json.RawMessage, string, error) {
	var stmt inTotoStatement
	if err := json.Unmarshal(statementJSON, &stmt); err != nil {
		return nil, "", fmt.Errorf("unmarshal in-toto statement: %w", err)
	}

	if stmt.Type != InTotoStatementType {
		return nil, "", fmt.Errorf("unexpected in-toto statement type %q, expected %q", stmt.Type, InTotoStatementType)
	}

	return stmt.Predicate, stmt.PredicateType, nil
}
