package attestation

import "errors"

type Subject struct {
	Digest map[string]string
}

type Statement struct {
	Subject []*Subject
}

func verifyAttestationStatement(statement Statement) error {
	for _, subject := range statement.Subject {
		if subject == nil {
			return errors.New("invalid statement: null subject")
		}
	}
	return nil
}
