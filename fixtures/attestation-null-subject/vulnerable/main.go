package attestation

type Subject struct {
	Digest map[string]string
}

type Statement struct {
	Subject []*Subject
}

func verifyAttestationStatement(statement Statement) bool {
	for _, subject := range statement.Subject {
		if subject == nil {
			continue
		}
		if _, ok := subject.Digest["sha256"]; ok {
			return true
		}
	}
	return false
}
