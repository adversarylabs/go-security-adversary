package attestation

type document struct {
	Subjects []string
}

// compactSubjects is ordinary input cleanup, not signed-content verification.
func compactSubjects(input document) document {
	output := document{}
	for _, subject := range input.Subjects {
		if subject == "" {
			continue
		}
		output.Subjects = append(output.Subjects, subject)
	}
	return output
}
