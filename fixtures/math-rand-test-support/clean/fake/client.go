package fake

import (
	"fmt"
	"math/rand"
)

// randomSecretRecord creates fake pagination data; the value is not a credential.
func randomSecretRecord() string {
	//nolint:gosec
	return fmt.Sprintf("conjur:variable:random/var_%d", rand.Intn(10000))
}
