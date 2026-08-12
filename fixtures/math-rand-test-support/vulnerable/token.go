package token

import (
	"fmt"
	"math/rand"
)

func fakeToken() string {
	return fmt.Sprintf("session-%d", rand.Int63())
}
