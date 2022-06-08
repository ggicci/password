package password

import (
	"crypto/rand"
	"strings"
)

// RandomSalt returns a random salt of the given length.
func RandomSalt(length uint32) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func algoPredict(hash, algo string) bool {
	return strings.HasPrefix(hash, algo)
}
