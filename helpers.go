package password

import (
	"crypto/rand"
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
