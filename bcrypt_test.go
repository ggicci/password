package password

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func testBcryptBasic(t *testing.T, plain Plaintext, plaintext string) {
	password, err := plain.Password()
	assert.NoError(t, err)
	t.Logf("password: %s", password)
	verifier := NewBcryptPassword(password)
	assert.NoError(t, verifier.Verify(plaintext))
	assert.Error(t, verifier.Verify(plaintext+"1"))
}

func TestBcryptPassword(t *testing.T) {
	plain, err := NewBcryptPlaintext("123456")
	assert.NoError(t, err)
	testBcryptBasic(t, plain, "123456")

	// incorrect password hash
	verifier := NewBcryptPassword("$2a$10$4nPk/g81euJjqAFMoPIBkuOtu9I.WM4knB6rJ4Ll0HZa6BYODMskt")
	assert.Error(t, verifier.Verify("123456"))

	// invalid cost
	verifier = NewBcryptPassword("$2a$99$4nPk/g81euJjqAFMoPIBkuOtu9I.WM4knB6rJ4Ll0HZa6BYODMskK")
	assert.Error(t, verifier.Verify("123456"))
}

func TestBcryptPassword_Options(t *testing.T) {
	plain, err := NewBcryptPlaintext("123456", BcryptCost(12))
	assert.NoError(t, err)
	testBcryptBasic(t, plain, "123456")
}
