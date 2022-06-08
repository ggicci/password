package password

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func testArgon2idBasic(t *testing.T, plain Plaintext, plaintext string) {
	password := plain.Password()
	t.Logf("password: %s", password)
	verifier, err := NewArgon2idPassword(password)
	assert.NoError(t, err)
	assert.True(t, verifier.Verify(plaintext))
	assert.False(t, verifier.Verify(plaintext+"1"))
}

func TestArgon2idPassword(t *testing.T) {
	plain, err := NewArgon2idPlaintext("123456")
	assert.NoError(t, err)
	testArgon2idBasic(t, plain, "123456")

	verifier, err := NewArgon2idPassword("$argon2id$19$2$65536$1$32$z8nM6bD5jWHGg4/qyPprmA$trqqulUDAjWZ550jfYBiq/0LsZXPcrMxlqBbM1TKhBx")
	assert.NoError(t, err)
	assert.False(t, verifier.Verify("123456"))

	var errorCases = []struct {
		password string
		err      error
	}{
		{"$argon$19$2$65536$1$32$z8nM6bD5jWHGg4/qyPprmA$trqqulUDAjWZ550jfYBiq/0LsZXPcrMxlqBbM1TKhBc", ErrNotArgon2idPassword},
		{"$argon2id$18$2$65536$1$32$z8nM6bD5jWHGg4/qyPprmA$trqqulUDAjWZ550jfYBiq/0LsZXPcrMxlqBbM1TKhBc", ErrUnsupportedAlgoVersion},
		{"$argon2id$19$65536$1$32$z8nM6bD5jWHGg4/qyPprmA$trqqulUDAjWZ550jfYBiq/0LsZXPcrMxlqBbM1TKhBc", ErrInvalidPassword},
	}

	for i, errorCase := range errorCases {
		verifier, err := NewArgon2idPassword(errorCase.password)
		assert.Nil(t, verifier, "case %d", i)
		assert.Equal(t, errorCase.err, err, "case %d", i)
	}
}

func TestArgon2idPassword_Options(t *testing.T) {
	mySalt, err := RandomSalt(32)
	assert.NoError(t, err)
	plain, err := NewArgon2idPlaintext("apple123", Argon2Time(1), Argon2Memory(32*1024), Argon2Parallelism(2), Argon2KeyLen(64), Argon2Salt(mySalt))
	assert.NoError(t, err)
	assert.Equal(t, plain.(*Argon2Password).Time, uint32(1))
	assert.Equal(t, plain.(*Argon2Password).Memory, uint32(32*1024))
	assert.Equal(t, plain.(*Argon2Password).Parallelism, uint8(2))
	assert.Equal(t, plain.(*Argon2Password).KeyLen, uint32(64))
	assert.Equal(t, plain.(*Argon2Password).Salt, mySalt)

	testArgon2idBasic(t, plain, "apple123")
}

func TestArgon2idPassword_Options_NilSalt(t *testing.T) {
	plain, err := NewArgon2idPlaintext("banana123+-*/", Argon2Salt(nil))
	assert.NoError(t, err)
	assert.Nil(t, plain.(*Argon2Password).Salt)
	testArgon2idBasic(t, plain, "banana123+-*/")
}
