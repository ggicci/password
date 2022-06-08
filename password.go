package password

// Plaintext is a plaintext password and can be used to generate a password hash.
type Plaintext interface {
	// Password returns the password hash.
	Password() string
}

// Password is a hashed password who can verify the plaintext.
type Password interface {
	// Verify compares the plaintext with the hashed password.
	Verify(plaintext string) bool
}
