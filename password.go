package password

// Plaintext is a plaintext password and can be used to generate a password hash.
// Typically the hash will be stored in a database.
type Plaintext interface {
	// Password returns the password hash.
	Password() (string, error)
}

// Password is a hashed password who can verify a plaintext password.
type Password interface {
	// Verify compares the plaintext with the hashed password.
	Verify(plaintext string) error
}
