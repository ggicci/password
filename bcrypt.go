package password

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

type BcryptPassword struct {
	Cost int

	plaintext []byte
	password  []byte
}

func NewBcryptPlaintext(plaintext string, opts ...BcryptPasswordOption) (Plaintext, error) {
	p := &BcryptPassword{
		Cost: bcrypt.DefaultCost,

		plaintext: []byte(plaintext),
		password:  nil,
	}

	for _, opt := range opts {
		opt(p)
	}

	return p, nil
}

func (p *BcryptPassword) Password() (string, error) {
	if p.password == nil {
		password, err := bcrypt.GenerateFromPassword(p.plaintext, p.Cost)
		if err != nil {
			return "", err
		}
		p.password = password
	}
	return string(p.password), nil
}

func NewBcryptPassword(password string) Password {
	return &BcryptPassword{
		password: []byte(password),
	}
}

// Verify verifies the plaintext with the password hash.
func (p *BcryptPassword) Verify(plaintext string) error {
	if err := bcrypt.CompareHashAndPassword(p.password, []byte(plaintext)); err != nil {
		return fmt.Errorf("%w: %v", ErrMissmatchedPassword, err)
	}
	return nil
}

// BcryptPasswordOption is a function that can be used to configure a BcryptPassword.
type BcryptPasswordOption func(*BcryptPassword)

func BcryptCost(cost int) BcryptPasswordOption {
	return func(p *BcryptPassword) {
		p.Cost = cost
	}
}
