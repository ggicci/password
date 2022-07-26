package password

import (
	"bytes"
	"encoding/base64"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Argon2Password struct {
	Time        uint32
	Memory      uint32
	Parallelism uint8
	KeyLen      uint32
	Salt        []byte

	plaintext     []byte
	password      []byte
	key           []byte
	useRandomSalt bool
}

// NewArgon2idPlaintext creates a plaintext password that can be hashed with Argon2id.
func NewArgon2idPlaintext(plaintext string, opts ...Argon2PasswordOption) (Plaintext, error) {
	p := &Argon2Password{
		Time:        2,
		Memory:      64 * 1024,
		Parallelism: 1,
		KeyLen:      32,
		Salt:        nil, // lazy initialization

		plaintext:     []byte(plaintext),
		password:      nil,
		key:           nil,
		useRandomSalt: true,
	}

	for _, opt := range opts {
		opt(p)
	}

	if p.Salt == nil && p.useRandomSalt {
		salt, err := RandomSalt(16)
		if err != nil {
			return nil, err
		}
		p.Salt = salt
	}
	return p, nil
}

// Password generates a password hash.
func (p *Argon2Password) Password() (string, error) {
	key := argon2.IDKey(p.plaintext, p.Salt, p.Time, p.Memory, p.Parallelism, p.KeyLen)
	parts := []string{
		"argon2id",                                   // algo
		strconv.Itoa(argon2.Version),                 // version
		strconv.Itoa(int(p.Time)),                    // time
		strconv.Itoa(int(p.Memory)),                  // memory
		strconv.Itoa(int(p.Parallelism)),             // parallelism
		strconv.Itoa(int(p.KeyLen)),                  // keylen
		base64.RawStdEncoding.EncodeToString(p.Salt), // salt
		base64.RawStdEncoding.EncodeToString(key),    // key
	}
	return "$" + strings.Join(parts, "$"), nil
}

// NewArgon2idPassword loads a password hash and can be used to verify a plaintext.
func NewArgon2idPassword(password string) Password {
	return &Argon2Password{
		password: []byte(password),
	}
}

func (p *Argon2Password) lazyInit() error {
	if p.key != nil {
		return nil
	}

	password := string(p.password)
	if !strings.HasPrefix(password, "$argon2id$") {
		return ErrNotArgon2idPassword
	}
	parts := strings.Split(password, "$")
	if len(parts) != 9 {
		return ErrMalformedPassword
	}
	var (
		version, _     = strconv.Atoi(parts[2])
		time, _        = strconv.Atoi(parts[3])
		memory, _      = strconv.Atoi(parts[4])
		parallelism, _ = strconv.Atoi(parts[5])
		keyLen, _      = strconv.Atoi(parts[6])
		salt, _        = base64.RawStdEncoding.DecodeString(parts[7])
		key, _         = base64.RawStdEncoding.DecodeString(parts[8])
	)

	if version != argon2.Version {
		return ErrUnsupportedAlgoVersion
	}

	p.Time = uint32(time)
	p.Memory = uint32(memory)
	p.Parallelism = uint8(parallelism)
	p.KeyLen = uint32(keyLen)
	p.Salt = salt
	p.key = key
	return nil
}

// Verify verifies the plaintext with the password hash.
func (p *Argon2Password) Verify(plaintext string) error {
	if err := p.lazyInit(); err != nil {
		return err
	}

	key := argon2.IDKey([]byte(plaintext), p.Salt, p.Time, p.Memory, p.Parallelism, p.KeyLen)
	if bytes.Equal(key, p.key) {
		return nil
	}
	return ErrMissmatchedPassword
}

// Argon2PasswordOption is a function that can be used to configure a Argon2Password.
type Argon2PasswordOption func(*Argon2Password)

// Argon2Salt sets the `salt` parameter for Argon2 algorithm.
// Recommended value is a 16 bytes random secret.
func Argon2Salt(salt []byte) Argon2PasswordOption {
	return func(p *Argon2Password) {
		p.Salt = salt
		p.useRandomSalt = false
	}
}

// Argon2Time sets the `time` parameter for Argon2 algorithm, which is the number of iterations.
// Recommended value is 2.
func Argon2Time(time uint32) Argon2PasswordOption {
	return func(p *Argon2Password) {
		p.Time = time
	}
}

// Argon2Memory sets the `memory` parameter for Argon2 algorithm, which is the memory cost, in KiB.
// Recommended value is 64 * 1024, i.e. 64 MB.
func Argon2Memory(memory uint32) Argon2PasswordOption {
	return func(p *Argon2Password) {
		p.Memory = memory
	}
}

// Argon2Parallelism sets the `parallelism` parameter for Argon2 algorithm, which is the number of threads.
// Recommended value is 1.
func Argon2Parallelism(parallelism uint8) Argon2PasswordOption {
	return func(p *Argon2Password) {
		p.Parallelism = parallelism
	}
}

// Argon2KeyLen sets the `keylen` parameter for Argon2 algorithm, the desired length of the returned hash.
// Recommended value is 32.
func Argon2KeyLen(keyLen uint32) Argon2PasswordOption {
	return func(p *Argon2Password) {
		p.KeyLen = keyLen
	}
}
