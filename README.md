# password

[![Go](https://github.com/ggicci/password/actions/workflows/go.yaml/badge.svg?branch=main)](https://github.com/ggicci/password/actions/workflows/go.yaml) [![codecov](https://codecov.io/gh/ggicci/password/branch/main/graph/badge.svg?token=RT61L9ngHj)](https://codecov.io/gh/ggicci/password) [![Go Report Card](https://goreportcard.com/badge/github.com/ggicci/password)](https://goreportcard.com/report/github.com/ggicci/password) [![Go Reference](https://pkg.go.dev/badge/github.com/ggicci/password.svg)](https://pkg.go.dev/github.com/ggicci/password)

Password Hash & Verification with Argon2, Bcrypt

## The Simplest API

```go
type Plaintext interface {
    Password() (string, error) // generate a password hash from a plaintext
}

type Password interface {
    Verify(plaintext string) error // verify the plaintext against the loaded password hash
}
```

## Argon2

### Generate Password Hash from Plaintext

```go
plain, err := password.NewArgon2idPlaintext("123456")
password, err := plain.Password()
// password: "$argon2id$19$2$65536$1$32$kgMI2k14vWHAbX/3hotUHQ$P/HTRZE/TuqeqJYWyDw4nhZFxBTPMIEydX291t31ZwI"
```

Save the above `password` (i.e. password hash) to your database for storage.

The above method `NewArgon2idPlaintext` uses recommended parameters for the Argon2 algorithm, including a 16 bytes random salt. If you want to tweak the parameters, apply the options as follows:

```go
plain, err := password.NewArgon2idPlaintext(
    "123456",
    Argon2Time(2),
    Argon2Salt(mySalt),
    // ...
)
```

### Verify Plaintext Password

```go
password := password.NewArgon2idPassword("$argon2id$19$.....")
err := password.Verify("123456")
if err == nil {} // matched
```

## Bcrypt

### Generate Password Hash from Plaintext

```go
plain, err := password.NewBcryptPlaintext("123456")
password, err := plain.Password()
// password: "$2a$10$4nPk/g81euJjqAFMoPIBkuOtu9I.WM4knB6rJ4Ll0HZa6BYODMskK"
```

Tweak `cost` parameter:

```go
plain, err := password.NewBcryptPlaintext("123456", BcryptCost(12))
```

### Verify Plaintext Password

```go
password, err := password.NewBcryptPassword("$2a$10$...")
err := password.Verify("123456")
if err == nil {} // matched
```

## BL

This package was originally desinged to facilitate access and verification of password with Argon2 algorithm. However, it should not be limited to Argon2 only. There're many other useful algorithms and sometimes we use them, e.g. bcrypt, scrypt, PBKDF2, etc.

If you thought the API this package provided is intuitive to use and hoped more algorithms be involved, feel free to file an issue. Contributions are more welcome.
