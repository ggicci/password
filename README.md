# password

Password Hash & Verification with Argon2

## Generate Password Hash from Plaintext

```go
plain, err := password.NewArgon2idPlaintext("123456")
password := plain.Password() // $argon2id$19$2$65536$1$32$kgMI2k14vWHAbX/3hotUHQ$P/HTRZE/TuqeqJYWyDw4nhZFxBTPMIEydX291t31ZwI
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

## Verify Plaintext Password

```go
password, err := password.NewArgon2idPassword("$argon2id$19$.....")
password.Verify("123456") // test if "123456" is the correct plaintext password
```

## BL

This package was originally desinged to facilitate access and verification of password with Argon2 algorithm. However, it should not be limited to Argon2 only. There're many other useful algorithms and sometimes we use them, e.g. bcrypt, scrypt, PBKDF2, etc.

If you thought the API this package provided is intuitive to use and hoped more algorithms be involved, feel free to file an issue. Contributions are more welcome.
