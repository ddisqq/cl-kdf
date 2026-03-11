# cl-kdf

Pure Common Lisp Key Derivation Functions library. Zero external dependencies.

## Features

- **PBKDF2-SHA256/SHA512** - Password-Based Key Derivation (RFC 2898, NIST SP 800-132)
- **scrypt** - Memory-hard key derivation (RFC 7914)
- **SHA-256/SHA-512** - Cryptographic hash functions (FIPS 180-4)
- **HMAC-SHA256/HMAC-SHA512** - Keyed-hash message authentication (RFC 2104, FIPS 198-1)

## Installation

```lisp
(asdf:load-system :cl-kdf)
```

## Usage

### PBKDF2

```lisp
(cl-kdf:pbkdf2-sha256 "password"
                      (cl-kdf:string-to-octets "salt")
                      600000   ; iterations (OWASP 2024 minimum)
                      32)      ; key length
```

### scrypt

```lisp
(cl-kdf:scrypt-derive-key "password"
                          (cl-kdf:string-to-octets "salt")
                          :n 32768   ; CPU/memory cost (2^15)
                          :r 8       ; block size
                          :p 1       ; parallelization
                          :dklen 32) ; key length
```

### SHA-256

```lisp
(cl-kdf:sha256 (cl-kdf:string-to-octets "data"))
```

### HMAC

```lisp
(cl-kdf:hmac-sha256 key-bytes message-bytes)
```

## Parameter Guidelines

### PBKDF2-SHA256

| Use Case | Iterations | Notes |
|----------|------------|-------|
| Interactive | 600,000 | OWASP 2024 minimum |
| File encryption | 1,000,000+ | Higher security |

### scrypt

| Use Case | N | r | p | Memory |
|----------|---|---|---|--------|
| Interactive | 16384 | 8 | 1 | 16 MB |
| Standard | 32768 | 8 | 1 | 33 MB |
| High security | 131072 | 8 | 1 | 128 MB |

## Testing

```lisp
(asdf:test-system :cl-kdf)
```

## License

BSD-3-Clause. See LICENSE file.

## Standards Compliance

- RFC 2898: PKCS #5 v2.0 (PBKDF2)
- RFC 7914: scrypt
- RFC 2104: HMAC
- FIPS 180-4: SHA-256, SHA-512
- FIPS 198-1: HMAC
- NIST SP 800-132: Password-Based Key Derivation
