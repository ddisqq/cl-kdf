;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0

(defpackage #:cl-kdf
  (:use #:cl)
  (:documentation "Pure Common Lisp key derivation functions.

Implements:
  - PBKDF2 with SHA-256 (RFC 2898, NIST SP 800-132)
  - scrypt memory-hard KDF (RFC 7914)

Thread Safety: Yes (all functions are pure, no shared state)
Performance: SHA-256 is ~1 MB/s, scrypt is intentionally slow")
  (:export
   ;; SHA-256
   #:sha256

   ;; HMAC
   #:hmac-sha256
   #:hmac-sha512

   ;; PBKDF2
   #:pbkdf2-sha256
   #:pbkdf2-sha512

   ;; scrypt
   #:scrypt-derive-key
   #:+scrypt-default-n+
   #:+scrypt-default-r+
   #:+scrypt-default-p+

   ;; SHA-512
   #:sha512

   ;; Utilities
   #:hex-to-bytes
   #:bytes-to-hex
   #:string-to-octets))

(defpackage #:cl-kdf.test
  (:use #:cl #:cl-kdf)
  (:export #:run-tests))
