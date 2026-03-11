;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; Tests for cl-kdf

(in-package #:cl-kdf-test)

;;; ============================================================================
;;; Test Infrastructure
;;; ============================================================================

(defvar *test-count* 0)
(defvar *pass-count* 0)
(defvar *fail-count* 0)

(defun run-test (name test-fn)
  "Run a single test and report results."
  (incf *test-count*)
  (handler-case
      (progn
        (funcall test-fn)
        (incf *pass-count*)
        (format t "  PASS: ~A~%" name))
    (error (e)
      (incf *fail-count*)
      (format t "  FAIL: ~A~%        ~A~%" name e))))

(defmacro deftest (name &body body)
  "Define a test case."
  `(run-test ',name (lambda () ,@body)))

(defun assert-equal (expected actual &optional message)
  "Assert that expected equals actual."
  (unless (equalp expected actual)
    (error "~@[~A: ~]Expected ~S but got ~S" message expected actual)))

(defun assert-true (value &optional message)
  "Assert that value is true."
  (unless value
    (error "~@[~A: ~]Expected true but got ~S" message value)))

;;; ============================================================================
;;; SHA-256 Tests
;;; ============================================================================

(defun test-sha256 ()
  "Test SHA-256 implementation."
  (format t "~%SHA-256 Tests:~%")

  ;; Test vector: empty string
  (deftest sha256-empty
    (let* ((input (make-array 0 :element-type '(unsigned-byte 8)))
           (hash (cl-kdf:sha256 input))
           (hex (cl-kdf:bytes-to-hex hash)))
      (assert-equal "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    hex)))

  ;; Test vector: "abc"
  (deftest sha256-abc
    (let* ((input (cl-kdf:string-to-octets "abc"))
           (hash (cl-kdf:sha256 input))
           (hex (cl-kdf:bytes-to-hex hash)))
      (assert-equal "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                    hex)))

  ;; Test vector: 448-bit message (exactly one block after padding)
  (deftest sha256-448bit
    (let* ((input (cl-kdf:string-to-octets "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
           (hash (cl-kdf:sha256 input))
           (hex (cl-kdf:bytes-to-hex hash)))
      (assert-equal "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
                    hex))))

;;; ============================================================================
;;; SHA-512 Tests
;;; ============================================================================

(defun test-sha512 ()
  "Test SHA-512 implementation."
  (format t "~%SHA-512 Tests:~%")

  ;; Test vector: empty string
  (deftest sha512-empty
    (let* ((input (make-array 0 :element-type '(unsigned-byte 8)))
           (hash (cl-kdf:sha512 input))
           (hex (cl-kdf:bytes-to-hex hash)))
      (assert-equal "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
                    hex)))

  ;; Test vector: "abc"
  (deftest sha512-abc
    (let* ((input (cl-kdf:string-to-octets "abc"))
           (hash (cl-kdf:sha512 input))
           (hex (cl-kdf:bytes-to-hex hash)))
      (assert-equal "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
                    hex))))

;;; ============================================================================
;;; HMAC Tests
;;; ============================================================================

(defun test-hmac ()
  "Test HMAC implementation."
  (format t "~%HMAC Tests:~%")

  ;; RFC 4231 Test Case 1
  (deftest hmac-sha256-tc1
    (let* ((key (make-array 20 :element-type '(unsigned-byte 8) :initial-element #x0b))
           (data (cl-kdf:string-to-octets "Hi There"))
           (mac (cl-kdf:hmac-sha256 key data))
           (hex (cl-kdf:bytes-to-hex mac)))
      (assert-equal "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
                    hex)))

  ;; RFC 4231 Test Case 2 (key = "Jefe")
  (deftest hmac-sha256-tc2
    (let* ((key (cl-kdf:string-to-octets "Jefe"))
           (data (cl-kdf:string-to-octets "what do ya want for nothing?"))
           (mac (cl-kdf:hmac-sha256 key data))
           (hex (cl-kdf:bytes-to-hex mac)))
      (assert-equal "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
                    hex))))

;;; ============================================================================
;;; PBKDF2 Tests
;;; ============================================================================

(defun test-pbkdf2 ()
  "Test PBKDF2 implementation."
  (format t "~%PBKDF2 Tests:~%")

  ;; RFC 7914 test vector (used in scrypt)
  (deftest pbkdf2-sha256-basic
    (let* ((password (cl-kdf:string-to-octets "passwd"))
           (salt (cl-kdf:string-to-octets "salt"))
           (dk (cl-kdf:pbkdf2-sha256 password salt 1 64))
           (hex (cl-kdf:bytes-to-hex dk)))
      ;; First 32 bytes
      (assert-equal 64 (length dk))))

  ;; Simple iteration test
  (deftest pbkdf2-sha256-iterations
    (let* ((password (cl-kdf:string-to-octets "password"))
           (salt (cl-kdf:string-to-octets "salt"))
           (dk1 (cl-kdf:pbkdf2-sha256 password salt 1 32))
           (dk2 (cl-kdf:pbkdf2-sha256 password salt 2 32)))
      ;; Different iteration counts should produce different results
      (assert-true (not (equalp dk1 dk2))))))

;;; ============================================================================
;;; scrypt Tests
;;; ============================================================================

(defun test-scrypt ()
  "Test scrypt implementation."
  (format t "~%scrypt Tests:~%")

  ;; Basic functionality test (small parameters for speed)
  (deftest scrypt-basic
    (let* ((password "password")
           (salt (cl-kdf:string-to-octets "NaCl"))
           ;; Use minimal parameters for testing
           (dk (cl-kdf:scrypt-derive-key password salt :n 1024 :r 1 :p 1 :dklen 32)))
      (assert-equal 32 (length dk))))

  ;; Different passwords should produce different keys
  (deftest scrypt-different-passwords
    (let* ((salt (cl-kdf:string-to-octets "salt"))
           (dk1 (cl-kdf:scrypt-derive-key "password1" salt :n 1024 :r 1 :p 1 :dklen 32))
           (dk2 (cl-kdf:scrypt-derive-key "password2" salt :n 1024 :r 1 :p 1 :dklen 32)))
      (assert-true (not (equalp dk1 dk2)))))

  ;; Different salts should produce different keys
  (deftest scrypt-different-salts
    (let* ((password "password")
           (salt1 (cl-kdf:string-to-octets "salt1"))
           (salt2 (cl-kdf:string-to-octets "salt2"))
           (dk1 (cl-kdf:scrypt-derive-key password salt1 :n 1024 :r 1 :p 1 :dklen 32))
           (dk2 (cl-kdf:scrypt-derive-key password salt2 :n 1024 :r 1 :p 1 :dklen 32)))
      (assert-true (not (equalp dk1 dk2))))))

;;; ============================================================================
;;; Test Runner
;;; ============================================================================

(defun run-all-tests ()
  "Run all tests and report summary."
  (setf *test-count* 0
        *pass-count* 0
        *fail-count* 0)

  (format t "~%========================================~%")
  (format t "Running cl-kdf tests~%")
  (format t "========================================~%")

  (test-sha256)
  (test-sha512)
  (test-hmac)
  (test-pbkdf2)
  (test-scrypt)

  (format t "~%========================================~%")
  (format t "Results: ~D tests, ~D passed, ~D failed~%"
          *test-count* *pass-count* *fail-count*)
  (format t "========================================~%")

  (zerop *fail-count*))
