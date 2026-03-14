;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

(asdf:defsystem #:"cl-kdf"
  :version "0.1.0"
  :author "Parkian Company LLC"
  :license "BSD-3-Clause"
  :description "PBKDF2 and scrypt key derivation functions in pure Common Lisp"
  :homepage "https://github.com/parkian/cl-kdf"
  :depends-on ()
  :serial t
  :components ((:file "package")
               (:module "src"
                :serial t
                :components ((:file "util")
                             (:file "sha256")
                             (:file "hmac")
                             (:file "pbkdf2")
                             (:file "scrypt"))))
  :in-order-to ((asdf:test-op (test-op "cl-kdf/test"))))

(asdf:defsystem #:"cl-kdf/test"
  :depends-on ("cl-kdf")
  :serial t
  :components ((:module "test"
                :serial t
                :components ((:file "tests"))))
  :perform (asdf:test-op (o s)
             (let ((result (uiop:symbol-call :cl-kdf.test :run-tests)))
               (unless result
                 (error "Tests failed")))))
