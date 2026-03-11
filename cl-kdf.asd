;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

(defsystem "cl-kdf"
  :version "1.0.0"
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
  :in-order-to ((test-op (test-op "cl-kdf/test"))))

(defsystem "cl-kdf/test"
  :depends-on ("cl-kdf")
  :serial t
  :components ((:module "test"
                :serial t
                :components ((:file "tests"))))
  :perform (test-op (o s)
             (uiop:symbol-call :cl-kdf.test :run-tests)))
