;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(in-package #:cl-kdf)

(define-condition cl-kdf-error (error)
  ((message :initarg :message :reader cl-kdf-error-message))
  (:report (lambda (condition stream)
             (format stream "cl-kdf error: ~A" (cl-kdf-error-message condition)))))
