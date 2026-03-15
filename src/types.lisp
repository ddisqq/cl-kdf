;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(in-package #:cl-kdf)

;;; Core types for cl-kdf
(deftype cl-kdf-id () '(unsigned-byte 64))
(deftype cl-kdf-status () '(member :ready :active :error :shutdown))
