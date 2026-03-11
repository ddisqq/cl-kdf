;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; PBKDF2 implementation per RFC 2898 / NIST SP 800-132

(in-package #:cl-kdf)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; PBKDF2-SHA256
;;; ============================================================================

(defun pbkdf2-sha256 (password salt iterations key-length)
  "Derive key using PBKDF2 with HMAC-SHA256.

PARAMETERS:
  PASSWORD - password string or byte vector
  SALT - salt byte vector (minimum 16 bytes recommended)
  ITERATIONS - iteration count (minimum 600000 recommended for 2024)
  KEY-LENGTH - desired output length in bytes

RETURNS:
  Derived key of KEY-LENGTH bytes

STANDARDS:
  RFC 2898: PKCS #5 v2.0
  NIST SP 800-132: Password-Based Key Derivation

SECURITY:
  Use at least 600,000 iterations for SHA-256 per OWASP 2024."
  (declare (type (or string (vector (unsigned-byte 8))) password)
           (type (vector (unsigned-byte 8)) salt)
           (type fixnum iterations key-length)
           (optimize (speed 3) (safety 1)))
  (let* ((password (ensure-byte-vector password))
         (salt (ensure-byte-vector salt))
         (h-len 32)  ; SHA-256 output length
         (num-blocks (ceiling key-length h-len))
         (result (make-array (* num-blocks h-len) :element-type '(unsigned-byte 8))))
    (loop for i from 1 to num-blocks
          do (let* ((u (make-array (+ (length salt) 4) :element-type '(unsigned-byte 8)))
                    (t-val (make-array h-len :element-type '(unsigned-byte 8) :initial-element 0)))
               ;; U_1 = HMAC(password, salt || INT(i))
               (replace u salt)
               ;; INT(i) is big-endian 4-byte encoding
               (setf (aref u (+ (length salt) 0)) (ldb (byte 8 24) i)
                     (aref u (+ (length salt) 1)) (ldb (byte 8 16) i)
                     (aref u (+ (length salt) 2)) (ldb (byte 8 8) i)
                     (aref u (+ (length salt) 3)) (ldb (byte 8 0) i))
               (let ((u-prev (hmac-sha256 password u)))
                 ;; T = U_1
                 (replace t-val u-prev)
                 ;; U_2 .. U_c: XOR each iteration result
                 (loop for j from 2 to iterations
                       do (let ((u-next (hmac-sha256 password u-prev)))
                            (loop for k from 0 below h-len
                                  do (setf (aref t-val k)
                                           (logxor (aref t-val k) (aref u-next k))))
                            (setf u-prev u-next))))
               ;; Copy T_i to result
               (replace result t-val :start1 (* (1- i) h-len))))
    (subseq result 0 key-length)))

;;; ============================================================================
;;; PBKDF2-SHA512
;;; ============================================================================

(defun pbkdf2-sha512 (password salt iterations key-length)
  "Derive key using PBKDF2 with HMAC-SHA512.

PARAMETERS:
  PASSWORD - password string or byte vector
  SALT - salt byte vector (minimum 16 bytes recommended)
  ITERATIONS - iteration count (minimum 210000 recommended for 2024)
  KEY-LENGTH - desired output length in bytes

RETURNS:
  Derived key of KEY-LENGTH bytes

STANDARDS:
  RFC 2898: PKCS #5 v2.0
  NIST SP 800-132: Password-Based Key Derivation"
  (declare (type (or string (vector (unsigned-byte 8))) password)
           (type (vector (unsigned-byte 8)) salt)
           (type fixnum iterations key-length)
           (optimize (speed 3) (safety 1)))
  (let* ((password (ensure-byte-vector password))
         (salt (ensure-byte-vector salt))
         (h-len 64)  ; SHA-512 output length
         (num-blocks (ceiling key-length h-len))
         (result (make-array (* num-blocks h-len) :element-type '(unsigned-byte 8))))
    (loop for i from 1 to num-blocks
          do (let* ((u (make-array (+ (length salt) 4) :element-type '(unsigned-byte 8)))
                    (t-val (make-array h-len :element-type '(unsigned-byte 8) :initial-element 0)))
               (replace u salt)
               (setf (aref u (+ (length salt) 0)) (ldb (byte 8 24) i)
                     (aref u (+ (length salt) 1)) (ldb (byte 8 16) i)
                     (aref u (+ (length salt) 2)) (ldb (byte 8 8) i)
                     (aref u (+ (length salt) 3)) (ldb (byte 8 0) i))
               (let ((u-prev (hmac-sha512 password u)))
                 (replace t-val u-prev)
                 (loop for j from 2 to iterations
                       do (let ((u-next (hmac-sha512 password u-prev)))
                            (loop for k from 0 below h-len
                                  do (setf (aref t-val k)
                                           (logxor (aref t-val k) (aref u-next k))))
                            (setf u-prev u-next))))
               (replace result t-val :start1 (* (1- i) h-len))))
    (subseq result 0 key-length)))
