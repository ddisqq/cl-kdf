;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; HMAC implementation per RFC 2104 / FIPS 198-1

(in-package #:cl-kdf)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; HMAC-SHA256
;;; ============================================================================

(defun hmac-sha256 (key message)
  "Compute HMAC-SHA256. Returns 32-byte vector.

PARAMETERS:
  KEY - secret key (byte vector or string)
  MESSAGE - message to authenticate (byte vector or string)

RETURNS:
  32-byte authentication tag

STANDARDS:
  RFC 2104: HMAC
  FIPS 198-1: The Keyed-Hash Message Authentication Code"
  (declare (optimize (speed 3) (safety 1)))
  (let* ((key (ensure-byte-vector key))
         (message (ensure-byte-vector message))
         (block-size 64)
         (key-len (length key)))
    ;; If key is longer than block size, hash it
    (when (> key-len block-size)
      (setf key (sha256 key)))
    ;; Pad key to block size
    (when (< (length key) block-size)
      (let ((padded (make-array block-size :element-type '(unsigned-byte 8) :initial-element 0)))
        (replace padded key)
        (setf key padded)))
    ;; Compute HMAC: H((K XOR opad) || H((K XOR ipad) || message))
    (let ((o-key-pad (make-array block-size :element-type '(unsigned-byte 8)))
          (i-key-pad (make-array block-size :element-type '(unsigned-byte 8))))
      ;; XOR key with ipad (0x36) and opad (0x5c)
      (loop for i from 0 below block-size
            do (setf (aref o-key-pad i) (logxor (aref key i) #x5c)
                     (aref i-key-pad i) (logxor (aref key i) #x36)))
      ;; Inner hash: H(K XOR ipad || message)
      (let ((inner (make-array (+ block-size (length message))
                               :element-type '(unsigned-byte 8))))
        (replace inner i-key-pad)
        (replace inner message :start1 block-size)
        (let ((inner-hash (sha256 inner))
              ;; Outer hash: H(K XOR opad || inner-hash)
              (outer (make-array (+ block-size 32) :element-type '(unsigned-byte 8))))
          (replace outer o-key-pad)
          (replace outer inner-hash :start1 block-size)
          (sha256 outer))))))

;;; ============================================================================
;;; HMAC-SHA512
;;; ============================================================================

(defun hmac-sha512 (key message)
  "Compute HMAC-SHA512. Returns 64-byte vector.

PARAMETERS:
  KEY - secret key (byte vector or string)
  MESSAGE - message to authenticate (byte vector or string)

RETURNS:
  64-byte authentication tag

STANDARDS:
  RFC 2104: HMAC
  FIPS 198-1: The Keyed-Hash Message Authentication Code"
  (declare (optimize (speed 3) (safety 1)))
  (let* ((key (ensure-byte-vector key))
         (message (ensure-byte-vector message))
         (block-size 128)
         (key-len (length key)))
    ;; If key is longer than block size, hash it
    (when (> key-len block-size)
      (setf key (sha512 key)))
    ;; Pad key to block size
    (when (< (length key) block-size)
      (let ((padded (make-array block-size :element-type '(unsigned-byte 8) :initial-element 0)))
        (replace padded key)
        (setf key padded)))
    ;; Compute HMAC
    (let ((o-key-pad (make-array block-size :element-type '(unsigned-byte 8)))
          (i-key-pad (make-array block-size :element-type '(unsigned-byte 8))))
      (loop for i from 0 below block-size
            do (setf (aref o-key-pad i) (logxor (aref key i) #x5c)
                     (aref i-key-pad i) (logxor (aref key i) #x36)))
      (let ((inner (make-array (+ block-size (length message))
                               :element-type '(unsigned-byte 8))))
        (replace inner i-key-pad)
        (replace inner message :start1 block-size)
        (let ((inner-hash (sha512 inner))
              (outer (make-array (+ block-size 64) :element-type '(unsigned-byte 8))))
          (replace outer o-key-pad)
          (replace outer inner-hash :start1 block-size)
          (sha512 outer))))))
