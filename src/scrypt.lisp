;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; scrypt implementation per RFC 7914

(in-package #:cl-kdf)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; scrypt Constants
;;; ============================================================================

(defconstant +scrypt-default-n+ 32768
  "Default N parameter (2^15) - CPU/memory cost factor.")

(defconstant +scrypt-default-r+ 8
  "Default r parameter - block size parameter.")

(defconstant +scrypt-default-p+ 1
  "Default p parameter - parallelization parameter.")

(defparameter *scrypt-max-memory* (* 256 1024 1024)
  "Maximum memory usage for scrypt operations (256 MB).")

(defparameter *scrypt-max-n* 1048576
  "Maximum N parameter to prevent DoS (2^20).")

(defparameter *scrypt-min-n* 1024
  "Minimum N parameter for reasonable security (2^10).")

;;; ============================================================================
;;; Salsa20/8 Core - RFC 7914 Section 3
;;; ============================================================================

(declaim (inline rotl32))
(defun rotl32 (x n)
  "32-bit left rotation."
  (declare (type (unsigned-byte 32) x)
           (type (integer 0 31) n)
           (optimize (speed 3) (safety 0)))
  (logand #xFFFFFFFF
          (logior (ash x n)
                  (ash x (- n 32)))))

(defun salsa20-quarterround (y0 y1 y2 y3)
  "Salsa20 quarter round function per RFC 7914 Section 3.
Uses ADD-then-rotate (not XOR-then-rotate)."
  (declare (type (unsigned-byte 32) y0 y1 y2 y3)
           (optimize (speed 3) (safety 0)))
  (let* ((z1 (logxor y1 (rotl32 (logand #xFFFFFFFF (+ y0 y3)) 7)))
         (z2 (logxor y2 (rotl32 (logand #xFFFFFFFF (+ z1 y0)) 9)))
         (z3 (logxor y3 (rotl32 (logand #xFFFFFFFF (+ z2 z1)) 13)))
         (z0 (logxor y0 (rotl32 (logand #xFFFFFFFF (+ z3 z2)) 18))))
    (values z0 z1 z2 z3)))

(defun salsa20/8-core (input)
  "Execute Salsa20/8 core function on 64-byte input.
Returns 64-byte output."
  (declare (type (simple-array (unsigned-byte 8) (64)) input)
           (optimize (speed 3) (safety 0)))
  ;; Convert bytes to 16 x uint32 words (little-endian)
  (let ((x (make-array 16 :element-type '(unsigned-byte 32))))
    (dotimes (i 16)
      (setf (aref x i) (bytes-to-uint32-le input (* i 4))))
    ;; Store original state
    (let ((b (make-array 16 :element-type '(unsigned-byte 32))))
      (dotimes (i 16)
        (setf (aref b i) (aref x i)))
      ;; 8 rounds (4 double rounds)
      (dotimes (round 4)
        ;; Column round
        (multiple-value-bind (z0 z4 z8 z12)
            (salsa20-quarterround (aref x 0) (aref x 4) (aref x 8) (aref x 12))
          (setf (aref x 0) z0 (aref x 4) z4 (aref x 8) z8 (aref x 12) z12))
        (multiple-value-bind (z5 z9 z13 z1)
            (salsa20-quarterround (aref x 5) (aref x 9) (aref x 13) (aref x 1))
          (setf (aref x 5) z5 (aref x 9) z9 (aref x 13) z13 (aref x 1) z1))
        (multiple-value-bind (z10 z14 z2 z6)
            (salsa20-quarterround (aref x 10) (aref x 14) (aref x 2) (aref x 6))
          (setf (aref x 10) z10 (aref x 14) z14 (aref x 2) z2 (aref x 6) z6))
        (multiple-value-bind (z15 z3 z7 z11)
            (salsa20-quarterround (aref x 15) (aref x 3) (aref x 7) (aref x 11))
          (setf (aref x 15) z15 (aref x 3) z3 (aref x 7) z7 (aref x 11) z11))
        ;; Row round
        (multiple-value-bind (z0 z1 z2 z3)
            (salsa20-quarterround (aref x 0) (aref x 1) (aref x 2) (aref x 3))
          (setf (aref x 0) z0 (aref x 1) z1 (aref x 2) z2 (aref x 3) z3))
        (multiple-value-bind (z5 z6 z7 z4)
            (salsa20-quarterround (aref x 5) (aref x 6) (aref x 7) (aref x 4))
          (setf (aref x 5) z5 (aref x 6) z6 (aref x 7) z7 (aref x 4) z4))
        (multiple-value-bind (z10 z11 z8 z9)
            (salsa20-quarterround (aref x 10) (aref x 11) (aref x 8) (aref x 9))
          (setf (aref x 10) z10 (aref x 11) z11 (aref x 8) z8 (aref x 9) z9))
        (multiple-value-bind (z15 z12 z13 z14)
            (salsa20-quarterround (aref x 15) (aref x 12) (aref x 13) (aref x 14))
          (setf (aref x 15) z15 (aref x 12) z12 (aref x 13) z13 (aref x 14) z14)))
      ;; Add original state
      (dotimes (i 16)
        (setf (aref x i) (logand #xFFFFFFFF (+ (aref x i) (aref b i)))))
      ;; Convert back to bytes
      (let ((output (make-array 64 :element-type '(unsigned-byte 8))))
        (dotimes (i 16)
          (uint32-to-bytes-le (aref x i) output (* i 4)))
        output))))

;;; ============================================================================
;;; BlockMix - RFC 7914 Section 4
;;; ============================================================================

(defun scrypt-blockmix (b r)
  "BlockMix mixing function. Processes 2*r blocks of 64 bytes each."
  (declare (type (simple-array (unsigned-byte 8) (*)) b)
           (type fixnum r)
           (optimize (speed 3) (safety 1)))
  (let* ((block-count (* 2 r))
         (x (make-array 64 :element-type '(unsigned-byte 8)))
         (y (make-array (length b) :element-type '(unsigned-byte 8))))
    ;; X = B[2*r - 1]
    (replace x b :start2 (* 64 (1- block-count)) :end2 (* 64 block-count))
    ;; Process each block
    (dotimes (i block-count)
      (let ((block-offset (* i 64)))
        ;; T = X XOR B[i]
        (dotimes (j 64)
          (setf (aref x j) (logxor (aref x j) (aref b (+ block-offset j)))))
        ;; X = Salsa20/8(T)
        (let ((salsa-result (salsa20/8-core x)))
          (replace x salsa-result))
        ;; Y[i] = X (reordered: even to first half, odd to second half)
        (if (evenp i)
            (replace y x :start1 (* 64 (/ i 2)))
            (replace y x :start1 (* 64 (+ r (/ (1- i) 2)))))))
    y))

;;; ============================================================================
;;; ROMix - RFC 7914 Section 5
;;; ============================================================================

(defun scrypt-romix (b n r)
  "ROMix memory-hard mixing function (core of scrypt).

PARAMETERS:
  B - input block (128*r bytes)
  N - iteration count (must be power of 2)
  R - block size parameter

This is intentionally memory-hard: requires O(N*r) memory."
  (declare (type (simple-array (unsigned-byte 8) (*)) b)
           (type fixnum n r)
           (optimize (speed 3) (safety 1)))
  (let* ((block-size (* 128 r))
         (v (make-array (* n block-size) :element-type '(unsigned-byte 8)))
         (x (make-array block-size :element-type '(unsigned-byte 8))))
    ;; Initialize X = B
    (replace x b)
    ;; Step 1: Fill V array
    (dotimes (i n)
      ;; V[i] = X
      (replace v x :start1 (* i block-size))
      ;; X = BlockMix(X)
      (setf x (scrypt-blockmix x r)))
    ;; Step 2: Mix using random access to V
    (dotimes (i n)
      ;; j = Integerify(X) mod N
      (let* ((j (mod (bytes-to-uint32-le x (* 64 (1- (* 2 r)))) n))
             (v-offset (* j block-size)))
        ;; X = BlockMix(X XOR V[j])
        (dotimes (k block-size)
          (setf (aref x k) (logxor (aref x k) (aref v (+ v-offset k)))))
        (setf x (scrypt-blockmix x r))))
    x))

;;; ============================================================================
;;; Main scrypt Function - RFC 7914 Section 6
;;; ============================================================================

(defun scrypt-derive-key (password salt &key (n +scrypt-default-n+)
                                             (r +scrypt-default-r+)
                                             (p +scrypt-default-p+)
                                             (dklen 32))
  "Derive cryptographic key from password using memory-hard scrypt KDF.

PARAMETERS:
  PASSWORD - password string or byte vector
  SALT - salt byte vector (32 bytes recommended)
  N - CPU/memory cost parameter (power of 2, default 32768)
  R - block size parameter (default 8)
  P - parallelization parameter (default 1)
  DKLEN - desired key length in bytes (default 32)

RETURNS:
  Derived key of DKLEN bytes

STANDARDS:
  RFC 7914: scrypt key derivation function

MEMORY USAGE:
  128 * N * r bytes (e.g., 33 MB for N=32768, r=8)

PARAMETER GUIDELINES:
  N=16384:  ~100ms, 16 MB (interactive)
  N=32768:  ~200ms, 33 MB (standard)
  N=131072: ~2s, 128 MB (OWASP minimum for 2024)
  N=1048576: ~30s, 1 GB (high security)"
  (declare (type (or string (vector (unsigned-byte 8))) password)
           (type (vector (unsigned-byte 8)) salt)
           (type fixnum n r p dklen)
           (optimize (speed 3) (safety 1)))
  ;; Validate parameters
  (unless (and (plusp n) (plusp r) (plusp p) (plusp dklen))
    (error "All scrypt parameters must be positive"))
  (when (< n *scrypt-min-n*)
    (warn "scrypt N=~D is below recommended minimum ~D" n *scrypt-min-n*))
  (when (> n *scrypt-max-n*)
    (error "scrypt N=~D exceeds maximum ~D" n *scrypt-max-n*))
  ;; N must be power of 2
  (unless (= n (ash 1 (1- (integer-length n))))
    (error "scrypt N must be a power of 2, got ~D" n))
  ;; Convert password
  (let* ((password-bytes (ensure-byte-vector password))
         (salt-bytes (ensure-byte-vector salt))
         (block-size (* 128 r)))
    ;; Check memory requirements
    (let ((memory-bytes (* p n block-size)))
      (when (> memory-bytes *scrypt-max-memory*)
        (warn "scrypt will use ~D bytes of memory (> ~D limit)"
              memory-bytes *scrypt-max-memory*)))
    ;; Step 1: B = PBKDF2(P, S, 1, p * 128 * r)
    (let* ((b-size (* p block-size))
           (b (pbkdf2-sha256 password-bytes salt-bytes 1 b-size)))
      ;; Step 2: Process each block with ROMix
      (dotimes (i p)
        (let* ((block-start (* i block-size))
               (block-end (+ block-start block-size))
               (block (subseq b block-start block-end))
               (mixed (scrypt-romix block n r)))
          (replace b mixed :start1 block-start)))
      ;; Step 3: DK = PBKDF2(P, B, 1, dkLen)
      (pbkdf2-sha256 password-bytes b 1 dklen))))
