;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; SHA-256 implementation per FIPS 180-4

(in-package #:cl-kdf)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; SHA-256 Constants (FIPS 180-4 Section 4.2.2)
;;; ============================================================================

(defvar +sha256-k+
  (make-array 64 :element-type '(unsigned-byte 32) :initial-contents
              '(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5 #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
                #xd807aa98 #x12835b01 #x243185be #x550c7dc3 #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
                #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
                #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7 #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
                #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13 #x650a7354 #x766a0abb #x81c2c92e #x92722c85
                #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3 #xd192e819 #xd6990624 #xf40e3585 #x106aa070
                #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5 #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
                #x748f82ee #x78a5636f #x84c87814 #x8cc70208 #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2))
  "SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes).")

;;; ============================================================================
;;; SHA-256 Operations
;;; ============================================================================

(defmacro sha256/rotr (x n)
  "32-bit right rotation."
  `(logior (ldb (byte 32 0) (ash ,x (- ,n)))
           (ldb (byte 32 0) (ash ,x (- 32 ,n)))))

(defmacro sha256/ch (x y z)
  "Ch(x, y, z) = (x AND y) XOR ((NOT x) AND z)"
  `(logxor (logand ,x ,y) (logand (lognot ,x) ,z)))

(defmacro sha256/maj (x y z)
  "Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)"
  `(logxor (logand ,x ,y) (logand ,x ,z) (logand ,y ,z)))

(defmacro sha256/sigma0 (x)
  "Big sigma 0: ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)"
  `(logxor (sha256/rotr ,x 2) (sha256/rotr ,x 13) (sha256/rotr ,x 22)))

(defmacro sha256/sigma1 (x)
  "Big sigma 1: ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)"
  `(logxor (sha256/rotr ,x 6) (sha256/rotr ,x 11) (sha256/rotr ,x 25)))

(defmacro sha256/gamma0 (x)
  "Small sigma 0: ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)"
  `(logxor (sha256/rotr ,x 7) (sha256/rotr ,x 18) (ash ,x -3)))

(defmacro sha256/gamma1 (x)
  "Small sigma 1: ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)"
  `(logxor (sha256/rotr ,x 17) (sha256/rotr ,x 19) (ash ,x -10)))

;;; ============================================================================
;;; SHA-256 Core
;;; ============================================================================

(defun sha256 (data)
  "Compute SHA-256 hash of DATA. Returns 32-byte vector.

PARAMETERS:
  DATA - byte vector or string

RETURNS:
  32-byte hash digest

STANDARDS:
  FIPS 180-4: Secure Hash Standard (SHS)"
  (declare (optimize (speed 3) (safety 1)))
  (let* ((data (ensure-byte-vector data))
         (len (length data))
         (bit-len (* len 8))
         ;; Initial hash values (FIPS 180-4 Section 5.3.3)
         (h (list #x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
                  #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19))
         (w (make-array 64 :element-type '(unsigned-byte 32))))
    ;; Pad message (FIPS 180-4 Section 5.1.1)
    (let* ((pad-len (- 64 (mod (+ len 9) 64)))
           (total-len (+ len 1 pad-len 8))
           (padded (make-array total-len :element-type '(unsigned-byte 8) :initial-element 0)))
      (replace padded data)
      (setf (aref padded len) #x80)
      ;; Append length in bits (big-endian)
      (loop for i from 0 below 8
            do (setf (aref padded (- total-len 1 i))
                     (ldb (byte 8 (* i 8)) bit-len)))
      ;; Process blocks (FIPS 180-4 Section 6.2.2)
      (loop for block-start from 0 below total-len by 64
            do (progn
                 ;; Prepare message schedule
                 (loop for i from 0 below 16
                       do (setf (aref w i)
                                (logior (ash (aref padded (+ block-start (* i 4))) 24)
                                        (ash (aref padded (+ block-start (* i 4) 1)) 16)
                                        (ash (aref padded (+ block-start (* i 4) 2)) 8)
                                        (aref padded (+ block-start (* i 4) 3)))))
                 (loop for i from 16 below 64
                       do (setf (aref w i)
                                (ldb (byte 32 0)
                                     (+ (sha256/gamma1 (aref w (- i 2)))
                                        (aref w (- i 7))
                                        (sha256/gamma0 (aref w (- i 15)))
                                        (aref w (- i 16))))))
                 ;; Initialize working variables
                 (let ((a (nth 0 h)) (b (nth 1 h)) (c (nth 2 h)) (d (nth 3 h))
                       (e (nth 4 h)) (f (nth 5 h)) (g (nth 6 h)) (hh (nth 7 h)))
                   ;; Compression function
                   (loop for i from 0 below 64
                         do (let* ((s1 (sha256/sigma1 e))
                                   (ch (sha256/ch e f g))
                                   (temp1 (ldb (byte 32 0)
                                               (+ hh s1 ch (aref +sha256-k+ i) (aref w i))))
                                   (s0 (sha256/sigma0 a))
                                   (maj (sha256/maj a b c))
                                   (temp2 (ldb (byte 32 0) (+ s0 maj))))
                              (setf hh g
                                    g f
                                    f e
                                    e (ldb (byte 32 0) (+ d temp1))
                                    d c
                                    c b
                                    b a
                                    a (ldb (byte 32 0) (+ temp1 temp2)))))
                   ;; Compute intermediate hash value
                   (setf h (list (ldb (byte 32 0) (+ (nth 0 h) a))
                                 (ldb (byte 32 0) (+ (nth 1 h) b))
                                 (ldb (byte 32 0) (+ (nth 2 h) c))
                                 (ldb (byte 32 0) (+ (nth 3 h) d))
                                 (ldb (byte 32 0) (+ (nth 4 h) e))
                                 (ldb (byte 32 0) (+ (nth 5 h) f))
                                 (ldb (byte 32 0) (+ (nth 6 h) g))
                                 (ldb (byte 32 0) (+ (nth 7 h) hh))))))))
    ;; Produce final hash value
    (let ((result (make-array 32 :element-type '(unsigned-byte 8))))
      (loop for i from 0 below 8
            for val in h
            do (setf (aref result (* i 4)) (ldb (byte 8 24) val)
                     (aref result (+ (* i 4) 1)) (ldb (byte 8 16) val)
                     (aref result (+ (* i 4) 2)) (ldb (byte 8 8) val)
                     (aref result (+ (* i 4) 3)) (ldb (byte 8 0) val)))
      result)))

;;; ============================================================================
;;; SHA-512 (for HMAC-SHA512)
;;; ============================================================================

(defvar +sha512-k+
  (make-array 80 :element-type '(unsigned-byte 64) :initial-contents
              '(#x428a2f98d728ae22 #x7137449123ef65cd #xb5c0fbcfec4d3b2f #xe9b5dba58189dbbc
                #x3956c25bf348b538 #x59f111f1b605d019 #x923f82a4af194f9b #xab1c5ed5da6d8118
                #xd807aa98a3030242 #x12835b0145706fbe #x243185be4ee4b28c #x550c7dc3d5ffb4e2
                #x72be5d74f27b896f #x80deb1fe3b1696b1 #x9bdc06a725c71235 #xc19bf174cf692694
                #xe49b69c19ef14ad2 #xefbe4786384f25e3 #x0fc19dc68b8cd5b5 #x240ca1cc77ac9c65
                #x2de92c6f592b0275 #x4a7484aa6ea6e483 #x5cb0a9dcbd41fbd4 #x76f988da831153b5
                #x983e5152ee66dfab #xa831c66d2db43210 #xb00327c898fb213f #xbf597fc7beef0ee4
                #xc6e00bf33da88fc2 #xd5a79147930aa725 #x06ca6351e003826f #x142929670a0e6e70
                #x27b70a8546d22ffc #x2e1b21385c26c926 #x4d2c6dfc5ac42aed #x53380d139d95b3df
                #x650a73548baf63de #x766a0abb3c77b2a8 #x81c2c92e47edaee6 #x92722c851482353b
                #xa2bfe8a14cf10364 #xa81a664bbc423001 #xc24b8b70d0f89791 #xc76c51a30654be30
                #xd192e819d6ef5218 #xd69906245565a910 #xf40e35855771202a #x106aa07032bbd1b8
                #x19a4c116b8d2d0c8 #x1e376c085141ab53 #x2748774cdf8eeb99 #x34b0bcb5e19b48a8
                #x391c0cb3c5c95a63 #x4ed8aa4ae3418acb #x5b9cca4f7763e373 #x682e6ff3d6b2b8a3
                #x748f82ee5defb2fc #x78a5636f43172f60 #x84c87814a1f0ab72 #x8cc702081a6439ec
                #x90befffa23631e28 #xa4506cebde82bde9 #xbef9a3f7b2c67915 #xc67178f2e372532b
                #xca273eceea26619c #xd186b8c721c0c207 #xeada7dd6cde0eb1e #xf57d4f7fee6ed178
                #x06f067aa72176fba #x0a637dc5a2c898a6 #x113f9804bef90dae #x1b710b35131c471b
                #x28db77f523047d84 #x32caab7b40c72493 #x3c9ebe0a15c9bebc #x431d67c49c100d4c
                #x4cc5d4becb3e42b6 #x597f299cfc657e2a #x5fcb6fab3ad6faec #x6c44198c4a475817))
  "SHA-512 round constants.")

(defmacro sha512/rotr (x n)
  `(logior (ldb (byte 64 0) (ash ,x (- ,n)))
           (ldb (byte 64 0) (ash ,x (- 64 ,n)))))

(defmacro sha512/ch (x y z)
  `(logxor (logand ,x ,y) (logand (lognot ,x) ,z)))

(defmacro sha512/maj (x y z)
  `(logxor (logand ,x ,y) (logand ,x ,z) (logand ,y ,z)))

(defmacro sha512/sigma0 (x)
  `(logxor (sha512/rotr ,x 28) (sha512/rotr ,x 34) (sha512/rotr ,x 39)))

(defmacro sha512/sigma1 (x)
  `(logxor (sha512/rotr ,x 14) (sha512/rotr ,x 18) (sha512/rotr ,x 41)))

(defmacro sha512/gamma0 (x)
  `(logxor (sha512/rotr ,x 1) (sha512/rotr ,x 8) (ash ,x -7)))

(defmacro sha512/gamma1 (x)
  `(logxor (sha512/rotr ,x 19) (sha512/rotr ,x 61) (ash ,x -6)))

(defun sha512 (data)
  "Compute SHA-512 hash of DATA. Returns 64-byte vector."
  (declare (optimize (speed 3) (safety 1)))
  (let* ((data (ensure-byte-vector data))
         (len (length data))
         (bit-len (* len 8))
         (h (list #x6a09e667f3bcc908 #xbb67ae8584caa73b
                  #x3c6ef372fe94f82b #xa54ff53a5f1d36f1
                  #x510e527fade682d1 #x9b05688c2b3e6c1f
                  #x1f83d9abfb41bd6b #x5be0cd19137e2179))
         (w (make-array 80 :element-type '(unsigned-byte 64))))
    ;; Pad message
    (let* ((pad-len (- 128 (mod (+ len 17) 128)))
           (total-len (+ len 1 pad-len 16))
           (padded (make-array total-len :element-type '(unsigned-byte 8) :initial-element 0)))
      (replace padded data)
      (setf (aref padded len) #x80)
      ;; Append length in bits (big-endian, 128-bit but we use 64 for length)
      (loop for i from 0 below 8
            do (setf (aref padded (- total-len 1 i))
                     (ldb (byte 8 (* i 8)) bit-len)))
      ;; Process 128-byte blocks
      (loop for block-start from 0 below total-len by 128
            do (progn
                 ;; Prepare message schedule
                 (loop for i from 0 below 16
                       do (setf (aref w i)
                                (logior (ash (aref padded (+ block-start (* i 8))) 56)
                                        (ash (aref padded (+ block-start (* i 8) 1)) 48)
                                        (ash (aref padded (+ block-start (* i 8) 2)) 40)
                                        (ash (aref padded (+ block-start (* i 8) 3)) 32)
                                        (ash (aref padded (+ block-start (* i 8) 4)) 24)
                                        (ash (aref padded (+ block-start (* i 8) 5)) 16)
                                        (ash (aref padded (+ block-start (* i 8) 6)) 8)
                                        (aref padded (+ block-start (* i 8) 7)))))
                 (loop for i from 16 below 80
                       do (setf (aref w i)
                                (ldb (byte 64 0)
                                     (+ (sha512/gamma1 (aref w (- i 2)))
                                        (aref w (- i 7))
                                        (sha512/gamma0 (aref w (- i 15)))
                                        (aref w (- i 16))))))
                 ;; Initialize working variables
                 (let ((a (nth 0 h)) (b (nth 1 h)) (c (nth 2 h)) (d (nth 3 h))
                       (e (nth 4 h)) (f (nth 5 h)) (g (nth 6 h)) (hh (nth 7 h)))
                   ;; Compression
                   (loop for i from 0 below 80
                         do (let* ((s1 (sha512/sigma1 e))
                                   (ch (sha512/ch e f g))
                                   (temp1 (ldb (byte 64 0)
                                               (+ hh s1 ch (aref +sha512-k+ i) (aref w i))))
                                   (s0 (sha512/sigma0 a))
                                   (maj (sha512/maj a b c))
                                   (temp2 (ldb (byte 64 0) (+ s0 maj))))
                              (setf hh g
                                    g f
                                    f e
                                    e (ldb (byte 64 0) (+ d temp1))
                                    d c
                                    c b
                                    b a
                                    a (ldb (byte 64 0) (+ temp1 temp2)))))
                   ;; Add to hash
                   (setf h (list (ldb (byte 64 0) (+ (nth 0 h) a))
                                 (ldb (byte 64 0) (+ (nth 1 h) b))
                                 (ldb (byte 64 0) (+ (nth 2 h) c))
                                 (ldb (byte 64 0) (+ (nth 3 h) d))
                                 (ldb (byte 64 0) (+ (nth 4 h) e))
                                 (ldb (byte 64 0) (+ (nth 5 h) f))
                                 (ldb (byte 64 0) (+ (nth 6 h) g))
                                 (ldb (byte 64 0) (+ (nth 7 h) hh))))))))
    ;; Output
    (let ((result (make-array 64 :element-type '(unsigned-byte 8))))
      (loop for i from 0 below 8
            for val in h
            do (setf (aref result (* i 8)) (ldb (byte 8 56) val)
                     (aref result (+ (* i 8) 1)) (ldb (byte 8 48) val)
                     (aref result (+ (* i 8) 2)) (ldb (byte 8 40) val)
                     (aref result (+ (* i 8) 3)) (ldb (byte 8 32) val)
                     (aref result (+ (* i 8) 4)) (ldb (byte 8 24) val)
                     (aref result (+ (* i 8) 5)) (ldb (byte 8 16) val)
                     (aref result (+ (* i 8) 6)) (ldb (byte 8 8) val)
                     (aref result (+ (* i 8) 7)) (ldb (byte 8 0) val)))
      result)))
