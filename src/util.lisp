;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; Utility functions for cl-kdf

(in-package #:cl-kdf)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; Byte Vector Utilities
;;; ============================================================================

(defun hex-to-bytes (hex-string)
  "Convert hexadecimal string to byte vector."
  (declare (type string hex-string)
           (optimize (speed 3)))
  (let* ((len (length hex-string))
         (result (make-array (/ len 2) :element-type '(unsigned-byte 8))))
    (loop for i from 0 below len by 2
          for j from 0
          do (setf (aref result j)
                   (parse-integer hex-string :start i :end (+ i 2) :radix 16)))
    result))

(defun bytes-to-hex (bytes)
  "Convert byte vector to lowercase hexadecimal string."
  (declare (type (vector (unsigned-byte 8)) bytes)
           (optimize (speed 3)))
  (with-output-to-string (s)
    (loop for byte across bytes
          do (format s "~2,'0x" byte))))

(declaim (inline string-to-octets))
(defun string-to-octets (string)
  "Convert string to UTF-8 byte vector."
  (declare (type string string))
  #+sbcl (sb-ext:string-to-octets string :external-format :utf-8)
  #-sbcl
  (let* ((len (length string))
         (result (make-array len :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for char across string
          for code = (char-code char)
          do (cond
               ((< code #x80)
                (vector-push-extend code result))
               ((< code #x800)
                (vector-push-extend (logior #xC0 (ash code -6)) result)
                (vector-push-extend (logior #x80 (logand code #x3F)) result))
               ((< code #x10000)
                (vector-push-extend (logior #xE0 (ash code -12)) result)
                (vector-push-extend (logior #x80 (logand (ash code -6) #x3F)) result)
                (vector-push-extend (logior #x80 (logand code #x3F)) result))
               (t
                (vector-push-extend (logior #xF0 (ash code -18)) result)
                (vector-push-extend (logior #x80 (logand (ash code -12) #x3F)) result)
                (vector-push-extend (logior #x80 (logand (ash code -6) #x3F)) result)
                (vector-push-extend (logior #x80 (logand code #x3F)) result))))
    (coerce result '(simple-array (unsigned-byte 8) (*)))))

(defun ensure-byte-vector (data)
  "Ensure DATA is a byte vector. Convert strings to UTF-8."
  (etypecase data
    ((simple-array (unsigned-byte 8) (*)) data)
    ((vector (unsigned-byte 8))
     (let ((result (make-array (length data) :element-type '(unsigned-byte 8))))
       (replace result data)
       result))
    (string (string-to-octets data))))

;;; ============================================================================
;;; Integer/Byte Conversion
;;; ============================================================================

(declaim (inline bytes-to-uint32-be))
(defun bytes-to-uint32-be (bytes offset)
  "Convert 4 bytes to uint32 (big-endian)."
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes)
           (type fixnum offset)
           (optimize (speed 3) (safety 0)))
  (logior (ash (aref bytes offset) 24)
          (ash (aref bytes (+ offset 1)) 16)
          (ash (aref bytes (+ offset 2)) 8)
          (aref bytes (+ offset 3))))

(declaim (inline uint32-to-bytes-be))
(defun uint32-to-bytes-be (value bytes offset)
  "Convert uint32 to 4 bytes (big-endian)."
  (declare (type (unsigned-byte 32) value)
           (type (simple-array (unsigned-byte 8) (*)) bytes)
           (type fixnum offset)
           (optimize (speed 3) (safety 0)))
  (setf (aref bytes offset) (ldb (byte 8 24) value))
  (setf (aref bytes (+ offset 1)) (ldb (byte 8 16) value))
  (setf (aref bytes (+ offset 2)) (ldb (byte 8 8) value))
  (setf (aref bytes (+ offset 3)) (ldb (byte 8 0) value)))

(declaim (inline bytes-to-uint32-le))
(defun bytes-to-uint32-le (bytes offset)
  "Convert 4 bytes to uint32 (little-endian)."
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes)
           (type fixnum offset)
           (optimize (speed 3) (safety 0)))
  (logior (aref bytes offset)
          (ash (aref bytes (+ offset 1)) 8)
          (ash (aref bytes (+ offset 2)) 16)
          (ash (aref bytes (+ offset 3)) 24)))

(declaim (inline uint32-to-bytes-le))
(defun uint32-to-bytes-le (value bytes offset)
  "Convert uint32 to 4 bytes (little-endian)."
  (declare (type (unsigned-byte 32) value)
           (type (simple-array (unsigned-byte 8) (*)) bytes)
           (type fixnum offset)
           (optimize (speed 3) (safety 0)))
  (setf (aref bytes offset) (logand value #xFF))
  (setf (aref bytes (+ offset 1)) (logand (ash value -8) #xFF))
  (setf (aref bytes (+ offset 2)) (logand (ash value -16) #xFF))
  (setf (aref bytes (+ offset 3)) (logand (ash value -24) #xFF)))

(declaim (inline bytes-to-uint64-be))
(defun bytes-to-uint64-be (bytes offset)
  "Convert 8 bytes to uint64 (big-endian)."
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes)
           (type fixnum offset)
           (optimize (speed 3) (safety 0)))
  (logior (ash (aref bytes offset) 56)
          (ash (aref bytes (+ offset 1)) 48)
          (ash (aref bytes (+ offset 2)) 40)
          (ash (aref bytes (+ offset 3)) 32)
          (ash (aref bytes (+ offset 4)) 24)
          (ash (aref bytes (+ offset 5)) 16)
          (ash (aref bytes (+ offset 6)) 8)
          (aref bytes (+ offset 7))))

(declaim (inline uint64-to-bytes-be))
(defun uint64-to-bytes-be (value bytes offset)
  "Convert uint64 to 8 bytes (big-endian)."
  (declare (type (unsigned-byte 64) value)
           (type (simple-array (unsigned-byte 8) (*)) bytes)
           (type fixnum offset)
           (optimize (speed 3) (safety 0)))
  (setf (aref bytes offset) (ldb (byte 8 56) value))
  (setf (aref bytes (+ offset 1)) (ldb (byte 8 48) value))
  (setf (aref bytes (+ offset 2)) (ldb (byte 8 40) value))
  (setf (aref bytes (+ offset 3)) (ldb (byte 8 32) value))
  (setf (aref bytes (+ offset 4)) (ldb (byte 8 24) value))
  (setf (aref bytes (+ offset 5)) (ldb (byte 8 16) value))
  (setf (aref bytes (+ offset 6)) (ldb (byte 8 8) value))
  (setf (aref bytes (+ offset 7)) (ldb (byte 8 0) value)))
