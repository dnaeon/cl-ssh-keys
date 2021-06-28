;; Copyright (c) 2020 Marin Atanasov Nikolov <dnaeon@gmail.com>
;; All rights reserved.
;;
;; Redistribution and use in source and binary forms, with or without
;; modification, are permitted provided that the following conditions
;; are met:
;;
;;  1. Redistributions of source code must retain the above copyright
;;     notice, this list of conditions and the following disclaimer
;;     in this position and unchanged.
;;  2. Redistributions in binary form must reproduce the above copyright
;;     notice, this list of conditions and the following disclaimer in the
;;     documentation and/or other materials provided with the distribution.
;;
;; THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
;; IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
;; OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
;; IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
;; INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
;; NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
;; DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
;; THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
;; (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
;; THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

(in-package :cl-ssh-keys)

(define-condition base-error (simple-error)
  ((description
    :initarg :description
    :reader error-description))
  (:documentation "Base error condition")
  (:report (lambda (condition stream)
             (format stream "~a" (error-description condition)))))

(define-condition invalid-key-error (base-error)
  ()
  (:documentation "Signaled when a key is detected as invalid")
  (:report (lambda (condition stream)
             (format stream "Invalid key error: ~a~&" (error-description condition)))))

(define-condition key-type-mismatch-error (base-error)
  ((expected
    :initarg :expected
    :reader error-expected-key-type)
   (found
    :initarg :found
    :reader error-found-key-type))
  (:documentation "Signaled when there is a mismatch between the known key type and the encoded key type")
  (:report (lambda (condition stream)
             (format stream "~a. Expected key type ~a, but found ~a~&"
                     (error-description condition)
                     (error-expected-key-type condition)
                     (error-found-key-type condition)))))

(define-condition unsupported-key-error (base-error)
  ()
  (:documentation "Signaled when attempting to perform an operation on keys that are not supported")
  (:report (lambda (condition stream)
             (format stream "~a~&" (error-description condition)))))
