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

(in-package :cl-user)
(defpackage :cl-ssh-keys.core
  (:use :cl)
  (:nicknames :ssh-keys.core)
  (:import-from :uiop)
  (:import-from :cl-rfc4251)
  (:import-from :binascii)
  (:export
   :*key-types*
   :decode
   :get-key-type
   :base-error
   :invalid-public-key-error
   :key-type-mismatch-error))
(in-package :cl-ssh-keys.core)

(defparameter *key-types*
  '((:name "ssh-rsa"
     :plain "ssh-rsa"
     :short-name "RSA"
     :is-cert nil)
    (:name "ssh-rsa-cert-v01@openssh.com"
     :plain "ssh-rsa"
     :short-name "RSA-CERT"
     :is-cert t)
    (:name "ssh-dss"
     :plain "ssh-dss"
     :short-name "DSA"
     :is-cert nil)
    (:name "ssh-dss-cert-v01@openssh.com"
     :plain "ssh-dss"
     :short-name "DSA-CERT"
     :is-cert t)
    (:name "ecdsa-sha2-nistp256"
     :plain "ecdsa-sha2-nistp256"
     :short-name "ECDSA"
     :is-cert nil)
    (:name "ecdsa-sha2-nistp384"
     :plain "ecdsa-sha2-nistp384"
     :short-name "ECDSA"
     :is-cert nil)
    (:name "ecdsa-sha2-nistp521"
     :plain "ecdsa-sha2-nistp521"
     :short-name "ECDSA"
     :is-cert nil)
    (:name "ecdsa-sha2-nistp256-cert-v01@openssh.com"
     :plain "ecdsa-sha2-nistp256"
     :short-name "ECDSA-CERT"
     :is-cert t)
    (:name "ecdsa-sha2-nistp384-cert-v01@openssh.com"
     :plain "ecdsa-sha2-nistp384"
     :short-name "ECDSA-CERT"
     :is-cert t)
    (:name "ecdsa-sha2-nistp521-cert-v01@openssh.com"
     :plain "ecdsa-sha2-nistp521"
     :short-name "ECDSA-CERT"
     :is-cert t)
    (:name "ssh-ed25519"
     :plain "ssh-ed25519"
     :short-name "ED25519"
     :is-cert nil)
    (:name "ssh-ed25519-cert-v01@openssh.com"
     :plain "ssh-ed25519"
     :short-name "ED25519-CERT"
     :is-cert t))
  "OpenSSH key types")

(defgeneric decode-key (kind stream &key)
  (:documentation "Decodes a key with the given kind from the binary stream"))

(define-condition base-error (simple-error)
  ((description
    :initarg :description
    :reader error-description))
  (:documentation "Base error condition"))

(define-condition invalid-public-key-error (base-error)
  ()
  (:documentation "Signaled when a public key file is detected as invalid"))

(define-condition key-type-mismatch-error (base-error)
  ((expected
    :initarg :expected
    :reader error-expected-key-type)
   (found
    :initarg :found
    :reader error-found-key-type))
  (:documentation "Signaled when there is a mismatch between the public key type and the encoded key type"))

(defun get-key-type (name)
  "Get the key type identified by the given name"
  (find name *key-types*
        :key (lambda (item)
               (getf item :name))
        :test #'string=))
