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

(alexandria:define-constant +private-key-auth-magic+
  "openssh-key-v1"
  :test #'equal
  :documentation "OpenSSH private key AUTH_MAGIC header")

(alexandria:define-constant +private-key-mark-begin+
  "-----BEGIN OPENSSH PRIVATE KEY-----"
  :test #'string-equal
  :documentation "Beginning marker for OpenSSH private keys")

(alexandria:define-constant +private-key-mark-end+
  "-----END OPENSSH PRIVATE KEY-----"
  :test #'string-equal
  :documentation "Ending marker for OpenSSH private keys")

(defclass base-private-key (base-key)
  ((public-key
    :initarg :public-key
    :initform (error "Must specify public key")
    :reader embedded-public-key
    :documentation "Public key embedded in the private key")
   (cipher-name
    :initarg :cipher-name
    :initform (error "Must specify cipher name")
    :reader key-cipher-name
    :documentation "Private key cipher name")
   (kdf-name
    :initarg :kdf-name
    :initform (error "Must specify KDF name")
    :reader key-kdf-name
    :documentation "Private key KDF name")
   (kdf-options
    :initarg :kdf-options
    :initform (error "Must specify KDF options")
    :reader key-kdf-options
    :documentation "Private key KDF options")
   (checksum-int
    :initarg :checksum-int
    :initform (error "Must specify checksum integer")
    :reader key-checksum-int
    :documentation "Checksum integer for private keys"))
  (:documentation "Base class for representing an OpenSSH private key"))

(defmethod fingerprintf ((hash-spec (eql :md5)) (key base-private-key) &key)
  "Computes the MD5 fingerprint of the embedded public key"
  (with-slots (public-key) key
    (fingerprint :md5 public-key)))

(defmethod fingerprint ((hash-spec (eql :sha1)) (key base-private-key) &key)
  "Computes the SHA-1 fingerprint of the embedded public key"
  (with-slots (public-key) key
    (fingerprint :sha1 public-key)))

(defmethod fingerprint ((hash-spec (eql :sha256)) (key base-private-key) &key)
  "Computes the SHA-256 fingerprint of the embedded public key"
  (with-slots (public-key) key
    (fingerprint :sha256 public-key)))

(defun extract-private-key (stream)
  "Extracts the private key contents from the given stream"
  (with-output-to-string (s)
    ;; First line should be the beginning marker
    (unless (string= +private-key-mark-begin+
                     (read-line stream))
      (error 'invalid-key-error
             :description "Invalid private key format"))
    ;; Read until the end marker
    (loop for line = (read-line stream nil nil)
          until (string= line +private-key-mark-end+)
          do
             (write-string line s))
    s))

(defun extract-private-key-from-file (path)
  "Extracts the private key contents from the given path"
  (with-open-file (in path)
    (extract-private-key in)))

(defun private-key-padding-is-correct-p (stream)
  "Predicate for deterministic check of padding after private key"
  (loop for byte = (read-byte stream nil :eof)
        for i from 1
        until (equal byte :eof) do
          (unless (= byte i)
            (return-from private-key-padding-is-correct-p nil)))
  t)
