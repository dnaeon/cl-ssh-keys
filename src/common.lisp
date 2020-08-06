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

(defclass base-key ()
  ((kind
    :initarg :kind
    :initform (error "Must specify key kind")
    :reader key-kind
    :documentation "SSH key kind")
   (comment
    :initarg :comment
    :initform nil
    :reader key-comment
    :documentation "Comment associated with the key"))
  (:documentation "Base class for representing an OpenSSH key"))

(defclass base-public-key (base-key)
  ()
  (:documentation "Base class for representing an OpenSSH public key"))

(defclass base-private-key (base-key)
  ((public-key
    :initarg :public-key
    :initform (error "Must specify public key")
    :reader embedded-public-key
    :documentation "Public key embedded in the private key"))
  (:documentation "Base class for representing an OpenSSH private key"))

(defun public-key-file-parts (path)
  "Returns the parts of an OpenSSH public key file"
  (with-open-file (in path)
    (uiop:split-string (read-line in) :separator '(#\Space))))

(defun parse-public-key-file (path)
  "Parses an OpenSSH public key file from the given path"
  (let* ((parts (public-key-file-parts path))
         (key-type (get-key-type (first parts)))
         (data (second parts))
         (comment (third parts)))
    ;; We need a key identifier
    (unless key-type
      (error 'invalid-public-key-error
             :description "Missing key type"))

    ;; OpenSSH public keys are encoded in a way, so that the
    ;; key kind preceeds the actual public key components.
    ;; See RFC 4253 for more details.
    (let* ((stream (rfc4251:make-binary-input-stream (binascii:decode-base64 data)))
           (key-type-name (getf key-type :name))
           (encoded-key-type-name (rfc4251:decode :string stream)))
      (unless (string= key-type-name encoded-key-type-name)
        (error 'key-type-mismatch-error
               :description "Key types mismatch"
               :expected want-key-type-name
               :found encoded-key-type-name))

      (alexandria:switch (key-type-name :test #'equal)
        ("ssh-rsa" (decode :rsa-public-key stream :kind key-type :comment comment))
        (t
         (error 'invalid-public-key-error :description (format nil "Unknown key type ~a" key-type-name)))))))

(defun fingerprint (key &optional (hash :sha256))
  "Computes the fingerprint of the given key"
  (let* ((stream (rfc4251:make-binary-output-stream))
         (encoded-size (rfc4251:encode :public-key key stream))
         (bytes (rfc4251:binary-output-stream-data stream)))
    (declare (ignore encoded-size))
    (case hash
      ((:sha1 :sha256) (fingerprint-sha1/sha256 bytes hash))
      (:md5 (fingerprint-md5 bytes))
      (t
       (error 'unknown-fingerprint-hash-error
              :description (format nil "Unknown fingerprint hash algorithm ~a" hash))))))

(defun fingerprint-sha1/sha256 (bytes &optional (hash :sha256))
  "Computes the SHA-1 or SHA-256 fingerprint of the given bytes"
  (let* ((digest (ironclad:digest-sequence hash bytes))
         (encoded (binascii:encode-base64 digest))
         (trim-position (position #\= encoded :test #'char=)))
    (subseq encoded 0 trim-position)))

(defun fingerprint-md5 (bytes)
  "Computes the MD5 fingerprint of the given bytes"
  (let* ((digest (ironclad:digest-sequence :md5 bytes)))
    (format nil "~{~(~2,'0x~)~^:~}" (map 'list #'identity digest))))
