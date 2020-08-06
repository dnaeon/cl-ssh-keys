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

(defmethod rfc4251:decode ((type (eql :public-key)) stream &key key-type-name comment)
  "Decode a public key from the given stream. If KEY-TYPE-NAME is specified
then we dispatch decoding to the respective implementation of the given
KEY-TYPE-NAME (e.g. ssh-rsa). Otherwise the KEY-TYPE-NAME is first decoded
from the binary stream and then dispatched to the respective implementation."
  (let* ((key-type-name (or key-type-name (rfc4251:decode :string stream)))
         (key-type (get-key-type key-type-name :by :name))
         (key-id (getf key-type :id)))
    (case key-id
      (:ssh-rsa (rfc4251:decode :rsa-public-key stream :kind key-type :comment comment))
      (t
       (error 'invalid-key-error
              :description (format nil "Unknown key type ~a" key-type-name))))))

(defun parse-public-key (text)
  "Parses an OpenSSH public key file from the given plain-text string"
  (let* ((parts (uiop:split-string text :separator '(#\Space)))
         (key-type (get-key-type (first parts) :by :name))
         (data (second parts))
         (comment (third parts)))
    ;; A key type identifier is expected
    (unless key-type
      (error 'invalid-key-error
             :description "Invalid key: missing or unknown key type"))

    ;; OpenSSH public keys are encoded in a way, so that the
    ;; key kind preceeds the actual public key components.
    ;; See RFC 4253 for more details.
    (let* ((stream (rfc4251:make-binary-input-stream (binascii:decode-base64 data)))
           (key-type-name (getf key-type :name))
           (encoded-key-type-name (rfc4251:decode :string stream)))
      (unless (string= key-type-name encoded-key-type-name)
        (error 'key-type-mismatch-error
               :description "Invalid key: key types mismatch"
               :expected key-type-name
               :found encoded-key-type-name))
      (rfc4251:decode :public-key stream :key-type-name key-type-name :comment comment))))

(defun parse-public-key-from-file (path)
  "Parses an OpenSSH public key from the given path"
  (with-open-file (in path)
    (parse-public-key (read-line in))))

(defmethod fingerprint ((hash-spec (eql :md5)) (key base-public-key) &key)
  "Computes the MD5 fingerprint of the given public key"
  (let* ((stream (rfc4251:make-binary-output-stream))
         (size (rfc4251:encode :public-key key stream))
         (bytes (rfc4251:binary-output-stream-data stream))
         (digest (ironclad:digest-sequence :md5 bytes)))
    (declare (ignore size))
    (format nil "~{~(~2,'0x~)~^:~}" (coerce digest 'list))))

(defmethod fingerprint ((hash-spec (eql :sha1)) (key base-public-key) &key)
  "Computes the SHA-1 fingerprint of the given public key"
  (let* ((stream (rfc4251:make-binary-output-stream))
         (size (rfc4251:encode :public-key key stream))
         (bytes (rfc4251:binary-output-stream-data stream))
         (digest (ironclad:digest-sequence :sha1 bytes))
         (encoded (binascii:encode-base64 digest))
         (trim-position (position #\= encoded :test #'char=))) ;; Trim padding characters
    (declare (ignore size))
    (subseq encoded 0 trim-position)))

(defmethod fingerprint ((hash-spec (eql :sha256)) (key base-public-key) &key)
  "Computes the SHA-256 fingerprint of the given public key"
  (let* ((stream (rfc4251:make-binary-output-stream))
         (size (rfc4251:encode :public-key key stream))
         (bytes (rfc4251:binary-output-stream-data stream))
         (digest (ironclad:digest-sequence :sha256 bytes))
         (encoded (binascii:encode-base64 digest))
         (trim-position (position #\= encoded :test #'char=))) ;; Trim padding characters
    (declare (ignore size))
    (subseq encoded 0 trim-position)))
