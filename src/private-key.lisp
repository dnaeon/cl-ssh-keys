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

;; TODO: Add support for encrypted keys
;; TODO: Return total number of bytes read from the stream
(defmethod rfc4251:decode ((type (eql :private-key)) stream &key)
  "Decodes an OpenSSH private key from the given stream"
  (let* (cipher
         kdf-name
         kdf-options
         pub-key-buffer
         pub-key-stream
         public-key
         check-int-1
         check-int-2
         encrypted-buffer
         encrypted-stream
         args
         priv-key)
    ;; Parse AUTH_MAGIC header
    (unless (string= (rfc4251:decode :c-string stream)
                     +private-key-auth-magic+)
      (error 'invalid-key-error
             :description "Expected AUTH_MAGIC header not found"))

    ;; Parse cipher name
    ;; TODO: Add support for encrypted keys
    (let ((cipher-name (rfc4251:decode :string stream)))
      (setf cipher (get-cipher-by-name cipher-name))
      (unless cipher
        (error 'invalid-key-error
               :description (format nil "Unknown cipher name found ~a" cipher-name)))
      ;; TODO: Remove this check once we can decrypt keys
      (unless (string= cipher-name "none")
        (error 'unsupported-key-error
               :description "Encrypted keys are not supported yet")))

    ;; Parse KDF name
    (let ((value (rfc4251:decode :string stream)))
      (setf kdf-name value)
      ;; KDF name can be either "none" or "bcrypt"
      (unless (or (string= kdf-name "none") (string= kdf-name "bcrypt"))
        (error 'invalid-key-error
               :description (format nil "Unknown KDF function name ~a" value))))

    ;; Parse kdf options
    ;; TODO: Add support for encrypted keys
    (setf kdf-options (rfc4251:decode :buffer stream))

    ;; Parse number of keys, which are embedded in the private key.
    ;; Only 1 key is expected here.
    (unless (= 1 (rfc4251:decode :uint32 stream))
      (error 'invalid-key-error
             :description "Expected only one key embedded in the blob"))

    ;; Parse public key section.
    ;; We need to decode the buffer first and then decode the embedded key.
    (setf pub-key-buffer (rfc4251:decode :buffer stream))
    (setf pub-key-stream (rfc4251:make-binary-input-stream pub-key-buffer))
    (setf public-key (rfc4251:decode :public-key pub-key-stream))

    ;; Read encrypted section.
    ;; TODO: Add support for encrypted keys
    (setf encrypted-buffer (rfc4251:decode :buffer stream))
    (setf encrypted-stream (rfc4251:make-binary-input-stream encrypted-buffer))
    ;; Check size of encrypted data against the cipher blocksize that was used
    (unless (zerop (mod (length encrypted-buffer) (getf cipher :blocksize)))
      (error 'invalid-key-error
             :description "Invalid private key format"))

    ;; Decode checksum integers.
    ;; If they don't match this means that the private key was
    ;; not successfully decrypted.
    (setf check-int-1 (rfc4251:decode :uint32 encrypted-stream))
    (setf check-int-2 (rfc4251:decode :uint32 encrypted-stream))
    (unless (= check-int-1 check-int-2)
      (error 'invalid-key-error
             :description "Checksum integers mismatch"))

    ;; Parse key type name. Must match with the one of the public key.
    (unless (string= (rfc4251:decode :string encrypted-stream)
                     (getf (key-kind public-key) :plain-name))
      (error 'invalid-key-error
             :description "Private and public key types mismatch"))

    ;; Dispatch to the respective private key implementation for
    ;; decoding the rest of the encrypted stream
    (setf args (list :kind (key-kind public-key)
                     :public-key public-key
                     :cipher-name (getf cipher :name)
                     :kdf-name kdf-name
                     :kdf-options kdf-options
                     :checksum-int check-int-1))

    (case (getf (key-kind public-key) :id)
      (:ssh-rsa
       (setf priv-key (apply #'rfc4251:decode :rsa-private-key encrypted-stream args)))
      (t
       (error 'invalid-key-error
              :description "Invalid or unknown private key")))

    ;; Decode comment
    (setf (key-comment priv-key) (rfc4251:decode :string encrypted-stream))

    ;; Perform a deterministic pad check
    (unless (private-key-padding-is-correct-p encrypted-stream)
      (error 'invalid-key-error
             :description "Invalid private key padding"))

    priv-key))

(defmethod fingerprint ((hash-spec (eql :md5)) (key base-private-key) &key)
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

;; TODO: Add support for encrypted keys
(defun parse-private-key (text)
  "Parses an OpenSSH private key from the given plain-text string"
  (let* ((s (make-string-input-stream text))
         (extracted (extract-private-key s))
         (decoded (binascii:decode-base64 extracted))
         (stream (rfc4251:make-binary-input-stream decoded)))
    (rfc4251:decode :private-key stream)))

;; TODO: Add support for encrypted keys
(defun parse-private-key-from-file (path)
  "Parses an OpenSSH private key from the given path"
  (parse-private-key (alexandria:read-file-into-string path)))
