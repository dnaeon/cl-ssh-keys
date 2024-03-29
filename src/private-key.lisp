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

(defparameter *supported-kdf-names*
  '("none" "bcrypt")
  "Known and supported KDF names")

(defparameter *default-kdf-rounds*
  16
  "Default number of iterations to use when deriving a key")

(defconstant +kdf-salt-size+ 16
  "Salt size in bytes")

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
    :accessor key-cipher-name
    :documentation "Private key cipher name")
   (kdf-name
    :initarg :kdf-name
    :initform (error "Must specify KDF name")
    :accessor key-kdf-name
    :documentation "Private key KDF name")
   (kdf-salt
    :initarg :kdf-salt
    :initform (ironclad:random-data +kdf-salt-size+)
    :reader key-kdf-salt
    :documentation "Salt used by the KDF function")
   (kdf-rounds
    :initarg :kdf-rounds
    :initform *default-kdf-rounds*
    :accessor key-kdf-rounds
    :documentation "Number of iterations used to derive the key")
   (checksum-int
    :initarg :checksum-int
    :initform (error "Must specify checksum integer")
    :reader key-checksum-int
    :documentation "Checksum integer for private keys")
   (passphrase
    :initarg :passphrase
    :initform nil
    :accessor key-passphrase
    :documentation "Passphrase used to encrypt the private key"))
  (:documentation "Base class for representing an OpenSSH private key"))

(defmethod (setf key-kdf-name) :before (new-value (key base-private-key))
  "Set KDF name for the private key"
  (unless (member new-value *supported-kdf-names* :test #'string=)
    (error 'base-error :description "Invalid KDF name")))

(defmethod (setf key-cipher-name) :before (new-value (key base-private-key))
  "Set cipher name to use for encryption of the private key"
  (unless (member new-value (get-all-cipher-names) :test #'string=)
    (error 'base-error :description "Invalid cipher name")))

(defmethod (setf key-passphrase) :before (new-value (key base-private-key))
  "Reset or remove passphrase for the private key.
If NIL is provided then encryption will be removed for the private key."
  (etypecase new-value
    ;; Remove passphrase from the key, if passphrase is nil
    (null
     (setf (key-cipher-name key) "none")
     (setf (key-kdf-name key) "none"))
    ;; Setup cipher name and KDF name, if not already
    ;; set when changing passphrase.
    (string
     (with-accessors ((cipher key-cipher-name) (kdf key-kdf-name)) key
       (when (string= cipher "none")
         (setf cipher *default-cipher-name*))
       (when (string= kdf "none")
         (setf kdf "bcrypt"))))))

(defclass base-ecdsa-nistp-private-key (base-ecdsa-nistp-key base-private-key)
  ()
  (:documentation "Base class for representing an OpenSSH ECDSA private key"))

(defmethod rfc4251:decode ((type (eql :private-key)) stream &key passphrase)
  "Decodes an OpenSSH private key from the given stream"
  (let* (cipher
         kdf-name
         kdf-options
         kdf-options-stream
         salt
         rounds
         pub-key-stream
         public-key
         check-int-1
         check-int-2
         encrypted-buffer
         encrypted-stream
         args
         priv-key
         comment
         key-is-encrypted-p
         (total 0))
    ;; Parse AUTH_MAGIC header
    (multiple-value-bind (auth-magic size) (rfc4251:decode :c-string stream)
      (incf total size)
      (unless (string= auth-magic +private-key-auth-magic+)
        (error 'invalid-key-error
               :description "Expected AUTH_MAGIC header not found")))

    ;; Parse cipher name
    (multiple-value-bind (cipher-name size) (rfc4251:decode :string stream)
      (incf total size)
      (setf cipher (get-cipher-by-name-or-lose cipher-name)))

    (unless (string= (getf cipher :name) "none")
      (setf key-is-encrypted-p t))

    ;; Parse KDF name
    (multiple-value-bind (value size) (rfc4251:decode :string stream)
      (incf total size)
      (setf kdf-name value)
      ;; KDF name can be either "none" or "bcrypt"
      (unless (or (string= kdf-name "none") (string= kdf-name "bcrypt"))
        (error 'invalid-key-error
               :description (format nil "Unknown KDF function name ~a" value))))

    ;; Parse kdf options
    (multiple-value-bind (value size) (rfc4251:decode :buffer stream)
      (incf total size)
      (setf kdf-options value))

    ;; KDF options will contain the salt and the number of rounds, if
    ;; the key has been encrypted using a known cipher.
    (when key-is-encrypted-p
      (setf kdf-options-stream (rfc4251:make-binary-input-stream kdf-options))
      (setf salt (rfc4251:decode :buffer kdf-options-stream))
      (setf rounds (rfc4251:decode :uint32 kdf-options-stream)))

    ;; Parse number of keys, which are embedded in the private key.
    ;; Only 1 key is expected here.
    (multiple-value-bind (value size) (rfc4251:decode :uint32 stream)
      (incf total size)
      (unless (= value 1)
        (error 'invalid-key-error
               :description "Expected only one key embedded in the blob")))

    ;; Parse public key section.
    ;; We need to decode the buffer first and then decode the embedded key.
    (multiple-value-bind (buffer size) (rfc4251:decode :buffer stream)
      (incf total size)
      (setf pub-key-stream (rfc4251:make-binary-input-stream buffer))
      (setf public-key (rfc4251:decode :public-key pub-key-stream)))

    ;; Read encrypted section.
    (multiple-value-bind (buffer size) (rfc4251:decode :buffer stream)
      (incf total size)
      (setf encrypted-buffer buffer))

    ;; Check size of encrypted data against the cipher blocksize that was used
    (unless (zerop (mod (length encrypted-buffer) (getf cipher :blocksize)))
      (error 'invalid-key-error
             :description "Invalid private key format"))

    ;; Decrypt in-place, if needed.
    (when key-is-encrypted-p
      (unless passphrase
        (error 'base-error :description "Key is encrypted. Passphrase is required"))
      (decrypt-private-key encrypted-buffer
                           (getf cipher :name)
                           (ironclad:ascii-string-to-byte-array passphrase)
                           salt
                           rounds))

    ;; Continue decoding the rest of the encrypted section, which by now should
    ;; be decrypted, if given a correct passphrase.
    (setf encrypted-stream (rfc4251:make-binary-input-stream encrypted-buffer))

    ;; Decode checksum integers.
    ;; If they don't match this means that the private key was
    ;; not successfully decrypted.
    (setf check-int-1 (rfc4251:decode :uint32 encrypted-stream))
    (setf check-int-2 (rfc4251:decode :uint32 encrypted-stream))
    (unless (= check-int-1 check-int-2)
      (error 'base-error
             :description "Checksum integers mismatch. Wrong passphrase."))

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
                     :kdf-salt salt
                     :kdf-rounds rounds
                     :passphrase passphrase
                     :checksum-int check-int-1))

    (setf priv-key
          (case (getf (key-kind public-key) :id) ;; Dispatch based on the public key id
            (:ssh-rsa (apply #'rfc4251:decode :rsa-private-key encrypted-stream args))
            (:ssh-dss (apply #'rfc4251:decode :dsa-private-key encrypted-stream args))
            (:ssh-ed25519 (apply #'rfc4251:decode :ed25519-private-key encrypted-stream args))
            (:ecdsa-sha2-nistp256 (apply #'rfc4251:decode :ecdsa-nistp256-private-key encrypted-stream args))
            (:ecdsa-sha2-nistp384 (apply #'rfc4251:decode :ecdsa-nistp384-private-key encrypted-stream args))
            (:ecdsa-sha2-nistp521 (apply #'rfc4251:decode :ecdsa-nistp521-private-key encrypted-stream args))
            (t
             (error 'invalid-key-error
                    :description "Invalid or unknown private key"))))

    ;; Decode comment
    (setf comment (rfc4251:decode :string encrypted-stream))
    (setf (key-comment priv-key) comment)

    ;; Also set the comment on the embedded public key
    (setf (key-comment public-key) comment)

    ;; Perform a deterministic pad check
    (unless (private-key-padding-is-correct-p encrypted-stream)
      (error 'invalid-key-error
             :description "Invalid private key padding"))

    (values priv-key total)))

(defmethod rfc4251:encode ((type (eql :private-key)) (key base-private-key) stream &key)
  "Encodes the private key in OpenSSH private key format"
  (let* ((tmp-stream (rfc4251:make-binary-output-stream)) ;; Temporary buffer to which we write
         (pub-key-stream (rfc4251:make-binary-output-stream))
         (kdf-stream (rfc4251:make-binary-output-stream))
         (encrypted-stream (rfc4251:make-binary-output-stream))
         (key-type (key-kind key))
         (key-type-plain (getf key-type :plain-name))
         (key-id (getf key-type :id))
         (cipher (get-cipher-by-name-or-lose (key-cipher-name key)))
         (cipher-blocksize (getf cipher :blocksize))
         encrypted-buffer)
    (unless cipher
      (error 'invalid-key-error
             :description "Invalid cipher name"))

    (rfc4251:encode :c-string +private-key-auth-magic+ tmp-stream) ;; AUTH_MAGIC header
    (rfc4251:encode :string (key-cipher-name key) tmp-stream)      ;; Cipher name

    ;; KDF name and options.
    (rfc4251:encode :string (key-kdf-name key) tmp-stream)         ;; KDF name

    ;; The salt and rounds reside in a separate buffer,
    ;; when the key is encoded. Encode salt and rounds, only
    ;; if we are encrypting the private key with a passphrase.
    (when (key-passphrase key)
        (rfc4251:encode :buffer (key-kdf-salt key) kdf-stream)     ;; KDF salt
        (rfc4251:encode :uint32 (key-kdf-rounds key) kdf-stream))  ;; KDF rounds

    ;; Write out the KDF options buffer to the temp stream
    (rfc4251:encode :buffer
                    (rfc4251:get-binary-stream-bytes kdf-stream)
                    tmp-stream)

    (rfc4251:encode :uint32 #x01 tmp-stream)                       ;; Number of keys

    ;; Public key buffer
    (rfc4251:encode :public-key
                    (embedded-public-key key)
                    pub-key-stream)
    (rfc4251:encode :buffer
                    (rfc4251:get-binary-stream-bytes pub-key-stream)
                    tmp-stream)

    ;; Encrypted buffer
    (rfc4251:encode :uint32 (key-checksum-int key) encrypted-stream) ;; checkint 1
    (rfc4251:encode :uint32 (key-checksum-int key) encrypted-stream) ;; checkint 2
    (rfc4251:encode :string key-type-plain encrypted-stream)         ;; key type name

    ;; Dispatch further encoding to the respective implementation
    (case key-id
      (:ssh-rsa (rfc4251:encode :rsa-private-key key encrypted-stream))
      (:ssh-dss (rfc4251:encode :dsa-private-key key encrypted-stream))
      (:ssh-ed25519 (rfc4251:encode :ed25519-private-key key encrypted-stream))
      (:ecdsa-sha2-nistp256 (rfc4251:encode :ecdsa-nistp256-private-key key encrypted-stream))
      (:ecdsa-sha2-nistp384 (rfc4251:encode :ecdsa-nistp384-private-key key encrypted-stream))
      (:ecdsa-sha2-nistp521 (rfc4251:encode :ecdsa-nistp521-private-key key encrypted-stream))
      (t
       (error 'unsupported-key-error
              :description (format nil "Unsupported private key type ~a" key-type-plain))))

    ;; Comment
    (rfc4251:encode :string (or (key-comment key) "") encrypted-stream)

    ;; Padding
    (loop for size = (length (rfc4251:get-binary-stream-bytes encrypted-stream))
          for i from 1
          until (zerop (mod size cipher-blocksize))
          do
             (rfc4251:encode :byte i encrypted-stream))

    ;; Write out the encrypted buffer, and optionally encrypt if we have a passphrase
    (setf encrypted-buffer (rfc4251:get-binary-stream-bytes encrypted-stream))

    (when (key-passphrase key)
      (encrypt-private-key encrypted-buffer
                           (key-cipher-name key)
                           (ironclad:ascii-string-to-byte-array (key-passphrase key))
                           (key-kdf-salt key)
                           (key-kdf-rounds key)))

    (rfc4251:encode :buffer encrypted-buffer tmp-stream)

    ;; Flush out the temp buffer
    (rfc4251:encode :raw-bytes (rfc4251:get-binary-stream-bytes tmp-stream) stream)))

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

(defmethod write-key ((key base-private-key) &optional (stream *standard-output*))
  "Writes the private key in its text representation"
  (let* ((s (rfc4251:make-binary-output-stream))
         (size (rfc4251:encode :private-key key s))
         (data (rfc4251:get-binary-stream-bytes s))
         (encoded (cl-base64:usb8-array-to-base64-string data)))
    (declare (ignore size))
    (format stream "~a~&" +private-key-mark-begin+)
    (loop for char across encoded
          for i from 1 do
            (when (zerop (mod (1- i) 70))
              (format stream "~&"))
            (write-char char stream))
    (format stream "~&~a~&" +private-key-mark-end+)))

(defmacro with-private-key ((var text &key passphrase) &body body)
  "Parses a private key from the given TEXT and evaluates the
BODY with VAR bound to the decoded private key"
  `(let ((,var (parse-private-key ,text :passphrase ,passphrase)))
     ,@body))

(defmacro with-private-key-file ((var path &key passphrase) &body body)
  "Parses a private key from the given PATH and evaluates the
BODY with VAR bound to the decoded private key"
  `(let ((,var (parse-private-key-file ,path :passphrase ,passphrase)))
     ,@body))

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

(defun encrypt-private-key (text cipher-name passphrase salt rounds)
  (let ((cipher (get-cipher-for-encryption/decryption cipher-name passphrase salt rounds)))
    (ironclad:encrypt-in-place cipher text)))

(defun decrypt-private-key (encrypted cipher-name passphrase salt rounds)
  (let ((cipher (get-cipher-for-encryption/decryption cipher-name passphrase salt rounds)))
    (ironclad:decrypt-in-place cipher encrypted)))

(defun parse-private-key (text &key passphrase)
  "Parses an OpenSSH private key from the given plain-text string"
  (let* ((s (make-string-input-stream text))
         (extracted (extract-private-key s))
         (decoded (cl-base64:base64-string-to-usb8-array extracted))
         (stream (rfc4251:make-binary-input-stream decoded)))
    (multiple-value-bind (key size) (rfc4251:decode :private-key stream :passphrase passphrase)
      (declare (ignore size))
      key)))

(defun parse-private-key-file (path &key passphrase)
  "Parses an OpenSSH private key from the given path"
  (parse-private-key (alexandria:read-file-into-string path)
                     :passphrase passphrase))
