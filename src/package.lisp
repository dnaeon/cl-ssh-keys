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
(defpackage :cl-ssh-keys
  (:use :cl)
  (:nicknames :ssh-keys)
  (:import-from
   :ironclad
   :rsa-key-exponent
   :rsa-key-modulus
   :rsa-key-prime-p
   :rsa-key-prime-q
   :dsa-key-p
   :dsa-key-q
   :dsa-key-g
   :dsa-key-y
   :dsa-key-x
   :ed25519-key-x
   :ed25519-key-y
   :secp256r1-key-y
   :secp256r1-key-x
   :secp384r1-key-y
   :secp384r1-key-x
   :secp521r1-key-y
   :secp521r1-key-x)
  (:import-from :cl-rfc4251)
  (:import-from :uiop)
  (:import-from :alexandria)
  (:export
   ;; package
   :base-key
   :key-kind
   :key-comment
   :base-ecdsa-nistp-key
   :ecdsa-curve-identifier
   :write-key-to-path

   ;; conditions
   :invalid-public-key-error
   :key-type-mismatch-error
   :unsupported-key-error

   ;; generics
   :fingerprint
   :key-bits
   :write-key
   :generate-key-pair

   ;; key-types
   :*key-types*
   :get-key-type
   :get-key-type-or-lose

   ;; ciphers
   :*ciphers*
   :*default-cipher-name*
   :get-cipher-by-name
   :get-cipher-by-name-or-lose
   :get-all-cipher-names

   ;; public-key
   :base-public-key
   :base-ecdsa-nistp-public-key
   :parse-public-key
   :parse-public-key-file
   :with-public-key
   :with-public-key-file

   ;; private-key
   :*default-kdf-rounds*
   :+kdf-salt-size+
   :+private-key-auth-magic+
   :+private-key-mark-begin+
   :+private-key-mark-end+
   :base-private-key
   :base-ecdsa-nistp-private-key
   :embedded-public-key
   :key-cipher-name
   :key-kdf-name
   :key-kdf-salt
   :key-kdf-rounds
   :key-passphrase
   :key-checksum-int
   :extract-private-key
   :extract-private-key-from-file
   :private-key-padding-is-correct-p
   :parse-private-key
   :parse-private-key-file
   :with-private-key
   :with-private-key-file

   ;; rsa
   :rsa-public-key
   :rsa-private-key
   :rsa-key-exponent  ;; Re-export from ironclad
   :rsa-key-modulus   ;; Re-export from ironclad
   :rsa-key-prime-p   ;; Re-export from ironclad
   :rsa-key-prime-q   ;; Re-export from ironclad

   ;; dsa
   :dsa-public-key
   :dsa-private-key
   :dsa-key-p         ;; Re-export from ironclad
   :dsa-key-q         ;; Re-export from ironclad
   :dsa-key-g         ;; Re-export from ironclad
   :dsa-key-y         ;; Re-export from ironclad
   :dsa-key-x         ;; Re-export from ironclad

   ;; ed25519
   :ed25519-public-key
   :ed25519-private-key
   :ed25519-key-x     ;; Re-export from ironclad
   :ed25519-key-y     ;; Re-export from ironclad

   ;; ecdsa-nistp256
   :+nistp256-identifier+
   :ecdsa-nistp256-public-key
   :ecdsa-nistp256-private-key
   :secp256r1-key-y   ;; Re-export from ironclad
   :secp256r1-key-x   ;; Re-export from ironclad

   ;; ecdsa-nistp384
   :+nistp384-identifier+
   :ecdsa-nistp384-public-key
   :ecdsa-nistp384-private-key
   :secp384r1-key-y   ;; Re-export from ironclad
   :secp384r1-key-x   ;; Re-export from ironclad

   ;; ecdsa-nistp521
   :+nistp521-identifier+
   :ecdsa-nistp521-public-key
   :ecdsa-nistp521-private-key
   :secp521r1-key-y   ;; Re-export from ironclad
   :secp521r1-key-x)) ;; Re-export from ironclad
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
    :accessor key-comment
    :documentation "Comment associated with the key"))
  (:documentation "Base class for representing an OpenSSH key"))

(defclass base-ecdsa-nistp-key (base-key)
  ((identifier
    :initarg :identifier
    :initform (error "Must specify curve identifier")
    :reader ecdsa-curve-identifier
    :documentation "Identifier of the elliptic curve domain parameters"))
  (:documentation "Base class for representing an OpenSSH ECDSA key"))

(defun write-key-to-path (key path)
  "Writes the given KEY to the destination PATH"
  (with-open-file (out path :direction :output)
    (write-key key out)))
