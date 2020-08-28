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

(alexandria:define-constant +nistp256-identifier+
  "nistp256"
  :test #'equal
  :documentation "NIST name of the curve")

(defclass ecdsa-nistp256-public-key (base-ecdsa-nistp-public-key ironclad:secp256r1-public-key)
  ()
  (:documentation "Represents an OpenSSH ECDSA NIST P-256 public key"))

(defmethod rfc4251:decode ((type (eql :ecdsa-nistp256-public-key)) stream &key kind comment)
  "Decodes an ECDSA NIST P-256 public key from the given binary stream"
  (unless kind
    (error 'invalid-key-error
           :description "Public key kind was not specified"))
  ;; The `[identifier]` and `Q` fields as defined in RFC 5656, section 3.1.
  ;; The `Q` field is the public key, which is represented as `y` in
  ;; ironclad:secp256r1 class. This is an `mpint` value.
  ;; See https://tools.ietf.org/search/rfc4492#appendix-A for the
  ;; various names under which NIST P-256 curves are known.
  (let* ((identifier-data (multiple-value-list (rfc4251:decode :string stream))) ;; Identifier of elliptic curve domain parameters
         (q-data (multiple-value-list (rfc4251:decode :mpint stream))) ;; Public key
         (size (+ (second identifier-data) (second q-data))) ;; Total number of bytes read from the stream
         (pk (make-instance 'ecdsa-nistp256-public-key
                            :kind kind
                            :comment comment
                            :identifier (first identifier-data)
                            :y (first q-data))))
    (values pk size)))

(defmethod rfc4251:encode ((type (eql :ecdsa-nistp256-public-key)) (key ecdsa-nistp256-public-key) stream &key)
  "Encodes the ECDSA NIST P-256 public key into the given binary stream."
  (with-accessors ((identifier ecdsa-curve-identifier) (y ironclad:secp256r1-key-y)) key
    (+
     (rfc4251:encode :string identifier stream)
     (rfc4251:encode :mpint y stream))))

(defmethod key-bits ((key ecdsa-nistp256-public-key))
  "Returns the number of bits for the ECDSA NIST P-256 public key"
  ironclad::+secp256r1-bits+)

(defclass ecdsa-nistp256-private-key (base-ecdsa-nistp-private-key ironclad:secp256r1-private-key)
  ()
  (:documentation "Represents an OpenSSH ECDSA NIST P-256 private key"))

(defmethod rfc4251:decode ((type (eql :ecdsa-nistp256-private-key)) stream &key kind public-key
                                                                             cipher-name kdf-name
                                                                             kdf-options checksum-int)
  "Decodes a ECDSA NIST P-256 private key from the given stream"
  (let* (identifier ;; Curve identifier
         d          ;; Private key
         q)         ;; Public key
    ;; Decode curve identifier. The decoded identifier must match with the
    ;; curve identifier.
    (setf identifier (rfc4251:decode :string stream))
    (unless (string= identifier +nistp256-identifier+)
      (error 'invalid-key-error
             :description "Invalid ECDSA NIST P-256 key. Curve identifiers mismatch"))

    ;; Public key, also embedded in the encrypted section. Must match with the
    ;; one of the provided public key.
    (setf q (rfc4251:decode :mpint stream))
    (unless (= q (ironclad:secp256r1-key-y public-key))
      (error 'invalid-key-error
             :description "Invalid ECDSA NIST P-256 key. Decoded and provided public keys mismatch"))

    ;; Decode private key
    (setf d (rfc4251:decode :mpint stream))

    (make-instance 'ecdsa-nistp256-private-key
                   :kind kind
                   :public-key public-key
                   :cipher-name cipher-name
                   :kdf-name kdf-name
                   :kdf-options kdf-options
                   :checksum-int checksum-int
                   :identifier identifier
                   :y q
                   :x d)))

(defmethod rfc4251:encode ((type (eql :ecdsa-nistp256-private-key)) (key ecdsa-nistp256-private-key) stream &key)
  "Encodes the ECDSA NIST P-256 private key into the given binary stream"
  (let ((identifier (ecdsa-curve-identifier key))
         (y (ironclad:secp256r1-key-y key))
         (x (ironclad:secp256r1-key-x key)))
    (+
     (rfc4251:encode :string identifier stream) ;; Curve identifier
     (rfc4251:encode :mpint y stream) ;; Public key
     (rfc4251:encode :mpint x stream)))) ;; Private key

(defmethod key-bits ((key ecdsa-nistp256-private-key))
  "Returns the number of bits of the embedded public key"
  (with-slots (public-key) key
    (key-bits public-key)))

;; TODO: Add support for encrypted private keys
(defmethod generate-key-pair ((kind (eql :ecdsa-nistp256)) &key comment)
  "Generates a new pair of ECDSA NIST P-256 public and private keys"
  (let* ((key-type (get-key-type :ecdsa-sha2-nistp256 :by :id))
         (checksum-int (ironclad:random-bits 32))
         (priv-pub-pair (multiple-value-list (ironclad:generate-key-pair :secp256r1)))
         (ironclad-priv-key (first priv-pub-pair))
         (ironclad-pub-key (second priv-pub-pair))

         ;; When encoding the private and public pairs we need to
         ;; encode them as `mpint` values and preserve sign, so we
         ;; convert the keys to scalars here first.
         (x-bytes (ironclad:secp256r1-key-x ironclad-priv-key))
         (y-bytes (ironclad:secp256r1-key-y ironclad-pub-key))
         (x-scalar (ironclad::ec-decode-scalar :secp256r1 x-bytes))
         (y-scalar (ironclad::ec-decode-scalar :secp256r1 y-bytes))

         (pub-key (make-instance 'ecdsa-nistp256-public-key
                                 :kind key-type
                                 :comment comment
                                 :identifier +nistp256-identifier+
                                 :y y-scalar))
         (priv-key (make-instance 'ecdsa-nistp256-private-key
                                  :public-key pub-key
                                  :cipher-name "none"
                                  :kdf-name "none"
                                  :kdf-options #()
                                  :checksum-int checksum-int
                                  :kind key-type
                                  :comment comment
                                  :identifier +nistp256-identifier+
                                  :x x-scalar
                                  :y y-scalar)))
    (values priv-key pub-key)))
