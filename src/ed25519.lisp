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

(defclass ed25519-public-key (base-public-key ironclad:ed25519-public-key)
  ()
  (:documentation "Represents an OpenSSH Ed25519 public key"))

(defmethod rfc4251:decode ((type (eql :ed25519-public-key)) stream &key kind comment)
  "Decodes an Ed25519 public key from the given binary stream"
  (unless kind
    (error 'invalid-key-error
           :description "Public key kind was not specified"))
  (let* ((y-data (multiple-value-list (rfc4251:decode :buffer stream)))
         (y (first y-data)) ;; The public key
         (size (second y-data)) ;; Total number of bytes decoded
         (pk (make-instance 'ed25519-public-key
                            :kind kind
                            :comment comment
                            :y y)))
    (values pk size)))

(defmethod rfc4251:encode ((type (eql :ed25519-public-key)) (key ed25519-public-key) stream &key)
  "Encodes the Ed25519 public key into the given binary stream."
  (rfc4251:encode :buffer (ironclad:ed25519-key-y key) stream))

(defmethod key-bits ((key ed25519-public-key))
  "Returns the number of bits for the Ed25519 public key"
  256)

(defclass ed25519-private-key (base-private-key ironclad:ed25519-private-key)
  ()
  (:documentation "Represents an OpenSSH Ed25519 private key"))

(defmethod rfc4251:decode ((type (eql :ed25519-private-key)) stream &key kind public-key
                                                                      cipher-name kdf-name
                                                                      kdf-options checksum-int)
  "Decodes an Ed25519 private key from the given stream"
  (let* ((y (rfc4251:decode :buffer stream))  ;; Public key
         (x (rfc4251:decode :buffer stream))) ;; Private key
    ;; The public components must match
    (unless (equalp (ironclad:ed25519-key-y public-key) y)
      (error 'invalid-key-error
             :description "Invalid Ed25519 key. Public keys mismatch"))

    (make-instance 'ed25519-private-key
                   :kind kind
                   :public-key public-key
                   :cipher-name cipher-name
                   :kdf-name kdf-name
                   :kdf-options kdf-options
                   :checksum-int checksum-int
                   :y y
                   :x x)))

(defmethod rfc4251:encode ((type (eql :ed25519-private-key)) (key ed25519-private-key) stream &key)
  "Encodes the Ed25519 private key into the given binary stream"
  (let* ((y (ironclad:ed25519-key-y key))  ;; Public key
         (x (ironclad:ed25519-key-x key))) ;; Private key
    (+
     (rfc4251:encode :buffer y stream)
     (rfc4251:encode :buffer x stream))))

(defmethod key-bits ((key ed25519-private-key))
  "Returns the number of bits of the embedded public key"
  (with-slots (public-key) key
    (key-bits public-key)))

;; TODO: Add support for encrypted private keys
(defmethod generate-key-pair ((kind (eql :ed25519)) &key comment)
  "Generates a new pair of Ed25519 public and private keys"
  (let* ((key-type (get-key-type :ssh-ed25519 :by :id))
         (checksum-int (ironclad:random-bits 32))
         (priv-pub-pair (multiple-value-list (ironclad:generate-key-pair :ed25519)))
         (ironclad-priv-key (first priv-pub-pair))
         (ironclad-pub-key (second priv-pub-pair))
         (pub-key (make-instance 'ed25519-public-key
                                 :kind key-type
                                 :comment comment
                                 :y (ironclad:ed25519-key-y ironclad-pub-key)))
         (priv-key (make-instance 'ed25519-private-key
                                  :public-key pub-key
                                  :cipher-name "none"
                                  :kdf-name "none"
                                  :kdf-options #()
                                  :checksum-int checksum-int
                                  :kind key-type
                                  :comment comment
                                  :y (ironclad:ed25519-key-y ironclad-priv-key)
                                  :x (ironclad:ed25519-key-x ironclad-priv-key))))
    (values priv-key pub-key)))