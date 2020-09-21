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

(defclass dsa-public-key (base-public-key ironclad:dsa-public-key)
  ()
  (:documentation "Represents an OpenSSH DSA public key"))

(defmethod rfc4251:decode ((type (eql :dsa-public-key)) stream &key kind comment)
  "Decodes a DSA public key from the given binary stream as defined in FIPS-186-2"
  (unless kind
    (error 'invalid-key-error
           :description "Public key kind was not specified"))
  ;; DSA parameters as defined in FIPS-186-2, section 4.
  (let* ((p-data (multiple-value-list (rfc4251:decode :mpint stream)))
         (q-data (multiple-value-list (rfc4251:decode :mpint stream)))
         (g-data (multiple-value-list (rfc4251:decode :mpint stream)))
         (y-data (multiple-value-list (rfc4251:decode :mpint stream)))
         (size (+ (second p-data)
                  (second q-data)
                  (second g-data)
                  (second y-data))) ;; Total number of bytes read from the stream
         (p-q-g-group (list :p (first p-data) :q (first q-data) :g (first g-data)))
         (y (first y-data))
         (group (apply #'make-instance 'ironclad::discrete-logarithm-group p-q-g-group))
         (pk (make-instance 'dsa-public-key
                            :kind kind
                            :comment comment
                            :group group
                            :y y)))
    (values pk size)))

(defmethod rfc4251:encode ((type (eql :dsa-public-key)) (key dsa-public-key) stream &key)
  "Encodes the DSA public key into the given binary stream."
  (destructuring-bind (&key p q g y) (ironclad:destructure-public-key key)
    (+
     (rfc4251:encode :mpint p stream)
     (rfc4251:encode :mpint q stream)
     (rfc4251:encode :mpint g stream)
     (rfc4251:encode :mpint y stream))))

(defmethod key-bits ((key dsa-public-key))
  "Returns the number of bits for the DSA public key"
  (integer-length (ironclad:dsa-key-p key)))

(defclass dsa-private-key (base-private-key ironclad:dsa-private-key)
  ()
  (:documentation "Represents an OpenSSH DSA private key"))

(defmethod rfc4251:decode ((type (eql :dsa-private-key)) stream &key kind public-key
                                                                  cipher-name kdf-name
                                                                  kdf-salt kdf-rounds
                                                                  passphrase checksum-int)
  "Decodes a DSA private key from the given stream"
  ;; The DSA parameters as defined in FIPS-186-2
  (let* ((p (rfc4251:decode :mpint stream))
         (q (rfc4251:decode :mpint stream))
         (g (rfc4251:decode :mpint stream))
         (y (rfc4251:decode :mpint stream))
         (x (rfc4251:decode :mpint stream))
         (pub-key-components (ironclad:destructure-public-key public-key)))
    ;; The public components encoded in the encrypted section
    ;; must match with the already decoded public key.
    (unless (and (= p (getf pub-key-components :p))
                 (= q (getf pub-key-components :q))
                 (= g (getf pub-key-components :g))
                 (= y (getf pub-key-components :y)))
      (error 'invalid-key-error
             :description "Invalid DSA key. Public keys mismatch"))

    (make-instance 'dsa-private-key
                   :kind kind
                   :public-key public-key
                   :cipher-name cipher-name
                   :kdf-name kdf-name
                   :kdf-salt kdf-salt
                   :kdf-rounds kdf-rounds
                   :passphrase passphrase
                   :checksum-int checksum-int
                   :group (make-instance 'ironclad::discrete-logarithm-group :p p :q q :g g)
                   :x x
                   :y y)))

(defmethod rfc4251:encode ((type (eql :dsa-private-key)) (key dsa-private-key) stream &key)
  "Encodes the DSA private key into the given binary stream"
  (destructuring-bind (&key p q g y x) (ironclad:destructure-private-key key)
    (+
     (rfc4251:encode :mpint p stream)
     (rfc4251:encode :mpint q stream)
     (rfc4251:encode :mpint g stream)
     (rfc4251:encode :mpint y stream)
     (rfc4251:encode :mpint x stream))))

(defmethod key-bits ((key dsa-private-key))
  "Returns the number of bits of the embedded public key"
  (with-slots (public-key) key
    (integer-length (ironclad:dsa-key-p public-key))))

;; TODO: Add support for encrypted private keys
(defmethod generate-key-pair ((kind (eql :dsa)) &key comment passphrase)
  "Generates a new pair of DSA public and private keys"
  (let* ((cipher-name (if passphrase *default-cipher-name* "none"))
         (kdf-name (if passphrase "bcrypt" "none"))
         (key-type (get-key-type-or-lose :ssh-dss :by :id))
         (checksum-int (ironclad:random-bits 32))
         (priv-pub-pair (multiple-value-list (ironclad:generate-key-pair :dsa :num-bits 1024))) ;; DSA keys must be exactly 1024 bits
         (ironclad-priv-key (first priv-pub-pair))
         (ironclad-pub-key (second priv-pub-pair))
         (pub-key (make-instance 'dsa-public-key
                                 :group (ironclad::group ironclad-pub-key)
                                 :y (ironclad:dsa-key-y ironclad-pub-key)
                                 :kind key-type
                                 :comment comment))
         (priv-key (make-instance 'dsa-private-key
                                  :public-key pub-key
                                  :cipher-name cipher-name
                                  :kdf-name kdf-name
                                  :passphrase passphrase
                                  :checksum-int checksum-int
                                  :kind key-type
                                  :comment comment
                                  :group (ironclad::group ironclad-pub-key)
                                  :x (ironclad:dsa-key-x ironclad-priv-key)
                                  :y (ironclad:dsa-key-y ironclad-priv-key))))
    (values priv-key pub-key)))
