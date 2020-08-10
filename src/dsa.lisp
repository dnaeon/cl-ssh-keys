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
