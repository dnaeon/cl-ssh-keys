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

(defclass rsa-public-key (base-public-key ironclad:rsa-public-key)
  ()
  (:documentation "Represents an OpenSSH RSA public key"))

(defmethod rfc4251:decode ((type (eql :rsa-public-key)) stream &key kind comment)
  "Decodes an RSA public key from the given binary stream"
  ;; RFC4251:DECODE returns multiple values -- the first one is the
  ;; decoded value and the second one is the number of bytes that were
  ;; read from the stream in order to produce the given value.
  ;; We need to return both of these in order to conform to the
  ;; interface defined by RFC4251:DECODE generic function.
  (unless kind
    (error 'invalid-key-error
           :description "Public key kind was not specified"))
  (let* ((e-data (multiple-value-list (rfc4251:decode :mpint stream))) ;; RSA public exponent
         (n-data (multiple-value-list (rfc4251:decode :mpint stream))) ;; RSA modulus
         (pk (make-instance 'rsa-public-key
                            :e (first e-data)
                            :n (first n-data)
                            :kind kind
                            :comment comment)))
    (values
     pk
     (+ (second e-data) (second n-data)))))

(defmethod rfc4251:encode ((type (eql :rsa-public-key)) (key rsa-public-key) stream &key)
  "Encodes the RSA public key into the given binary stream."
  (with-accessors ((e ironclad:rsa-key-exponent) (n ironclad:rsa-key-modulus)) key
    (+
     (rfc4251:encode :mpint e stream)    ;; RSA public exponent
     (rfc4251:encode :mpint n stream)))) ;; RSA modulus

(defmethod key-bits ((key rsa-public-key))
  "Returns the number of bits for the RSA public key"
  (with-accessors ((n ironclad:rsa-key-modulus)) key
    (integer-length n)))

(defclass rsa-private-key (base-private-key ironclad:rsa-private-key)
  ()
  (:documentation "Represents an OpenSSH RSA private key"))

(defmethod rfc4251:decode ((type (eql :rsa-private-key)) stream &key kind public-key
                                                                  cipher-name kdf-name
                                                                  kdf-options checksum-int)
  "Decodes an RSA private key from the given stream"
  (let* (n         ;; RSA modulus
         e         ;; RSA public exponent
         d         ;; RSA private exponent
         iqmp      ;; RSA Inverse of Q Mod P
         p         ;; RSA prime number 1
         q         ;; RSA prime number 2
         comment)  ;; Key comment
    ;; Decode RSA modulus.
    ;; The modulus must match with the one from the
    ;; already decoded embedded public key.
    (setf n (rfc4251:decode :mpint stream))
    (unless (= n (ironclad:rsa-key-modulus public-key))
      (error 'invalid-key-error
             :description "Invalid RSA modulus found in encrypted section"))

    ;; RSA public exponent, also part of the encrypted section.
    ;; Must match with the one from the already decoded pubic key.
    (setf e (rfc4251:decode :mpint stream))
    (unless (= e (ironclad:rsa-key-exponent public-key))
      (error 'invalid-key-error
             :description "Invalid RSA public exponent found in encrypted section"))

    ;; RSA private exponent
    (setf d (rfc4251:decode :mpint stream))

    ;; Inverse of Q Mod P, a.k.a iqmp
    (setf iqmp (rfc4251:decode :mpint stream))

    ;; RSA prime number 1
    (setf p (rfc4251:decode :mpint stream))

    ;; RSA prime number 2
    (setf q (rfc4251:decode :mpint stream))

    ;; Verify the CRT coefficient
    (unless (= iqmp (ironclad::modular-inverse-with-blinding q p))
      (error 'invalid-key-error
             :description "Invalid CRT coefficient found in private key blob"))

    ;; Decode comment
    (setf comment (rfc4251:decode :string stream))

    ;; Perform a deterministic pad check
    (unless (private-key-padding-is-correct-p stream)
      (error 'invalid-key-error
             :description "Invalid private key padding"))

    ;; We are good, if we've reached so far.
    (make-instance 'rsa-private-key
                   :kind kind
                   :comment comment
                   :public-key public-key
                   :cipher-name cipher-name
                   :kdf-name kdf-name
                   :kdf-options kdf-options
                   :public-key public-key
                   :checksum-int checksum-int
                   :d d
                   :n n
                   :p p
                   :q q)))
