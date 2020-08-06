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

(defmethod rfc4251:encode ((type (eql :public-key)) (key rsa-public-key) stream &key (encode-key-type-p t))
  "Encodes the public key into the given binary stream according to RFC 4253, section 6.6.
If ENCODE-KEY-TYPE-P is T, then the key type name (e.g. ssh-rsa) is encoded in the stream,
before the actual public key components. Some key types (e.g. OpenSSH certificate keys)
do not encode the key type name, when being embedded within a certificate."
  (with-accessors ((kind key-kind) (e rsa-key-exponent) (n rsa-key-modulus)) key
    (if encode-key-type-p
        ;; Encode with key-type name
        (+
         (rfc4251:encode :string (getf kind :plain-name) stream)
         (rfc4251:encode :mpint e stream)
         (rfc4251:encode :mpint n stream))
        ;; Encode *without* key-type name, e.g. this public key is
        ;; embedded within a certificate key, which does not strictly
        ;; follow the rules of RFC 4253 encoding.
        (+
         (rfc4251:encode :mpint e stream)
         (rfc4251:encode :mpint n stream)))))
