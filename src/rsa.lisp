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
(defpackage :cl-ssh-keys.rsa
  (:use :cl)
  (:import-from :cl-rfc4251)
  (:import-from :ironclad)
  (:import-from
   :cl-ssh-keys.core
   :decode-key)
  (:export
   :rsa-public-key
   :rsa-key-type
   :rsa-key-comment))
(in-package :cl-ssh-keys.rsa)

(defclass rsa-public-key (ironclad:rsa-public-key)
  ((type
    :initarg :type
    :initform (error "Must specify key type")
    :reader rsa-key-type
    :documentation "Key type")
   (comment
    :initarg :comment
    :initform nil
    :reader rsa-key-comment
    :documentation "Key comment"))
  (:documentation "Represents an OpenSSH RSA public key"))

(defmethod decode-key ((kind (eql :rsa-public-key)) stream &key type comment)
  "Decodes an RSA public key from the given binary stream"
  (let ((e (rfc4251:decode :mpint stream))
        (n (rfc4251:decode :mpint stream)))
    (make-instance 'rsa-public-key
                   :e e
                   :n n
                   :type type
                   :comment comment)))
