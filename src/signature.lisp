;; Copyright (c) 2020-2021 Marin Atanasov Nikolov <dnaeon@gmail.com>
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

(defparameter *signature-types*
  '((:name "ssh-rsa"
     :digest :sha1)
    (:name "rsa-sha2-256"
     :digest :sha256)
    (:name "rsa-sha2-512"
     :digest :sha512)
    (:name "ssh-dss"
     :digest :sha1)
    (:name "ssh-ed25519"
     :digest :sha512)
    (:name "ecdsa-sha2-nistp256"
     :digest :sha256)
    (:name "ecdsa-sha2-nistp384"
     :digest :sha384)
    (:name "ecdsa-sha2-nistp521"
     :digest :sha512))
  "OpenSSH certificate signature types")

(defun get-signature-type (value)
  "Get the signature type with name identified by VALUE"
  (find value *signature-types*
	:key (lambda (item)
	       (getf item :name))
	:test #'equal))

(defun get-signature-type-or-lose (value)
  (let ((signature-type (get-signature-type value)))
    (unless signature-type
      (error 'base-error
	     :description (format nil "Unknown signature type ~a" value)))
    signature-type))

(defclass signature ()
  ((type
   :initarg :type
   :reader signature-type
   :initform (error "Must specify signature type")
   :documentation "Signature type")
   (blob
    :initarg :blob
    :reader signature-blob
    :initform (error "Must specify signature blob")
    :documentation "Computed signature blob"))
  (:documentation "Certificate signature"))


(defmethod rfc4251:decode ((type (eql :cert-signature)) stream &key)
  "Decode certificate key signature from the given binary stream"
  (let* ((type-data (multiple-value-list (rfc4251:decode :string stream)))
	 (blob-data (multiple-value-list (rfc4251:decode :buffer stream)))
	 (type (first type-data))
	 (blob (first blob-data))
	 (total (+ (second type-data) (second blob-data)))
	 (signature-type (get-signature-type-or-lose type))
	 (signature (make-instance 'signature
				   :type signature-type
				   :blob blob)))
    (values signature total)))

(defmethod rfc4251:encode ((type (eql :cert-signature)) (value signature) stream &key)
  "Encode certificate signature into the given stream"
  (with-accessors ((type signature-type) (blob signature-blob)) value
    (let ((type-name (getf type :name)))
      (+ (rfc4251:encode :string type-name stream)
	 (rfc4251:encode :buffer blob stream)))))
