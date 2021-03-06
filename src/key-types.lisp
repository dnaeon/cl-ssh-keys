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

(defparameter *key-types*
  '((:name "ssh-rsa"
     :plain-name "ssh-rsa"
     :short-name "RSA"
     :id :ssh-rsa
     :is-cert nil)
    (:name "ssh-rsa-cert-v01@openssh.com"
     :plain-name "ssh-rsa"
     :short-name "RSA-CERT"
     :id :ssh-rsa-cert-v01
     :is-cert t)
    (:name "ssh-dss"
     :plain-name "ssh-dss"
     :short-name "DSA"
     :id :ssh-dss
     :is-cert nil)
    (:name "ssh-dss-cert-v01@openssh.com"
     :plain-name "ssh-dss"
     :short-name "DSA-CERT"
     :id :ssh-dss-cert-v01
     :is-cert t)
    (:name "ecdsa-sha2-nistp256"
     :plain-name "ecdsa-sha2-nistp256"
     :short-name "ECDSA"
     :id :ecdsa-sha2-nistp256
     :is-cert nil)
    (:name "ecdsa-sha2-nistp384"
     :plain-name "ecdsa-sha2-nistp384"
     :short-name "ECDSA"
     :id :ecdsa-sha2-nistp384
     :is-cert nil)
    (:name "ecdsa-sha2-nistp521"
     :plain-name "ecdsa-sha2-nistp521"
     :short-name "ECDSA"
     :id :ecdsa-sha2-nistp521
     :is-cert nil)
    (:name "ecdsa-sha2-nistp256-cert-v01@openssh.com"
     :plain-name "ecdsa-sha2-nistp256"
     :short-name "ECDSA-CERT"
     :id :ecdsa-sha2-nistp256-cert-v01
     :is-cert t)
    (:name "ecdsa-sha2-nistp384-cert-v01@openssh.com"
     :plain-name "ecdsa-sha2-nistp384"
     :short-name "ECDSA-CERT"
     :id :ecdsa-sha2-nistp384-cert-v01
     :is-cert t)
    (:name "ecdsa-sha2-nistp521-cert-v01@openssh.com"
     :plain-name "ecdsa-sha2-nistp521"
     :short-name "ECDSA-CERT"
     :id :ecdsa-sha2-nistp521-cert-v01
     :is-cert t)
    (:name "ssh-ed25519"
     :plain-name "ssh-ed25519"
     :short-name "ED25519"
     :id :ssh-ed25519
     :is-cert nil)
    (:name "ssh-ed25519-cert-v01@openssh.com"
     :plain-name "ssh-ed25519"
     :short-name "ED25519-CERT"
     :id :ssh-ed25519-cert-v01
     :is-cert t))
  "OpenSSH key types")

(defun get-key-type (value &key (by :name))
  "Get the key type identified by the given value and property"
  (find value *key-types*
        :key (lambda (item)
               (getf item by))
        :test #'equal))

(defun get-key-type-or-lose (value &key (by :name))
  (let ((key-type (get-key-type value :by by)))
    (unless key-type
      (error 'base-error
             :description (format nil "Unknown key type ~a" value)))
    key-type))
