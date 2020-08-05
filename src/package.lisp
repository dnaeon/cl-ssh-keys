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
   :rsa-key-modulus)
  (:import-from :cl-rfc4251)
  (:import-from :uiop)
  (:import-from :alexandria)
  (:export
   ;; conditions
   :invalid-public-key-error
   :key-type-mismatch-error
   :unknown-fingerprint-hash-error

   ;; key-types
   :*key-types*
   :get-key-type

   ;; rsa
   :rsa-public-key
   :rsa-key-kind
   :rsa-key-comment
   :rsa-key-exponent ;; Re-export from ironclad
   :rsa-key-modulus  ;; Re-export from ironclad

   ;; common
   :public-key-file-parts
   :parse-public-key-file
   :fingerprint))
(in-package :cl-ssh-keys)
