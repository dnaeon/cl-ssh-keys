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

(defparameter *ciphers*
  '((:name "3des-cbc"
     :blocksize 8
     :iv-length 8
     :key-length 24
     :mode :cbc
     :ironclad-cipher :3des)
    (:name "aes128-cbc"
     :blocksize 16
     :iv-length 16
     :key-length 16
     :mode :cbc
     :ironclad-cipher :aes)
    (:name "aes192-cbc"
     :blocksize 16
     :iv-length 16
     :key-length 24
     :mode :cbc
     :ironclad-cipher :aes)
    (:name "aes256-cbc"
     :blocksize 16
     :iv-length 16
     :key-length 32
     :mode :cbc
     :ironclad-cipher :aes)
    (:name "aes128-ctr"
     :blocksize 16
     :iv-length 16
     :key-length 16
     :mode :ctr
     :ironclad-cipher :aes)
    (:name "aes192-ctr"
     :blocksize 16
     :iv-length 16
     :key-length 24
     :mode :ctr
     :ironclad-cipher :aes)
    (:name "aes256-ctr"
     :blocksize 16
     :iv-length 16
     :key-length 32
     :mode :ctr
     :ironclad-cipher :aes)
    (:name "none"
     :blocksize 8
     :iv-length 0
     :key-length 0
     :mode nil
     :ironclad-cipher nil))
  "Various ciphers used by OpenSSH that are supported")

(defun get-cipher-by-name (name)
  "Get a cipher by its name"
  (find name *ciphers*
        :key (lambda (item)
               (getf item :name))
        :test #'equal))

(defun get-cipher-by-name-or-lose (name)
  (let ((cipher-info (get-cipher-by-name name)))
    (unless cipher-info
      (error 'base-error
             :description (format nil "Unknown cipher name ~a" name)))
    cipher-info))
