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

(defun public-key-file-parts (path)
  "Returns the parts of an OpenSSH public key file"
  (with-open-file (in path)
    (uiop:split-string (read-line in) :separator '(#\Space))))

(defun parse-public-key-file (path)
  "Parses an OpenSSH public key file from the given path"
  (let* ((parts (public-key-file-parts path))
         (key-type (get-key-type (first parts)))
         (data (second parts))
         (comment (third parts)))
    ;; We need a key identifier
    (unless key-type
      (error 'invalid-public-key-error
             :description "Missing key type"))

    ;; OpenSSH public keys are encoded in a way, so that the
    ;; key kind preceeds the actual public key components.
    ;; See RFC 4253 for more details.
    (let* ((stream (rfc4251:make-binary-input-stream (binascii:decode-base64 data)))
           (key-type-name (getf key-type :name))
           (encoded-key-type-name (rfc4251:decode :string stream)))
      (unless (string= key-type-name encoded-key-type-name)
        (error 'key-type-mismatch-error
               :description "Key types mismatch"
               :expected want-key-type-name
               :found encoded-key-type-name))

      (alexandria:switch (key-type-name :test #'equal)
        ("ssh-rsa" (decode-key :rsa-public-key stream :type key-type :comment comment))
        (t
         (error 'invalid-public-key-error :description (format nil "Unknown key type ~a" key-type-name)))))))
