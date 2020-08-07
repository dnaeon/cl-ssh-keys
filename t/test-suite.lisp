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
(defpackage :cl-ssh-keys.test
  (:use :cl :rove)
  (:nicknames :ssh-keys.test)
  (:import-from
   :cl-ssh-keys))
(in-package :cl-ssh-keys.test)

(defparameter *test-keys-path*
  (asdf:system-relative-pathname :cl-ssh-keys.test "t/test-keys/")
  "Path to public and private test keys")

(defun get-test-key-path (name)
  "Returns the path to a test key"
  (merge-pathnames *test-keys-path* name))

(deftest rsa-keys
  (testing "RSA 1024-bit public key"
    (let ((key (ssh-keys:parse-public-key-from-file (get-test-key-path #P"id_rsa_1024.pub"))))
      (ok (string= (ssh-keys:fingerprint :md5 key)
                   "dd:e6:24:29:55:48:40:af:28:2c:68:f3:33:40:58:20")
          "RSA 1024-bit public key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
                   "6K8c+b+HKqUjfIcT6WbQhoEjQM0")
          "RSA 1024-bit public key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
                   "jVI0ipXN04yjWVqOo4jjdS3ndneErRTHXKJUDbXjg18")
          "RSA 1024-bit public key SHA-256 fingerprint")
      (ok (equal (ssh-keys:key-kind key)
                 '(:name "ssh-rsa" :plain-name "ssh-rsa" :short-name "RSA" :id :ssh-rsa :is-cert nil))
          "RSA 1024-bit key kind")
      (ok (= (ssh-keys:key-bits key) 1024)
          "RSA 1024-bit key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "RSA 1024-bit key comment")))

  (testing "RSA 1024-bit private key"
    (let ((key (ssh-keys:parse-private-key-from-file (get-test-key-path #P"id_rsa_1024"))))
      ;; Fingerprints of private keys are computed against the embedded public key
      (ok (string= (ssh-keys:fingerprint :md5 key)
                   "dd:e6:24:29:55:48:40:af:28:2c:68:f3:33:40:58:20")
          "RSA 1024-bit private key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
                   "6K8c+b+HKqUjfIcT6WbQhoEjQM0")
          "RSA 1024-bit private key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
                   "jVI0ipXN04yjWVqOo4jjdS3ndneErRTHXKJUDbXjg18")
          "RSA 1024-bit private key SHA-256 fingerprint")
      (ok (equal (ssh-keys:key-kind key)
                 '(:name "ssh-rsa" :plain-name "ssh-rsa" :short-name "RSA" :id :ssh-rsa :is-cert nil))
          "RSA 1024-bit key kind")
      (ok (= (ssh-keys:key-bits key) 1024)
          "RSA 1024-bit key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost"
          "RSA 1024-bit key comment"))
      (ok (string= (ssh-keys:key-cipher-name key) "none")
          "RSA 3072-bit private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name key) "none")
          "RSA 3072-bit private key KDF name")
      (ok (equalp (ssh-keys:key-kdf-options key) #())
          "RSA 3072-bit private key KDF options")))

  (testing "RSA 3072-bit public key"
    (let ((key (ssh-keys:parse-public-key-from-file (get-test-key-path #P"id_rsa_3072.pub"))))
      (ok (string= (ssh-keys:fingerprint :md5 key)
                   "04:02:4b:b2:43:39:a4:8e:89:47:49:6f:30:78:94:1e")
          "RSA 3072-bit public key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
                   "RnLPLG93GrABjOqc6xOvVFpQXsc")
          "RSA 3072-bit public key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
                   "VmYpd+5gvA5Cj57ZZcI8lnFMNNic6jpnnBd0WoNG1F8")
          "RSA 3072-bit public key SHA-256 fingerprint")
      (ok (equal (ssh-keys:key-kind key)
                 '(:name "ssh-rsa" :plain-name "ssh-rsa" :short-name "RSA" :id :ssh-rsa :is-cert nil))
          "RSA 3072-bit key kind")
      (ok (= (ssh-keys:key-bits key) 3072)
          "RSA 3072-bit key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "RSA 3072-bit key comment")))

  (testing "RSA 3072-bit private key"
    (let ((key (ssh-keys:parse-private-key-from-file (get-test-key-path #P"id_rsa_3072"))))
      ;; Fingerprints of private keys are computed against the embedded public key
      (ok (string= (ssh-keys:fingerprint :md5 key)
                   "04:02:4b:b2:43:39:a4:8e:89:47:49:6f:30:78:94:1e")
          "RSA 3072-bit private key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
                   "RnLPLG93GrABjOqc6xOvVFpQXsc")
          "RSA 3072-bit private key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
                   "VmYpd+5gvA5Cj57ZZcI8lnFMNNic6jpnnBd0WoNG1F8")
          "RSA 3072-bit private key SHA-256 fingerprint")
      (ok (equal (ssh-keys:key-kind key)
                 '(:name "ssh-rsa" :plain-name "ssh-rsa" :short-name "RSA" :id :ssh-rsa :is-cert nil))
          "RSA 3072-bit key kind")
      (ok (= (ssh-keys:key-bits key) 3072)
          "RSA 3072-bit key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "RSA 3072-bit key comment")
      (ok (string= (ssh-keys:key-cipher-name key) "none")
          "RSA 3072-bit private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name key) "none")
          "RSA 3072-bit private key KDF name")
      (ok (equalp (ssh-keys:key-kdf-options key) #())
          "RSA 3072-bit private key KDF options"))))

(deftest invalid-keys
  (ok (signals (ssh-keys:parse-public-key-from-file (get-test-key-path #P"id_rsa_unknown_key_type.pub")))
      "Signals on unknown key type")
  (ok (signals (ssh-keys:parse-public-key-from-file (get-test-key-path #P"id_rsa_unknown_key_type")))
      "Signals on invalid public key file")
  (ok (signals (ssh-keys:parse-public-key-from-file (get-test-key-path #P"id_ed25519_key_type_mismatch")))
      "Signals on mismatched key types")
  (ok (signals (ssh-keys:parse-public-key-from-file (get-test-key-path #P"id_rsa_missing_key_type")))
      "Signals on missing key type"))
