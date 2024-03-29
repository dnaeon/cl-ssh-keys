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
  (testing "Parse RSA 1024-bit public key"
    (let ((key (ssh-keys:parse-public-key-file (get-test-key-path #P"id_rsa_1024.pub")))
          (string-out-stream (make-string-output-stream)))
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
          "RSA 1024-bit key comment")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string (get-test-key-path #P"id_rsa_1024.pub"))
                   (get-output-stream-string string-out-stream))
          "Write RSA 1024-bit public key")))

  (testing "Parse RSA 1024-bit private key"
    (let ((key (ssh-keys:parse-private-key-file (get-test-key-path #P"id_rsa_1024")))
          (string-out-stream (make-string-output-stream)))
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
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "RSA 1024-bit private key comment")
      (ok (string= (ssh-keys:key-cipher-name key) "none")
          "RSA 1024-bit private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name key) "none")
          "RSA 1024-bit private key KDF name")
      (ok (equal (ssh-keys:key-kdf-salt key) nil) ;; Un-encrypted keys do not have salt set
          "RSA 1024-bit private key KDF salt")
      (ok (equal (ssh-keys:key-kdf-rounds key) nil) ;; Un-encrypted keys do not have rounds set
          "RSA 1024-bit private key KDF rounds")
      (ok (equal (ssh-keys:key-passphrase key) nil) ;; Un-encrypted keys do not have passphrase set
          "RSA 1024-bit private key passphrase")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string (get-test-key-path #P"id_rsa_1024"))
                   (get-output-stream-string string-out-stream))
          "Write RSA 1024-bit private key")))

  (testing "Parse RSA 3072-bit public key"
    (let ((key (ssh-keys:parse-public-key-file (get-test-key-path #P"id_rsa_3072.pub")))
          (string-out-stream (make-string-output-stream)))
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
          "RSA 3072-bit public key kind")
      (ok (= (ssh-keys:key-bits key) 3072)
          "RSA 3072-bit public key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "RSA 3072-bit public key comment")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string (get-test-key-path #P"id_rsa_3072.pub"))
                   (get-output-stream-string string-out-stream))
          "Write RSA 3072-bit public key")))

  (testing "Parse RSA 3072-bit private key"
    (let ((key (ssh-keys:parse-private-key-file (get-test-key-path #P"id_rsa_3072")))
          (string-out-stream (make-string-output-stream)))
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
          "RSA 3072-bit private key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "RSA 3072-bit private key comment")
      (ok (string= (ssh-keys:key-cipher-name key) "none")
          "RSA 3072-bit private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name key) "none")
          "RSA 3072-bit private key KDF name")
      (ok (equal (ssh-keys:key-kdf-salt key) nil)
          "RSA 3072-bit private key KDF salt")
      (ok (equal (ssh-keys:key-kdf-rounds key) nil)
          "RSA 3072-bit private key KDF rounds")
      (ok (equal (ssh-keys:key-passphrase key) nil)
          "RSA 3072-bit private key passphrase")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string (get-test-key-path #P"id_rsa_3072"))
                   (get-output-stream-string string-out-stream))
          "Write RSA 3072-bit private key")))

  (testing "Generate RSA private/public key pair"
    (multiple-value-bind (priv-key pub-key) (ssh-keys:generate-key-pair :rsa :comment "rsa-key@localhost")
      ;; Public key
      (ok (string= (ssh-keys:key-comment pub-key) "rsa-key@localhost")
          "Generated RSA public key comment")
      (ok (= (ssh-keys:key-bits pub-key) 3072)
          "Generated RSA public key number of bits")
      (ok (equal (ssh-keys:key-kind pub-key)
                 '(:name "ssh-rsa" :plain-name "ssh-rsa" :short-name "RSA" :id :ssh-rsa :is-cert nil))
          "Generated RSA public key kind")
      (ok (plusp (ssh-keys:rsa-key-exponent pub-key))
          "Generated RSA pulic key exponent")
      (ok (plusp (ssh-keys:rsa-key-modulus pub-key))
          "Generated RSA public key modulus")

      ;; Private key
      (ok (string= (ssh-keys:key-comment priv-key) "rsa-key@localhost")
          "Generated RSA private key comment")
      (ok (= (ssh-keys:key-bits priv-key) 3072)
          "Generated RSA private key number of bits")
      (ok (equal (ssh-keys:key-kind priv-key)
                 '(:name "ssh-rsa" :plain-name "ssh-rsa" :short-name "RSA" :id :ssh-rsa :is-cert nil))
          "Generated RSA private key kind")
      (ok (string= (ssh-keys:key-cipher-name priv-key) "none")
          "Generated RSA private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name priv-key) "none")
          "Generated RSA private key KDF name")
      (ok (= (length (ssh-keys:key-kdf-salt priv-key)) 16) ;; Generated keys have salt initialized
          "Generated RSA private key KDF salt")
      (ok (= (ssh-keys:key-kdf-rounds priv-key) 16) ;; Generated keys have rounds initialized
          "Generated RSA private key KDF rounds")
      (ok (equal (ssh-keys:key-passphrase priv-key) nil) ;; Generated keys do not have a default passphrase
          "Generated RSA private key passphrase")
      (ok (equal (ssh-keys:embedded-public-key priv-key)
                 pub-key)
          "Generated RSA private key embedded public key")
      (ok (plusp (ssh-keys:rsa-key-exponent priv-key))
          "Generated RSA private key exponent")
      (ok (plusp (ssh-keys:rsa-key-modulus priv-key))
          "Generated RSA private key modulus")
      (ok (plusp (ssh-keys:rsa-key-prime-p priv-key))
          "Generated RSA private key first prime factor - p")
      (ok (plusp (ssh-keys:rsa-key-prime-q priv-key))
          "Generated RSA private key second prime factor - q")))

  (testing "Generate RSA private/public key -- invalid number of bits"
    (ok (signals (ssh-keys:generate-key-pair :rsa :num-bits 512))
        "Generate RSA 512-bit keys -- signals on bit size less than 1024")))

(deftest dsa-keys
  (testing "Parse DSA 1024-bit public key"
    (let ((key (ssh-keys:parse-public-key-file (get-test-key-path #P"id_dsa.pub")))
          (string-out-stream (make-string-output-stream)))
      (ok (string= (ssh-keys:fingerprint :md5 key)
                   "ee:c9:41:84:29:e7:1f:95:98:ac:35:75:a5:5b:c7:a6")
          "DSA 1024-bit public key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
                   "2KBDiLfGio8CGoSHG4v2/CP2p/w")
          "DSA 1024-bit public key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
                   "kdAVH2jkXqT0WPyczN9bXsyH4WCct87C4kH55kTdqRo")
          "DSA 1024-bit public key SHA-256 fingerprint")
      (ok (equal (ssh-keys:key-kind key)
                 '(:name "ssh-dss" :plain-name "ssh-dss" :short-name "DSA" :id :ssh-dss :is-cert nil))
          "DSA 1024-bit public key kind")
      (ok (= (ssh-keys:key-bits key) 1024)
          "DSA 1024-bit public key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "DSA 1024-bit public key comment")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string (get-test-key-path #P"id_dsa.pub"))
                   (get-output-stream-string string-out-stream))
          "Write DSA 1024-bit public key")))

  (testing "Parse DSA 1024-bit private key"
    (let ((key (ssh-keys:parse-private-key-file (get-test-key-path #P"id_dsa")))
          (string-out-stream (make-string-output-stream)))
      (ok (string= (ssh-keys:fingerprint :md5 key)
                   "ee:c9:41:84:29:e7:1f:95:98:ac:35:75:a5:5b:c7:a6")
          "DSA 1024-bit private key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
                   "2KBDiLfGio8CGoSHG4v2/CP2p/w")
          "DSA 1024-bit private key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
                   "kdAVH2jkXqT0WPyczN9bXsyH4WCct87C4kH55kTdqRo")
          "DSA 1024-bit private key SHA-256 fingerprint")
      (ok (equal (ssh-keys:key-kind key)
                 '(:name "ssh-dss" :plain-name "ssh-dss" :short-name "DSA" :id :ssh-dss :is-cert nil))
          "DSA 1024-bit private key kind")
      (ok (= (ssh-keys:key-bits key) 1024)
          "DSA 1024-bit private key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "DSA 1024-bit private key comment")
      (ok (string= (ssh-keys:key-cipher-name key) "none")
          "DSA 1024-bit private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name key) "none")
          "DSA 1024-bit private key KDF name")
      (ok (equal (ssh-keys:key-kdf-salt key) nil)
          "DSA 1024-bit private key KDF salt")
      (ok (equal (ssh-keys:key-kdf-rounds key) nil)
          "DSA 1024-bit private key KDF rounds")
      (ok (equal (ssh-keys:key-passphrase key) nil)
          "DSA 124-bit private key passphrase")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string (get-test-key-path #P"id_dsa"))
                   (get-output-stream-string string-out-stream))
          "Write DSA 1024-bit private key")))

  (testing "Generate DSA private/public key pair"
    (multiple-value-bind (priv-key pub-key) (ssh-keys:generate-key-pair :dsa :comment "dsa-key@localhost")
      ;; Public key
      (ok (string= (ssh-keys:key-comment pub-key) "dsa-key@localhost")
          "Generated DSA public key comment")
      (ok (= (ssh-keys:key-bits pub-key) 1024)
          "Generated DSA public key number of bits")
      (ok (equal (ssh-keys:key-kind pub-key)
                 '(:name "ssh-dss" :plain-name "ssh-dss" :short-name "DSA" :id :ssh-dss :is-cert nil))
          "Generated DSA public key kind")
      (ok (plusp (ssh-keys:dsa-key-p pub-key))
          "Generated DSA pulic key - p")
      (ok (plusp (ssh-keys:dsa-key-q pub-key))
          "Generated DSA public key - q")
      (ok (plusp (ssh-keys:dsa-key-g pub-key))
          "Generated DSA public key - g")
      (ok (plusp (ssh-keys:dsa-key-y pub-key))
          "Generated DSA public key - y")

      ;; Private key
      (ok (string= (ssh-keys:key-comment priv-key) "dsa-key@localhost")
          "Generated DSA private key comment")
      (ok (= (ssh-keys:key-bits priv-key) 1024)
          "Generated DSA private key number of bits")
      (ok (equal (ssh-keys:key-kind priv-key)
                 '(:name "ssh-dss" :plain-name "ssh-dss" :short-name "DSA" :id :ssh-dss :is-cert nil))
          "Generated DSA private key kind")
      (ok (string= (ssh-keys:key-cipher-name priv-key) "none")
          "Generated DSA private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name priv-key) "none")
          "Generated DSA private key KDF name")
      (ok (= (length (ssh-keys:key-kdf-salt priv-key)) 16)
          "Generated DSA private key KDF salt")
      (ok (equal (ssh-keys:key-passphrase priv-key) nil)
          "Generated DSA private key passphrase")
      (ok (= (ssh-keys:key-kdf-rounds priv-key) 16)
          "Generated DSA private key KDF rounds")
      (ok (equal (ssh-keys:embedded-public-key priv-key)
                 pub-key)
          "Generated DSA private key embedded public key")
      (ok (plusp (ssh-keys:dsa-key-p priv-key))
          "Generated DSA private key - p")
      (ok (plusp (ssh-keys:dsa-key-q priv-key))
          "Generated DSA private key - q")
      (ok (plusp (ssh-keys:dsa-key-g priv-key))
          "Generated DSA private key - g")
      (ok (plusp (ssh-keys:dsa-key-y priv-key))
          "Generated DSA private key - y")
      (ok (plusp (ssh-keys:dsa-key-x priv-key))
          "Generated DSA private key - x"))))

(deftest ed25519-keys
  (testing "Parse Ed25519 public key"
    (let ((key (ssh-keys:parse-public-key-file (get-test-key-path #P"id_ed25519.pub")))
          (string-out-stream (make-string-output-stream)))
      (ok (string= (ssh-keys:fingerprint :md5 key)
                   "5a:53:0e:89:dd:92:5b:5a:0a:e4:b7:f2:0e:81:49:fe")
          "Ed25519 public key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
                   "wfa33emGK+n5KO6ksuyCP5J3nPI")
          "Ed25519 public key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
                   "SVZTs6OE/EiAhmiZD9vGPQlavM+tmW0Y2pWRoUE+/kY")
          "Ed25519 public key SHA-256 fingerprint")
      (ok (equal (ssh-keys:key-kind key)
                 '(:name "ssh-ed25519" :plain-name "ssh-ed25519" :short-name "ED25519" :id :ssh-ed25519 :is-cert nil))
          "Ed25519 public key kind")
      (ok (= (ssh-keys:key-bits key) 256)
          "Ed25519 public key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "Ed25519 public key comment")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string (get-test-key-path #P"id_ed25519.pub"))
                   (get-output-stream-string string-out-stream))
          "Write Ed25519 public key")))

  (testing "Parse Ed25519 private key"
    (let ((key (ssh-keys:parse-private-key-file (get-test-key-path #P"id_ed25519")))
          (string-out-stream (make-string-output-stream)))
      (ok (string= (ssh-keys:fingerprint :md5 key)
                   "5a:53:0e:89:dd:92:5b:5a:0a:e4:b7:f2:0e:81:49:fe")
          "Ed25519 private key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
                   "wfa33emGK+n5KO6ksuyCP5J3nPI")
          "Ed25519 private key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
                   "SVZTs6OE/EiAhmiZD9vGPQlavM+tmW0Y2pWRoUE+/kY")
          "Ed25519 private key SHA-256 fingerprint")
      (ok (equal (ssh-keys:key-kind key)
                 '(:name "ssh-ed25519" :plain-name "ssh-ed25519" :short-name "ED25519" :id :ssh-ed25519 :is-cert nil))
          "Ed25519 private key kind")
      (ok (= (ssh-keys:key-bits key) 256)
          "Ed25519 private key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "Ed25519 private key comment")

      (ok (string= (ssh-keys:key-cipher-name key) "none")
          "Ed25519 private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name key) "none")
          "Ed25519 private key KDF name")
      (ok (equal (ssh-keys:key-kdf-salt key) nil)
          "Ed25519 private key KDF salt")
      (ok (equal (ssh-keys:key-kdf-rounds key) nil)
          "Ed25519 private key KDF rounds")
      (ok (equal (ssh-keys:key-passphrase key) nil)
          "Ed25519 private key passphrase")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string (get-test-key-path #P"id_ed25519"))
                   (get-output-stream-string string-out-stream))
          "Write Ed25519 private key")))

  (testing "Generate Ed25519 private/public key pair"
    (multiple-value-bind (priv-key pub-key) (ssh-keys:generate-key-pair :ed25519 :comment "ed25519-key@localhost")
      ;; Public key
      (ok (string= (ssh-keys:key-comment pub-key) "ed25519-key@localhost")
          "Generated Ed25519 public key comment")
      (ok (= (ssh-keys:key-bits pub-key) 256)
          "Generated Ed25519 public key number of bits")
      (ok (equal (ssh-keys:key-kind pub-key)
                 '(:name "ssh-ed25519" :plain-name "ssh-ed25519" :short-name "ED25519" :id :ssh-ed25519 :is-cert nil))
          "Generated Ed25519 public key kind")
      (ok (= (length (ssh-keys:ed25519-key-y pub-key)) 32)
          "Generated Ed25519 pulic key - y")

      ;; Private key
      (ok (string= (ssh-keys:key-comment priv-key) "ed25519-key@localhost")
          "Generated Ed25519 private key comment")
      (ok (= (ssh-keys:key-bits priv-key) 256)
          "Generated Ed25519 private key number of bits")
      (ok (equal (ssh-keys:key-kind priv-key)
                 '(:name "ssh-ed25519" :plain-name "ssh-ed25519" :short-name "ED25519" :id :ssh-ed25519 :is-cert nil))
          "Generated Ed25519 private key kind")
      (ok (string= (ssh-keys:key-cipher-name priv-key) "none")
          "Generated Ed25519 private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name priv-key) "none")
          "Generated Ed25519 private key KDF name")
      (ok (= (length (ssh-keys:key-kdf-salt priv-key)) 16)
          "Generated Ed25519 private key KDF salt")
      (ok (= (ssh-keys:key-kdf-rounds priv-key) 16)
          "Generated Ed25519 private key KDF rounds")
      (ok (equal (ssh-keys:key-passphrase priv-key) nil)
          "Generated Ed25519 private key passphrase")
      (ok (equal (ssh-keys:embedded-public-key priv-key)
                 pub-key)
          "Generated Ed25519 private key embedded public key")
      (ok (= (length (ssh-keys:ed25519-key-y priv-key)) 32)
          "Generated Ed25519 private key - y")
      (ok (= (length (ssh-keys:ed25519-key-x priv-key)) 32)
          "Generated Ed25519 private key - x"))))

(deftest ecdsa-nistp256-keys
  (testing "Parse ECDSA NIST P-256 public key"
    (let ((key (ssh-keys:parse-public-key-file (get-test-key-path #P"id_ecdsa_nistp256.pub")))
          (string-out-stream (make-string-output-stream)))
      (ok (string= (ssh-keys:fingerprint :md5 key)
                   "3a:36:ba:c7:2c:26:9e:e3:14:bb:61:40:46:60:31:ae")
          "ECDSA NIST P-256 public key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
                   "eTmWRwNGK7FQsfbFiIGzfNG2hxo")
          "ECDSA NIST P-256 public key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
                   "q56e29ej1aTV9ptIX/ERikzqk0HWEtaBDBH33ziQVSM")
          "ECDSA NIST P-256 public key SHA-256 fingerprint")
      (ok (equal (ssh-keys:key-kind key)
                 '(:name "ecdsa-sha2-nistp256" :plain-name "ecdsa-sha2-nistp256" :short-name "ECDSA" :id :ecdsa-sha2-nistp256 :is-cert nil))
          "ECDSA NIST P-256 public key kind")
      (ok (= (ssh-keys:key-bits key) 256)
          "ECDSA NIST P-256 public key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "ECDSA NIST P-256 public key comment")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string (get-test-key-path #P"id_ecdsa_nistp256.pub"))
                   (get-output-stream-string string-out-stream))
          "Write ECDSA NIST P-256 public key")))

  (testing "Parse ECDSA NIST P-256 private key"
    (let ((key (ssh-keys:parse-private-key-file (get-test-key-path #P"id_ecdsa_nistp256")))
          (string-out-stream (make-string-output-stream)))
      (ok (string= (ssh-keys:fingerprint :md5 key)
                   "3a:36:ba:c7:2c:26:9e:e3:14:bb:61:40:46:60:31:ae")
          "ECDSA NIST P-256 private key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
                   "eTmWRwNGK7FQsfbFiIGzfNG2hxo")
          "ECDSA NIST P-256 private key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
                   "q56e29ej1aTV9ptIX/ERikzqk0HWEtaBDBH33ziQVSM")
          "ECDSA NIST P-256 private key SHA-256 fingerprint")
      (ok (equal (ssh-keys:key-kind key)
                 '(:name "ecdsa-sha2-nistp256" :plain-name "ecdsa-sha2-nistp256" :short-name "ECDSA" :id :ecdsa-sha2-nistp256 :is-cert nil))
          "ECDSA NIST P-256 private key kind")
      (ok (= (ssh-keys:key-bits key) 256)
          "ECDSA NIST P-256 private key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "ECDSA NIST P-256 private key comment")

      (ok (string= (ssh-keys:key-cipher-name key) "none")
          "ECDSA NIST P-256 private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name key) "none")
          "ECDSA NIST P-256 private key KDF name")
      (ok (equal (ssh-keys:key-kdf-salt key) nil)
          "ECDSA NIST P-256 private key KDF salt")
      (ok (equal (ssh-keys:key-kdf-rounds key) nil)
         "ECDSA NIST P-256 private key KDF rounds")
      (ok (equal (ssh-keys:key-passphrase key) nil)
          "ECDSA NIST P-256 private key passphrase")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string (get-test-key-path #P"id_ecdsa_nistp256"))
                   (get-output-stream-string string-out-stream))
          "Write ECDSA NIST P-256 private key")))

  (testing "Generate ECDSA NIST P-256 private/public key pair"
    (multiple-value-bind (priv-key pub-key) (ssh-keys:generate-key-pair :ecdsa-nistp256 :comment "ecdsa-nistp256-key@localhost")
      ;; Public key
      (ok (string= (ssh-keys:key-comment pub-key) "ecdsa-nistp256-key@localhost")
          "Generated ECDSA NIST P-256 public key comment")
      (ok (= (ssh-keys:key-bits pub-key) 256)
          "Generated ECDSA NIST P-256 public key number of bits")
      (ok (equal (ssh-keys:key-kind pub-key)
                 '(:name "ecdsa-sha2-nistp256" :plain-name "ecdsa-sha2-nistp256" :short-name "ECDSA" :id :ecdsa-sha2-nistp256 :is-cert nil))
          "Generated ECDSA NIST P-256 public key kind")
      (ok (plusp (length (ssh-keys:secp256r1-key-y pub-key)))
          "Generated ECDSA NIST P-256 pulic key - y")

      ;; Private key
      (ok (string= (ssh-keys:key-comment priv-key) "ecdsa-nistp256-key@localhost")
          "Generated ECDSA NIST P-256 private key comment")
      (ok (= (ssh-keys:key-bits priv-key) 256)
          "Generated ECDSA NIST P-256 private key number of bits")
      (ok (equal (ssh-keys:key-kind priv-key)
                 '(:name "ecdsa-sha2-nistp256" :plain-name "ecdsa-sha2-nistp256" :short-name "ECDSA" :id :ecdsa-sha2-nistp256 :is-cert nil))
          "Generated ECDSA NIST P-256 private key kind")
      (ok (string= (ssh-keys:key-cipher-name priv-key) "none")
          "Generated ECDSA NIST P-256 private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name priv-key) "none")
          "Generated ECDSA NIST P-256 private key KDF name")
      (ok (= (length (ssh-keys:key-kdf-salt priv-key)) 16)
          "Generated ECDSA NIST P-256 private key KDF salt")
      (ok (= (ssh-keys:key-kdf-rounds priv-key) 16)
          "Generated ECDSA NIST P-256 private key KDF rounds")
      (ok (equal (ssh-keys:key-passphrase priv-key) nil)
          "Generated ECDSA NIST P-256 private key passphrase")
      (ok (equal (ssh-keys:embedded-public-key priv-key)
                 pub-key)
          "Generated ECDSA NIST P-256 private key embedded public key")
      (ok (plusp (length (ssh-keys:secp256r1-key-y priv-key)))
          "Generated ECDSA NIST P-256 private key - y")
      (ok (plusp (length (ssh-keys:secp256r1-key-x priv-key)))
          "Generated ECDSA NIST P-256 private key - x"))))

(deftest ecdsa-nistp384-keys
  (testing "Parse ECDSA NIST P-384 public key"
    (let ((key (ssh-keys:parse-public-key-file (get-test-key-path #P"id_ecdsa_nistp384.pub")))
          (string-out-stream (make-string-output-stream)))
      (ok (string= (ssh-keys:fingerprint :md5 key)
                   "4b:4d:9f:0b:51:2a:0b:8c:7f:db:f2:e8:cc:20:93:f2")
          "ECDSA NIST P-384 public key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
                   "O4neOo5GtvUUZUErlDu8gD/MKr4")
          "ECDSA NIST P-384 public key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
                   "3HR8kr5XphIWXy312brnRHbrTMq6WmKP/8EkVMLRqMU")
          "ECDSA NIST P-384 public key SHA-256 fingerprint")
      (ok (equal (ssh-keys:key-kind key)
                 '(:name "ecdsa-sha2-nistp384" :plain-name "ecdsa-sha2-nistp384" :short-name "ECDSA" :id :ecdsa-sha2-nistp384 :is-cert nil))
          "ECDSA NIST P-384 public key kind")
      (ok (= (ssh-keys:key-bits key) 384)
          "ECDSA NIST P-384 public key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "ECDSA NIST P-384 public key comment")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string (get-test-key-path #P"id_ecdsa_nistp384.pub"))
                   (get-output-stream-string string-out-stream))
          "Write ECDSA NIST P-384 public key")))

  (testing "Parse ECDSA NIST P-384 private key"
    (let ((key (ssh-keys:parse-private-key-file (get-test-key-path #P"id_ecdsa_nistp384")))
          (string-out-stream (make-string-output-stream)))
      (ok (string= (ssh-keys:fingerprint :md5 key)
                   "4b:4d:9f:0b:51:2a:0b:8c:7f:db:f2:e8:cc:20:93:f2")
          "ECDSA NIST P-384 private key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
                   "O4neOo5GtvUUZUErlDu8gD/MKr4")
          "ECDSA NIST P-384 private key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
                   "3HR8kr5XphIWXy312brnRHbrTMq6WmKP/8EkVMLRqMU")
          "ECDSA NIST P-384 private key SHA-256 fingerprint")
      (ok (equal (ssh-keys:key-kind key)
                 '(:name "ecdsa-sha2-nistp384" :plain-name "ecdsa-sha2-nistp384" :short-name "ECDSA" :id :ecdsa-sha2-nistp384 :is-cert nil))
          "ECDSA NIST P-384 private key kind")
      (ok (= (ssh-keys:key-bits key) 384)
          "ECDSA NIST P-384 private key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "ECDSA NIST P-384 private key comment")

      (ok (string= (ssh-keys:key-cipher-name key) "none")
          "ECDSA NIST P-384 private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name key) "none")
          "ECDSA NIST P-384 private key KDF name")
      (ok (equal (ssh-keys:key-kdf-salt key) nil)
          "ECDSA NIST P-384 private key KDF salt")
      (ok (equal (ssh-keys:key-kdf-rounds key) nil)
          "ECDSA NIST P-384 private key KDF rounds")
      (ok (equal (ssh-keys:key-passphrase key) nil)
          "ECDSA NIST P-384 private key passphrase")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string (get-test-key-path #P"id_ecdsa_nistp384"))
                   (get-output-stream-string string-out-stream))
          "Write ECDSA NIST P-384 private key")))

  (testing "Generate ECDSA NIST P-384 private/public key pair"
    (multiple-value-bind (priv-key pub-key) (ssh-keys:generate-key-pair :ecdsa-nistp384 :comment "ecdsa-nistp384-key@localhost")
      ;; Public key
      (ok (string= (ssh-keys:key-comment pub-key) "ecdsa-nistp384-key@localhost")
          "Generated ECDSA NIST P-384 public key comment")
      (ok (= (ssh-keys:key-bits pub-key) 384)
          "Generated ECDSA NIST P-384 public key number of bits")
      (ok (equal (ssh-keys:key-kind pub-key)
                 '(:name "ecdsa-sha2-nistp384" :plain-name "ecdsa-sha2-nistp384" :short-name "ECDSA" :id :ecdsa-sha2-nistp384 :is-cert nil))
          "Generated ECDSA NIST P-384 public key kind")
      (ok (plusp (length (ssh-keys:secp384r1-key-y pub-key)))
          "Generated ECDSA NIST P-384 pulic key - y")

      ;; Private key
      (ok (string= (ssh-keys:key-comment priv-key) "ecdsa-nistp384-key@localhost")
          "Generated ECDSA NIST P-384 private key comment")
      (ok (= (ssh-keys:key-bits priv-key) 384)
          "Generated ECDSA NIST P-384 private key number of bits")
      (ok (equal (ssh-keys:key-kind priv-key)
                 '(:name "ecdsa-sha2-nistp384" :plain-name "ecdsa-sha2-nistp384" :short-name "ECDSA" :id :ecdsa-sha2-nistp384 :is-cert nil))
          "Generated ECDSA NIST P-384 private key kind")
      (ok (string= (ssh-keys:key-cipher-name priv-key) "none")
          "Generated ECDSA NIST P-384 private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name priv-key) "none")
          "Generated ECDSA NIST P-384 private key KDF name")
      (ok (= (length (ssh-keys:key-kdf-salt priv-key)) 16)
          "Generated ECDSA NIST P-384 private key KDF salt")
      (ok (= (ssh-keys:key-kdf-rounds priv-key) 16)
          "Generated ECDSA NIST P-384 private key KDF rounds")
      (ok (equal (ssh-keys:key-passphrase priv-key) nil)
          "Generated ECDSA NIST P-384 private key passphrase")
      (ok (equal (ssh-keys:embedded-public-key priv-key)
                 pub-key)
          "Generated ECDSA NIST P-384 private key embedded public key")
      (ok (plusp (length (ssh-keys:secp384r1-key-y priv-key)))
          "Generated ECDSA NIST P-384 private key - y")
      (ok (plusp (length (ssh-keys:secp384r1-key-x priv-key)))
          "Generated ECDSA NIST P-384 private key - x"))))

(deftest ecdsa-nistp521-keys
  (testing "Parse ECDSA NIST P-521 public key"
    (let ((key (ssh-keys:parse-public-key-file (get-test-key-path #P"id_ecdsa_nistp521.pub")))
          (string-out-stream (make-string-output-stream)))
      (ok (string= (ssh-keys:fingerprint :md5 key)
                   "20:e7:81:b1:5b:25:5b:51:86:68:d9:0d:f2:4f:c2:bc")
          "ECDSA NIST P-521 public key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
                   "1itTOyxo/LDunoesxEBlQbvRnSM")
          "ECDSA NIST P-521 public key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
                   "IpPQNSCfvLbG1/RfcELgaG12r3RH4av+qWE32dp2yWE")
          "ECDSA NIST P-521 public key SHA-256 fingerprint")
      (ok (equal (ssh-keys:key-kind key)
                 '(:name "ecdsa-sha2-nistp521" :plain-name "ecdsa-sha2-nistp521" :short-name "ECDSA" :id :ecdsa-sha2-nistp521 :is-cert nil))
          "ECDSA NIST P-521 public key kind")
      (ok (= (ssh-keys:key-bits key) 521)
          "ECDSA NIST P-521 public key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "ECDSA NIST P-521 public key comment")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string (get-test-key-path #P"id_ecdsa_nistp521.pub"))
                   (get-output-stream-string string-out-stream))
          "Write ECDSA NIST P-521 public key")))

  (testing "Parse ECDSA NIST P-521 private key"
    (let ((key (ssh-keys:parse-private-key-file (get-test-key-path #P"id_ecdsa_nistp521")))
          (string-out-stream (make-string-output-stream)))
      (ok (string= (ssh-keys:fingerprint :md5 key)
                   "20:e7:81:b1:5b:25:5b:51:86:68:d9:0d:f2:4f:c2:bc")
          "ECDSA NIST P-521 private key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
                   "1itTOyxo/LDunoesxEBlQbvRnSM")
          "ECDSA NIST P-521 private key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
                   "IpPQNSCfvLbG1/RfcELgaG12r3RH4av+qWE32dp2yWE")
          "ECDSA NIST P-521 private key SHA-256 fingerprint")
      (ok (equal (ssh-keys:key-kind key)
                 '(:name "ecdsa-sha2-nistp521" :plain-name "ecdsa-sha2-nistp521" :short-name "ECDSA" :id :ecdsa-sha2-nistp521 :is-cert nil))
          "ECDSA NIST P-521 private key kind")
      (ok (= (ssh-keys:key-bits key) 521)
          "ECDSA NIST P-521 private key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "ECDSA NIST P-521 private key comment")

      (ok (string= (ssh-keys:key-cipher-name key) "none")
          "ECDSA NIST P-521 private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name key) "none")
          "ECDSA NIST P-521 private key KDF name")
      (ok (equal (ssh-keys:key-kdf-salt key) nil)
          "ECDSA NIST P-521 private key KDF salt")
      (ok (equal (ssh-keys:key-kdf-rounds key) nil)
          "ECDSA NIST P-521 private key KDF rounds")
      (ok (equal (ssh-keys:key-passphrase key) nil)
          "ECDSA NIST P-521 private key passphrase")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string (get-test-key-path #P"id_ecdsa_nistp521"))
                   (get-output-stream-string string-out-stream))
          "Write ECDSA NIST P-521 private key")))

  (testing "Generate ECDSA NIST P-521 private/public key pair"
    (multiple-value-bind (priv-key pub-key) (ssh-keys:generate-key-pair :ecdsa-nistp521 :comment "ecdsa-nistp521-key@localhost")
      ;; Public key
      (ok (string= (ssh-keys:key-comment pub-key) "ecdsa-nistp521-key@localhost")
          "Generated ECDSA NIST P-521 public key comment")
      (ok (= (ssh-keys:key-bits pub-key) 521)
          "Generated ECDSA NIST P-521 public key number of bits")
      (ok (equal (ssh-keys:key-kind pub-key)
                 '(:name "ecdsa-sha2-nistp521" :plain-name "ecdsa-sha2-nistp521" :short-name "ECDSA" :id :ecdsa-sha2-nistp521 :is-cert nil))
          "Generated ECDSA NIST P-521 public key kind")
      (ok (plusp (length (ssh-keys:secp521r1-key-y pub-key)))
          "Generated ECDSA NIST P-521 pulic key - y")

      ;; Private key
      (ok (string= (ssh-keys:key-comment priv-key) "ecdsa-nistp521-key@localhost")
          "Generated ECDSA NIST P-521 private key comment")
      (ok (= (ssh-keys:key-bits priv-key) 521)
          "Generated ECDSA NIST P-521 private key number of bits")
      (ok (equal (ssh-keys:key-kind priv-key)
                 '(:name "ecdsa-sha2-nistp521" :plain-name "ecdsa-sha2-nistp521" :short-name "ECDSA" :id :ecdsa-sha2-nistp521 :is-cert nil))
          "Generated ECDSA NIST P-521 private key kind")
      (ok (string= (ssh-keys:key-cipher-name priv-key) "none")
          "Generated ECDSA NIST P-521 private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name priv-key) "none")
          "Generated ECDSA NIST P-521 private key KDF name")
      (ok (= (length (ssh-keys:key-kdf-salt priv-key)) 16)
          "Generated ECDSA NIST P-521 private key KDF salt")
      (ok (= (ssh-keys:key-kdf-rounds priv-key) 16)
          "Generated ECDSA NIST P-521 private key rounds")
      (ok (equal (ssh-keys:key-passphrase priv-key) nil)
          "Generated ECDSA NIST P-521 private key passphrase")
      (ok (equal (ssh-keys:embedded-public-key priv-key)
                 pub-key)
          "Generated ECDSA NIST P-521 private key embedded public key")
      (ok (plusp (length (ssh-keys:secp521r1-key-y priv-key)))
          "Generated ECDSA NIST P-521 private key - y")
      (ok (plusp (length (ssh-keys:secp521r1-key-x priv-key)))
          "Generated ECDSA NIST P-521 private key - x"))))

(deftest with-macros
  (testing "with-public-key macro"
    (ok (expands '(ssh-keys:with-public-key (key "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDi...")
                   (ssh-keys:fingerprint :sha256 key))
                 '(let ((key (ssh-keys:parse-public-key "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDi...")))
                   (ssh-keys:fingerprint :sha256 key)))
        "Test WITH-PUBLIC-KEY macro expanding"))
  (testing "with-public-key-file macro"
    (ok (expands '(ssh-keys:with-public-key-file (key #P"id_rsa.pub")
                   (ssh-keys:fingerprint :sha256 key))
                 '(let ((key (ssh-keys:parse-public-key-file #P"id_rsa.pub")))
                   (ssh-keys:fingerprint :sha256 key)))
        "Test WITH-PUBLIC-KEY-FILE macro"))
  (testing "with-private-key macro"
    (ok (expands '(ssh-keys:with-private-key (key "-----BEGIN OPENSSH PRIVATE KEY----- ...")
                   (ssh-keys:fingerprint :sha256 key))
                 '(let ((key (ssh-keys:parse-private-key "-----BEGIN OPENSSH PRIVATE KEY----- ..." :passphrase nil)))
                   (ssh-keys:fingerprint :sha256 key)))
        "Test WITH-PRIVATE-KEY macro expanding"))
  (testing "with-private-key-file macro"
    (ok (expands '(ssh-keys:with-private-key-file (key #P"id_rsa")
                   (ssh-keys:fingerprint :sha256 key))
                 '(let ((key (ssh-keys:parse-private-key-file #P"id_rsa" :passphrase nil)))
                   (ssh-keys:fingerprint :sha256 key)))
        "Test WITH-PRIVATE-KEY-FILE macro expanding")))

(deftest invalid-keys
  (ok (signals (ssh-keys:parse-public-key-file (get-test-key-path #P"id_rsa_unknown_key_type.pub")))
      "Signals on unknown key type")
  (ok (signals (ssh-keys:parse-public-key-file (get-test-key-path #P"id_rsa_unknown_key_type")))
      "Signals on invalid public key file")
  (ok (signals (ssh-keys:parse-public-key-file (get-test-key-path #P"id_ed25519_key_type_mismatch")))
      "Signals on mismatched key types")
  (ok (signals (ssh-keys:parse-public-key-file (get-test-key-path #P"id_rsa_missing_key_type")))
      "Signals on missing key type")
  (ok (signals (ssh-keys:parse-private-key-file (get-test-key-path #P"id_rsa_invalid_padding")))
      "Signals on invalid padding"))

(deftest encrypted-keys
  (testing "3des-cbc cipher"
    (let ((key (ssh-keys:parse-private-key-file (get-test-key-path #P"id_ed25519_encrypted_3des-cbc")
                                                :passphrase "123456"))
          (string-out-stream (make-string-output-stream)))
      (ok (string= (ssh-keys:fingerprint :md5 key)
                   "01:ea:ad:b6:c8:b1:e8:dd:41:90:d2:b2:eb:ea:f5:2c")
          "Ed25519 encrypted (3des-cbc) private key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
                   "5JUVhhFIo/Fyv7HAGb5HgHIyKlA")
          "Ed25519 encrypted (3des-cbc) private key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
                   "SIOpsNueWsiP6+nrQrjytlKZajcb5RhezuAfsKqrEE4")
          "Ed25519 encrypted (3des-cbc) private key SHA-256 fingerprint")
      (ok (equal (ssh-keys:key-kind key)
                 '(:name "ssh-ed25519" :plain-name "ssh-ed25519" :short-name "ED25519" :id :ssh-ed25519 :is-cert nil))
          "Ed25519 encrypted (3des-cbc) private key kind")
      (ok (= (ssh-keys:key-bits key) 256)
          "Ed25519 encrypted (3des-cbc) private key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "Ed25519 encrypted (3des-cbc) private key comment")

      (ok (string= (ssh-keys:key-cipher-name key) "3des-cbc")
          "Ed25519 encrypted (3des-cbc) private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name key) "bcrypt")
          "Ed25519 encrypted (3des-cbc) private key KDF name")
      (ok (= (length (ssh-keys:key-kdf-salt key)) 16)
          "Ed25519 encrypted (3des-cbc) private key KDF salt")
      (ok (= (ssh-keys:key-kdf-rounds key) 16)
          "Ed25519 encrypted (3des-cbc) private key KDF rounds")
      (ok (string= (ssh-keys:key-passphrase key) "123456")
          "Ed25519 encrypted (3des-cbc) private key passphrase")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string (get-test-key-path #P"id_ed25519_encrypted_3des-cbc"))
                   (get-output-stream-string string-out-stream))
          "Write Ed25519 encrypted (3des-cbc) private key")))

  (testing "aes128-cbc cipher"
    (let ((key (ssh-keys:parse-private-key-file (get-test-key-path #P"id_rsa_3072_encrypted_aes128-cbc")
                                                :passphrase "123456"))
          (string-out-stream (make-string-output-stream)))
      (ok (string= (ssh-keys:fingerprint :md5 key)
                   "37:4c:1b:16:c6:44:d3:60:ab:01:08:89:d7:0c:c4:e7")
          "RSA 3072-bit encrypted (aes128-cbc) private key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
                   "Uhv44DazaYbCxqVuusTGxRmJNc8")
          "RSA 3072-bit encrypted (aes128-cbc) private key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
                   "stNdz9DhMN7fUB3TlOa9raRZCmwXbZq/ZpzUNgp3ORo")
          "RSA 3072-bit encrypted (aes128-cbc) private key SHA-256 fingerprint")
      (ok (equal (ssh-keys:key-kind key)
                 '(:name "ssh-rsa" :plain-name "ssh-rsa" :short-name "RSA" :id :ssh-rsa :is-cert nil))
          "RSA 3072-bit encrypted (aes128-cbc) private key kind")
      (ok (= (ssh-keys:key-bits key) 3072)
          "RSA 3072-bit encrypted (aes128-cbc) private key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "RSA 3072-bit encrypted (aes128-cbc) private key comment")
      (ok (string= (ssh-keys:key-cipher-name key) "aes128-cbc")
          "RSA 3072-bit encrypted (aes128-cbc) private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name key) "bcrypt")
          "RSA 3072-bit encrypted (aes128-cbc) private key KDF name")
      (ok (= (length (ssh-keys:key-kdf-salt key)) 16)
          "RSA 3072-bit encrypted (aes128-cbc) private key KDF salt")
      (ok (= (ssh-keys:key-kdf-rounds key) 16)
          "RSA 3072-bit encrypted (aes128-cbc) private key KDF rounds")
      (ok (string= (ssh-keys:key-passphrase key) "123456")
          "RSA 3072-bit encrypted (aes128-cbc) private key passphrase")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string (get-test-key-path #P"id_rsa_3072_encrypted_aes128-cbc"))
                   (get-output-stream-string string-out-stream))
          "Write RSA 3072-bit encrypted (aes128-cbc) private key")))

  (testing "aes192-cbc cipher"
    (let ((key (ssh-keys:parse-private-key-file (get-test-key-path #P"id_ed25519_encrypted_aes192-cbc")
                                                :passphrase "123456"))
          (string-out-stream (make-string-output-stream)))
      (ok (string= (ssh-keys:fingerprint :md5 key)
                   "b3:a3:91:f2:3c:cb:0d:70:93:65:89:77:c2:8d:92:a7")
          "Ed25519 encrypted (aes192-cbc) private key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
                   "oBeKn++EPaep01WEgUWjw2+kVDo")
          "Ed25519 encrypted (aes192-cbc) private key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
                   "NNuRRk3z77YR5I3Ah3HMxuhLWqdq+CsMucsyNBsIX1Y")
          "Ed25519 encrypted (aes192-cbc) private key SHA-256 fingerprint")
      (ok (equal (ssh-keys:key-kind key)
                 '(:name "ssh-ed25519" :plain-name "ssh-ed25519" :short-name "ED25519" :id :ssh-ed25519 :is-cert nil))
          "Ed25519 encrypted (aes192-cbc) private key kind")
      (ok (= (ssh-keys:key-bits key) 256)
          "Ed25519 encrypted (aes192-cbc) private key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "Ed25519 encrypted (aes192-cbc) private key comment")

      (ok (string= (ssh-keys:key-cipher-name key) "aes192-cbc")
          "Ed25519 encrypted (aes192-cbc) private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name key) "bcrypt")
          "Ed25519 encrypted (aes192-cbc) private key KDF name")
      (ok (= (length (ssh-keys:key-kdf-salt key)) 16)
          "Ed25519 encrypted (aes192-cbc) private key KDF salt")
      (ok (= (ssh-keys:key-kdf-rounds key) 16)
          "Ed25519 encrypted (aes192-cbc) private key KDF rounds")
      (ok (string= (ssh-keys:key-passphrase key) "123456")
          "Ed25519 encrypted (aes192-cbc) private key passphrase")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string (get-test-key-path #P"id_ed25519_encrypted_aes192-cbc"))
                   (get-output-stream-string string-out-stream))
          "Write Ed25519 encrypted (aes192-cbc) private key")))

  (testing "aes256-cbc cipher"
    (let ((key (ssh-keys:parse-private-key-file (get-test-key-path #P"id_ed25519_encrypted_aes256-cbc")
                                                :passphrase "123456"))
          (string-out-stream (make-string-output-stream)))
      (ok (string= (ssh-keys:fingerprint :md5 key)
                   "4d:06:b5:c2:71:e9:1a:bf:bc:b4:bb:d2:6e:ac:7b:b5")
          "Ed25519 encrypted (aes256-cbc) private key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
                   "QFjs0FShCioe/XiDD8caoVbDCZ0")
          "Ed25519 encrypted (aes256-cbc) private key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
                   "gNZRqz4XJDx565eOeBQwg6ADPEnXf49DvjZCYNYjwGA")
          "Ed25519 encrypted (aes256-cbc) private key SHA-256 fingerprint")
      (ok (equal (ssh-keys:key-kind key)
                 '(:name "ssh-ed25519" :plain-name "ssh-ed25519" :short-name "ED25519" :id :ssh-ed25519 :is-cert nil))
          "Ed25519 encrypted (aes256-cbc) private key kind")
      (ok (= (ssh-keys:key-bits key) 256)
          "Ed25519 encrypted (aes256-cbc) private key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "Ed25519 encrypted (aes256-cbc) private key comment")

      (ok (string= (ssh-keys:key-cipher-name key) "aes256-cbc")
          "Ed25519 encrypted (aes256-cbc) private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name key) "bcrypt")
          "Ed25519 encrypted (aes256-cbc) private key KDF name")
      (ok (= (length (ssh-keys:key-kdf-salt key)) 16)
          "Ed25519 encrypted (aes256-cbc) private key KDF salt")
      (ok (= (ssh-keys:key-kdf-rounds key) 16)
          "Ed25519 encrypted (aes256-cbc) private key KDF rounds")
      (ok (string= (ssh-keys:key-passphrase key) "123456")
          "Ed25519 encrypted (aes256-cbc) private key passphrase")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string (get-test-key-path #P"id_ed25519_encrypted_aes256-cbc"))
                   (get-output-stream-string string-out-stream))
          "Write Ed25519 encrypted (aes256-cbc) private key")))

  (testing "aes128-ctr cipher"
    (let ((key (ssh-keys:parse-private-key-file (get-test-key-path #P"id_ed25519_encrypted_aes128-ctr")
                                                :passphrase "123456"))
          (string-out-stream (make-string-output-stream)))
      (ok (string= (ssh-keys:fingerprint :md5 key)
                   "13:67:ef:8f:75:2e:b2:de:32:53:af:4d:df:30:e9:89")
          "Ed25519 encrypted (aes128-ctr) private key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
                   "QTaQLwebmEeB+CBQ/7yMXHyBZzM")
          "Ed25519 encrypted (aes128-ctr) private key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
                   "bhY2M4AsyATQtB7Vdz7DKra6fxunTSLmBSszUt2pdQw")
          "Ed25519 encrypted (aes128-ctr) private key SHA-256 fingerprint")
      (ok (equal (ssh-keys:key-kind key)
                 '(:name "ssh-ed25519" :plain-name "ssh-ed25519" :short-name "ED25519" :id :ssh-ed25519 :is-cert nil))
          "Ed25519 encrypted (aes128-ctr) private key kind")
      (ok (= (ssh-keys:key-bits key) 256)
          "Ed25519 encrypted (aes128-ctr) private key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "Ed25519 encrypted (aes128-ctr) private key comment")

      (ok (string= (ssh-keys:key-cipher-name key) "aes128-ctr")
          "Ed25519 encrypted (aes128-ctr) private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name key) "bcrypt")
          "Ed25519 encrypted (aes128-ctr) private key KDF name")
      (ok (= (length (ssh-keys:key-kdf-salt key)) 16)
          "Ed25519 encrypted (aes128-ctr) private key KDF salt")
      (ok (= (ssh-keys:key-kdf-rounds key) 16)
          "Ed25519 encrypted (aes128-ctr) private key KDF rounds")
      (ok (string= (ssh-keys:key-passphrase key) "123456")
          "Ed25519 encrypted (aes128-ctr) private key passphrase")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string (get-test-key-path #P"id_ed25519_encrypted_aes128-ctr"))
                   (get-output-stream-string string-out-stream))
          "Write Ed25519 encrypted (aes128-ctr) private key")))

  (testing "aes192-ctr cipher"
    (let ((key (ssh-keys:parse-private-key-file (get-test-key-path #P"id_ed25519_encrypted_aes192-ctr")
                                                :passphrase "123456"))
          (string-out-stream (make-string-output-stream)))
      (ok (string= (ssh-keys:fingerprint :md5 key)
                   "52:b1:86:94:6e:29:02:2c:ef:cf:71:f5:a8:30:ba:10")
          "Ed25519 encrypted (aes192-ctr) private key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
                   "Jo8jDqzVpnnC4QTOy1jFLWnm7zs")
          "Ed25519 encrypted (aes192-ctr) private key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
                   "8riamI/02xAvqncuVJZwjdlMH4wEy8AQnfSfJtwSw3I")
          "Ed25519 encrypted (aes192-ctr) private key SHA-256 fingerprint")
      (ok (equal (ssh-keys:key-kind key)
                 '(:name "ssh-ed25519" :plain-name "ssh-ed25519" :short-name "ED25519" :id :ssh-ed25519 :is-cert nil))
          "Ed25519 encrypted (aes192-ctr) private key kind")
      (ok (= (ssh-keys:key-bits key) 256)
          "Ed25519 encrypted (aes192-ctr) private key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "Ed25519 encrypted (aes192-ctr) private key comment")

      (ok (string= (ssh-keys:key-cipher-name key) "aes192-ctr")
          "Ed25519 encrypted (aes192-ctr) private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name key) "bcrypt")
          "Ed25519 encrypted (aes192-ctr) private key KDF name")
      (ok (= (length (ssh-keys:key-kdf-salt key)) 16)
          "Ed25519 encrypted (aes192-ctr) private key KDF salt")
      (ok (= (ssh-keys:key-kdf-rounds key) 16)
          "Ed25519 encrypted (aes192-ctr) private key KDF rounds")
      (ok (string= (ssh-keys:key-passphrase key) "123456")
          "Ed25519 encrypted (aes192-ctr) private key passphrase")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string (get-test-key-path #P"id_ed25519_encrypted_aes192-ctr"))
                   (get-output-stream-string string-out-stream))
          "Write Ed25519 encrypted (aes192-ctr) private key")))

  (testing "aes256-ctr cipher"
    (let ((key (ssh-keys:parse-private-key-file (get-test-key-path #P"id_ed25519_encrypted_aes256-ctr")
                                                :passphrase "123456"))
          (string-out-stream (make-string-output-stream)))
      (ok (string= (ssh-keys:fingerprint :md5 key)
                   "a1:bf:ff:ba:2a:04:b8:86:ea:5f:85:9d:c9:2c:ee:0d")
          "Ed25519 encrypted (aes256-ctr) private key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
                   "JeZ3q25UyCL7y8VoZ3iCEEcNt4U")
          "Ed25519 encrypted (aes256-ctr) private key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
                   "0fBYbmAenJiWA7mTnpNkq1E7YbKKsMtoFOmhiSptPMc")
          "Ed25519 encrypted (aes256-ctr) private key SHA-256 fingerprint")
      (ok (equal (ssh-keys:key-kind key)
                 '(:name "ssh-ed25519" :plain-name "ssh-ed25519" :short-name "ED25519" :id :ssh-ed25519 :is-cert nil))
          "Ed25519 encrypted (aes256-ctr) private key kind")
      (ok (= (ssh-keys:key-bits key) 256)
          "Ed25519 encrypted (aes256-ctr) private key number of bits")
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
          "Ed25519 encrypted (aes256-ctr) private key comment")

      (ok (string= (ssh-keys:key-cipher-name key) "aes256-ctr")
          "Ed25519 encrypted (aes256-ctr) private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name key) "bcrypt")
          "Ed25519 encrypted (aes256-ctr) private key KDF name")
      (ok (= (length (ssh-keys:key-kdf-salt key)) 16)
          "Ed25519 encrypted (aes256-ctr) private key KDF salt")
      (ok (= (ssh-keys:key-kdf-rounds key) 16)
          "Ed25519 encrypted (aes256-ctr) private key KDF rounds")
      (ok (string= (ssh-keys:key-passphrase key) "123456")
          "Ed25519 encrypted (aes256-ctr) private key passphrase")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string (get-test-key-path #P"id_ed25519_encrypted_aes256-ctr"))
                   (get-output-stream-string string-out-stream))
          "Write Ed25519 encrypted (aes256-ctr) private key")))

  (testing "bad passphrases"
    (ok (signals (ssh-keys:parse-private-key-file (get-test-key-path #P"id_ed25519_encrypted_3des-cbc")
                                                  :passphrase "wrong-passphrase"))
        "Bad passphrase for encrypted (3des-cbc) private key")
    (ok (signals (ssh-keys:parse-private-key-file (get-test-key-path #P"id_rsa_3072_encrypted_aes128-cbc")
                                                  :passphrase "wrong-passphrase"))
        "Bad passphrase for encrypted (aes128-cbc) private key")
    (ok (signals (ssh-keys:parse-private-key-file (get-test-key-path #P"id_ed25519_encrypted_aes192-cbc")
                                                  :passphrase "wrong-passphrase"))
        "Bad passphrase for encrypted (aes192-cbc) private key")
    (ok (signals (ssh-keys:parse-private-key-file (get-test-key-path #P"id_ed25519_encrypted_aes256-cbc")
                                                  :passphrase "wrong-passphrase"))
        "Bad passphrase for encrypted (aes256-cbc) private key")
    (ok (signals (ssh-keys:parse-private-key-file (get-test-key-path #P"id_ed25519_encrypted_aes128-ctr")
                                                  :passphrase "wrong-passphrase"))
        "Bad passphrase for encrypted (aes128-ctr) private key")
    (ok (signals (ssh-keys:parse-private-key-file (get-test-key-path #P"id_ed25519_encrypted_aes192-ctr")
                                                  :passphrase "wrong-passphrase"))
        "Bad passphrase for encrypted (aes192-ctr) private key")
    (ok (signals (ssh-keys:parse-private-key-file (get-test-key-path #P"id_ed25519_encrypted_aes256-ctr")
                                                  :passphrase "wrong-passphrase"))
        "Bad passphrase for encrypted (aes256-ctr) private key")))

(deftest ssh-cert-valid-principals
  (testing "encode :ssh-cert-valid-principals -- non-empty list"
    (let* ((data '("root" "john.doe"))
           (s (rfc4251:make-binary-output-stream))
           (size (rfc4251:encode :ssh-cert-valid-principals data s))
           (encoded (rfc4251:get-binary-stream-bytes s)))
      (ok (= size 24)
          "Number of encoded bytes matches")
      (ok (equalp encoded
                  #(#x00 #x00 #x00 #x14 #x00 #x00 #x00 #x04 #x72 #x6F #x6F #x74 #x00 #x00 #x00 #x08 #x6A #x6F #x68 #x6E #x2E #x64 #x6F #x65))
          "Encoded bytes match")))

  (testing "decode :ssh-cert-valid-principals -- non-empty value"
    (let* ((data #(#x00 #x00 #x00 #x0C #x00 #x00 #x00 #x08 #x6A #x6F #x68 #x6E #x2E #x64 #x6F #x65))
           (s (rfc4251:make-binary-input-stream data)))
      (ok (equal '(("john.doe") 16)
                 (multiple-value-list (rfc4251:decode :ssh-cert-valid-principals s)))
          "Decode non-empty valid principals")))

  (testing "encode :ssh-cert-valid-principals -- empty list"
    (let* ((data (list))
           (s (rfc4251:make-binary-output-stream))
           (size (rfc4251:encode :ssh-cert-valid-principals data s))
           (encoded (rfc4251:get-binary-stream-bytes s)))
      (ok (= size 4)
          "Number of encoded bytes matches")
      (ok (equalp encoded #(#x00 #x00 #x00 #x00))
          "Encoded bytes match")))

  (testing "decode :ssh-cert-valid-principals -- empty list"
    (let* ((data #(#x00 #x00 #x00 #x00))
           (s (rfc4251:make-binary-input-stream data)))
      (ok (equal '(nil 4)
                 (multiple-value-list (rfc4251:decode :ssh-cert-valid-principals s)))
          "Decode empty list of valid principals"))))

(deftest ssh-cert-critical-options
  (testing "encode :ssh-cert-critical-options -- non-empty value"
    (let ((s (rfc4251:make-binary-output-stream))
          (options '(("source-address" . "127.0.0.1/32,10.0.0.0/8")))
          (want-bytes #(#x00 #x00 #x00 #x31 #x00 #x00 #x00 #x0E
                       #x73 #x6F #x75 #x72 #x63 #x65 #x2D #x61
                       #x64 #x64 #x72 #x65 #x73 #x73 #x00 #x00
                       #x00 #x1B #x00 #x00 #x00 #x17 #x31 #x32
                       #x37 #x2E #x30 #x2E #x30 #x2E #x31 #x2F
                       #x33 #x32 #x2C #x31 #x30 #x2E #x30 #x2E
                       #x30 #x2E #x30 #x2F #x38))
          (want-size 53))
      (ok (= want-size (rfc4251:encode :ssh-cert-critical-options options s))
          "Encoded number of bytes match")
      (ok (equalp want-bytes (rfc4251:get-binary-stream-bytes s))
          "Encoded bytes match")))

  (testing "decode :ssh-cert-critical-options -- non-empty value"
    (let* ((data #(#x00 #x00 #x00 #x51 #x00 #x00 #x00
                  #x0D #x66 #x6F #x72 #x63 #x65 #x2D
                  #x63 #x6F #x6D #x6D #x61 #x6E #x64
                  #x00 #x00 #x00 #x0B #x00 #x00 #x00
                  #x07 #x2F #x62 #x69 #x6E #x2F #x73
                  #x68 #x00 #x00 #x00 #x0E #x73 #x6F
                  #x75 #x72 #x63 #x65 #x2D #x61 #x64
                  #x64 #x72 #x65 #x73 #x73 #x00 #x00
                  #x00 #x1B #x00 #x00 #x00 #x17 #x31
                  #x32 #x37 #x2E #x30 #x2E #x30 #x2E
                  #x31 #x2F #x33 #x32 #x2C #x31 #x30
                  #x2E #x30 #x2E #x30 #x2E #x30 #x2F #x38))
           (s (rfc4251:make-binary-input-stream data))
           (want-size 85)
           (want-data '(("force-command" . "/bin/sh")
                        ("source-address" . "127.0.0.1/32,10.0.0.0/8"))))
      (ok (equalp (list want-data want-size)
                  (multiple-value-list (rfc4251:decode :ssh-cert-critical-options s)))
          "Decoded data matches")))

  (testing "encode :ssh-cert-critical-options -- empty value"
    (let ((s (rfc4251:make-binary-output-stream))
          (want-size 4)
          (want-bytes #(#x00 #x00 #x00 #x00)))
      (ok (= want-size (rfc4251:encode :ssh-cert-critical-options nil s))
          "Encoded number of bytes matches")
      (ok (equalp want-bytes (rfc4251:get-binary-stream-bytes s))
          "Encoded bytes match")))

  (testing "decode :ssh-cert-critical-options -- empty value"
    (let* ((data #(#x00 #x00 #x00 #x00))
           (s (rfc4251:make-binary-input-stream data)))
      (ok (equal '(nil 4)
                 (multiple-value-list (rfc4251:decode :ssh-cert-critical-options s)))
          "Decoded data matches"))))

(deftest ssh-cert-extensions
  (testing "encode :ssh-cert-extensions -- non-empty value"
    (let* ((s (rfc4251:make-binary-output-stream))
           (extensions '("permit-X11-forwarding"
                         "permit-agent-forwarding"
                         "permit-port-forwarding"
                         "permit-pty"
                         "permit-user-rc"))
           (want-data #(#x00 #x00 #x00 #x82 #x00 #x00 #x00
                       #x15 #x70 #x65 #x72 #x6D #x69 #x74
                       #x2D #x58 #x31 #x31 #x2D #x66 #x6F
                       #x72 #x77 #x61 #x72 #x64 #x69 #x6E
                       #x67 #x00 #x00 #x00 #x00 #x00 #x00
                       #x00 #x17 #x70 #x65 #x72 #x6D #x69
                       #x74 #x2D #x61 #x67 #x65 #x6E #x74
                       #x2D #x66 #x6F #x72 #x77 #x61 #x72
                       #x64 #x69 #x6E #x67 #x00 #x00 #x00
                       #x00 #x00 #x00 #x00 #x16 #x70 #x65
                       #x72 #x6D #x69 #x74 #x2D #x70 #x6F
                       #x72 #x74 #x2D #x66 #x6F #x72 #x77
                       #x61 #x72 #x64 #x69 #x6E #x67 #x00
                       #x00 #x00 #x00 #x00 #x00 #x00 #x0A
                       #x70 #x65 #x72 #x6D #x69 #x74 #x2D
                       #x70 #x74 #x79 #x00 #x00 #x00 #x00
                       #x00 #x00 #x00 #x0E #x70 #x65 #x72
                       #x6D #x69 #x74 #x2D #x75 #x73 #x65
                       #x72 #x2D #x72 #x63 #x00 #x00 #x00 #x00))
           (want-size 134))
      (ok (= want-size (rfc4251:encode :ssh-cert-extensions extensions s))
          "Encoded number of bytes match")
      (ok (equalp want-data (rfc4251:get-binary-stream-bytes s))
          "Encoded bytes match")))

  (testing "decode :ssh-cert-extensions -- non-empty value"
    (let* ((data #(#x00 #x00 #x00 #x82 #x00 #x00 #x00
                  #x15 #x70 #x65 #x72 #x6D #x69 #x74
                  #x2D #x58 #x31 #x31 #x2D #x66 #x6F
                  #x72 #x77 #x61 #x72 #x64 #x69 #x6E
                  #x67 #x00 #x00 #x00 #x00 #x00 #x00
                  #x00 #x17 #x70 #x65 #x72 #x6D #x69
                  #x74 #x2D #x61 #x67 #x65 #x6E #x74
                  #x2D #x66 #x6F #x72 #x77 #x61 #x72
                  #x64 #x69 #x6E #x67 #x00 #x00 #x00
                  #x00 #x00 #x00 #x00 #x16 #x70 #x65
                  #x72 #x6D #x69 #x74 #x2D #x70 #x6F
                  #x72 #x74 #x2D #x66 #x6F #x72 #x77
                  #x61 #x72 #x64 #x69 #x6E #x67 #x00
                  #x00 #x00 #x00 #x00 #x00 #x00 #x0A
                  #x70 #x65 #x72 #x6D #x69 #x74 #x2D
                  #x70 #x74 #x79 #x00 #x00 #x00 #x00
                  #x00 #x00 #x00 #x0E #x70 #x65 #x72
                  #x6D #x69 #x74 #x2D #x75 #x73 #x65
                  #x72 #x2D #x72 #x63 #x00 #x00 #x00 #x00))
           (s (rfc4251:make-binary-input-stream data))
           (want-extensions '("permit-X11-forwarding"
                              "permit-agent-forwarding"
                              "permit-port-forwarding"
                              "permit-pty"
                              "permit-user-rc"))
           (want-size 134))
      (ok (equal (list want-extensions want-size)
                 (multiple-value-list (rfc4251:decode :ssh-cert-extensions s)))
          "Decoded data matches")))

  (testing "encode :ssh-cert-extensions -- empty value"
    (let ((s (rfc4251:make-binary-output-stream))
          (want-bytes #(#x00 #x00 #x00 #x00))
          (want-size 4))
      (ok (= want-size (rfc4251:encode :ssh-cert-extensions nil s))
          "Encoded number of bytes match")
      (ok (equalp want-bytes (rfc4251:get-binary-stream-bytes s))
          "Encoded bytes match")))

  (testing "decode :ssh-cert-extensions -- empty value"
    (let* ((data #(#x00 #x00 #x00 #x00))
           (s (rfc4251:make-binary-input-stream data)))
      (ok (equal '(nil 4)
                 (multiple-value-list (rfc4251:decode :ssh-cert-extensions s)))
          "Decoded data matches"))))

(deftest ssh-rsa-cert-v01
  (testing "decode ssh-rsa-cert-v01"
    (let* ((cert-file-path (get-test-key-path #P"id_rsa_3072-cert.pub"))
	   (key (ssh-keys:parse-public-key-file cert-file-path))
	   (string-out-stream (make-string-output-stream)))
      ;; Client key
      (ok (string= (ssh-keys:fingerprint :md5 key)
		   "04:02:4b:b2:43:39:a4:8e:89:47:49:6f:30:78:94:1e")
	  "Client key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
		   "RnLPLG93GrABjOqc6xOvVFpQXsc")
	  "Client key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
		   "VmYpd+5gvA5Cj57ZZcI8lnFMNNic6jpnnBd0WoNG1F8")
	  "Client key SHA-256 fingerprint")

      ;; Key kind
      (ok (equalp (ssh-keys:key-kind key)
		  '(:name "ssh-rsa-cert-v01@openssh.com"
		    :plain-name "ssh-rsa"
		    :short-name "RSA-CERT"
		    :id :ssh-rsa-cert-v01
		    :is-cert t))
	  "Key kind")

      ;; Key comment
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
	  "Key comment")

      ;; CA key
      (ok (string= (ssh-keys:fingerprint :md5 (ssh-keys:cert-signature-key key))
		   "73:08:1c:1b:e5:63:0f:46:a7:87:c9:34:10:e9:bc:ee")
	  "CA key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 (ssh-keys:cert-signature-key key))
		   "yLj/8sjCpPxWVngCdxd9jnsSfjg")
	  "CA key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 (ssh-keys:cert-signature-key key))
		   "TqL9a97yRr48oop+puCjf4sxwiwevsBQ7N+jVScnBhY")
	  "CA key SHA-256 fingerprint")

      ;; Serial
      (ok (= 0 (ssh-keys:cert-serial key))
	  "Serial number")

      ;; Key identity
      (ok (string= (ssh-keys:cert-key-id key) "john.doe")
	  "Key identity")

      ;; Valid principals
      (ok (equal (ssh-keys:cert-valid-principals key) nil)
	  "Valid principals")

      ;; Valid After
      (ok (equal (ssh-keys:cert-valid-after key) 0)
	  "Valid After")

      ;; Valid Before
      (ok (equal (ssh-keys:cert-valid-before key) ssh-keys:+ssh-cert-max-valid-to+)
	  "Valid Before")

      ;; Critical Options
      (ok (equal (ssh-keys:cert-critical-options key) nil)
	  "Critical options")

      ;; Extensions
      (ok (equal (ssh-keys:cert-extensions key)
		 '("permit-X11-forwarding"
		   "permit-agent-forwarding"
		   "permit-port-forwarding"
		   "permit-pty"
		   "permit-user-rc"))
	  "Extensions")

      ;; Reserved
      (ok (equalp (ssh-keys:cert-reserved key) #())
	  "Reserved")

      ;; Signature
      (ok (equal (ssh-keys:signature-type (ssh-keys:cert-signature key))
		 '(:name "rsa-sha2-512" :digest :sha512))
	  "Signature type")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string cert-file-path)
		   (get-output-stream-string string-out-stream))
	  "Write cert file into text representation"))))

(deftest ssh-dss-cert-v01
  (testing "decode ssh-dss-cert-v01"
    (let* ((cert-file-path (get-test-key-path #P"id_dsa-cert.pub"))
	   (key (ssh-keys:parse-public-key-file cert-file-path))
	   (string-out-stream (make-string-output-stream)))
      ;; Client key
      (ok (string= (ssh-keys:fingerprint :md5 key)
		   "ee:c9:41:84:29:e7:1f:95:98:ac:35:75:a5:5b:c7:a6")
	  "Client key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
		   "2KBDiLfGio8CGoSHG4v2/CP2p/w")
	  "Client key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
		   "kdAVH2jkXqT0WPyczN9bXsyH4WCct87C4kH55kTdqRo")
	  "Client key SHA-256 fingerprint")

      ;; Key kind
      (ok (equalp (ssh-keys:key-kind key)
		  '(:name "ssh-dss-cert-v01@openssh.com"
		    :plain-name "ssh-dss"
		    :short-name "DSA-CERT"
		    :id :ssh-dss-cert-v01
		    :is-cert t))
	  "Key kind")

      ;; Key comment
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
	  "Key comment")

      ;; CA key
      (ok (string= (ssh-keys:fingerprint :md5 (ssh-keys:cert-signature-key key))
		   "73:08:1c:1b:e5:63:0f:46:a7:87:c9:34:10:e9:bc:ee")
	  "CA key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 (ssh-keys:cert-signature-key key))
		   "yLj/8sjCpPxWVngCdxd9jnsSfjg")
	  "CA key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 (ssh-keys:cert-signature-key key))
		   "TqL9a97yRr48oop+puCjf4sxwiwevsBQ7N+jVScnBhY")
	  "CA key SHA-256 fingerprint")

      ;; Serial
      (ok (= 0 (ssh-keys:cert-serial key))
	  "Serial number")

      ;; Key identity
      (ok (string= (ssh-keys:cert-key-id key) "john.doe")
	  "Key identity")

      ;; Valid principals
      (ok (equal (ssh-keys:cert-valid-principals key) nil)
	  "Valid principals")

      ;; Valid After
      (ok (equal (ssh-keys:cert-valid-after key) 0)
	  "Valid After")

      ;; Valid Before
      (ok (equal (ssh-keys:cert-valid-before key) ssh-keys:+ssh-cert-max-valid-to+)
	  "Valid Before")

      ;; Critical Options
      (ok (equal (ssh-keys:cert-critical-options key) nil)
	  "Critical options")

      ;; Extensions
      (ok (equal (ssh-keys:cert-extensions key)
		 '("permit-X11-forwarding"
		   "permit-agent-forwarding"
		   "permit-port-forwarding"
		   "permit-pty"
		   "permit-user-rc"))
	  "Extensions")

      ;; Reserved
      (ok (equalp (ssh-keys:cert-reserved key) #())
	  "Reserved")

      ;; Signature
      (ok (equal (ssh-keys:signature-type (ssh-keys:cert-signature key))
		 '(:name "rsa-sha2-512" :digest :sha512))
	  "Signature type")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string cert-file-path)
		   (get-output-stream-string string-out-stream))
	  "Write cert file into text representation"))))

(deftest ecdsa-sha2-nistp256-cert-v01
  (testing "decode ecdsa-sha2-nistp256-cert-v01"
    (let* ((cert-file-path (get-test-key-path #P"id_ecdsa_nistp256-cert.pub"))
	   (key (ssh-keys:parse-public-key-file cert-file-path))
	   (string-out-stream (make-string-output-stream)))
      ;; Client key
      (ok (string= (ssh-keys:fingerprint :md5 key)
		   "3a:36:ba:c7:2c:26:9e:e3:14:bb:61:40:46:60:31:ae")
	  "Client key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
		   "eTmWRwNGK7FQsfbFiIGzfNG2hxo")
	  "Client key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
		   "q56e29ej1aTV9ptIX/ERikzqk0HWEtaBDBH33ziQVSM")
	  "Client key SHA-256 fingerprint")

      ;; Key kind
      (ok (equalp (ssh-keys:key-kind key)
		  '(:name "ecdsa-sha2-nistp256-cert-v01@openssh.com"
		    :plain-name "ecdsa-sha2-nistp256"
		    :short-name "ECDSA-CERT"
		    :id :ecdsa-sha2-nistp256-cert-v01
		    :is-cert t))
	  "Key kind")

      ;; Key comment
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
	  "Key comment")

      ;; CA key
      (ok (string= (ssh-keys:fingerprint :md5 (ssh-keys:cert-signature-key key))
		   "73:08:1c:1b:e5:63:0f:46:a7:87:c9:34:10:e9:bc:ee")
	  "CA key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 (ssh-keys:cert-signature-key key))
		   "yLj/8sjCpPxWVngCdxd9jnsSfjg")
	  "CA key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 (ssh-keys:cert-signature-key key))
		   "TqL9a97yRr48oop+puCjf4sxwiwevsBQ7N+jVScnBhY")
	  "CA key SHA-256 fingerprint")

      ;; Serial
      (ok (= 0 (ssh-keys:cert-serial key))
	  "Serial number")

      ;; Key identity
      (ok (string= (ssh-keys:cert-key-id key) "john.doe")
	  "Key identity")

      ;; Valid principals
      (ok (equal (ssh-keys:cert-valid-principals key) nil)
	  "Valid principals")

      ;; Valid After
      (ok (equal (ssh-keys:cert-valid-after key) 0)
	  "Valid After")

      ;; Valid Before
      (ok (equal (ssh-keys:cert-valid-before key) ssh-keys:+ssh-cert-max-valid-to+)
	  "Valid Before")

      ;; Critical Options
      (ok (equal (ssh-keys:cert-critical-options key) nil)
	  "Critical options")

      ;; Extensions
      (ok (equal (ssh-keys:cert-extensions key)
		 '("permit-X11-forwarding"
		   "permit-agent-forwarding"
		   "permit-port-forwarding"
		   "permit-pty"
		   "permit-user-rc"))
	  "Extensions")

      ;; Reserved
      (ok (equalp (ssh-keys:cert-reserved key) #())
	  "Reserved")

      ;; Signature
      (ok (equal (ssh-keys:signature-type (ssh-keys:cert-signature key))
		 '(:name "rsa-sha2-512" :digest :sha512))
	  "Signature type")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string cert-file-path)
		   (get-output-stream-string string-out-stream))
	  "Write cert file into text representation"))))

(deftest ecdsa-sha2-nistp384-cert-v01
  (testing "decode ecdsa-sha2-nistp384-cert-v01"
    (let* ((cert-file-path (get-test-key-path #P"id_ecdsa_nistp384-cert.pub"))
	   (key (ssh-keys:parse-public-key-file cert-file-path))
	   (string-out-stream (make-string-output-stream)))
      ;; Client key
      (ok (string= (ssh-keys:fingerprint :md5 key)
		   "4b:4d:9f:0b:51:2a:0b:8c:7f:db:f2:e8:cc:20:93:f2")
	  "Client key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
		   "O4neOo5GtvUUZUErlDu8gD/MKr4")
	  "Client key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
		   "3HR8kr5XphIWXy312brnRHbrTMq6WmKP/8EkVMLRqMU")
	  "Client key SHA-256 fingerprint")

      ;; Key kind
      (ok (equalp (ssh-keys:key-kind key)
		  '(:name "ecdsa-sha2-nistp384-cert-v01@openssh.com"
		    :plain-name "ecdsa-sha2-nistp384"
		    :short-name "ECDSA-CERT"
		    :id :ecdsa-sha2-nistp384-cert-v01
		    :is-cert t))
	  "Key kind")

      ;; Key comment
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
	  "Key comment")

      ;; CA key
      (ok (string= (ssh-keys:fingerprint :md5 (ssh-keys:cert-signature-key key))
		   "73:08:1c:1b:e5:63:0f:46:a7:87:c9:34:10:e9:bc:ee")
	  "CA key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 (ssh-keys:cert-signature-key key))
		   "yLj/8sjCpPxWVngCdxd9jnsSfjg")
	  "CA key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 (ssh-keys:cert-signature-key key))
		   "TqL9a97yRr48oop+puCjf4sxwiwevsBQ7N+jVScnBhY")
	  "CA key SHA-256 fingerprint")

      ;; Serial
      (ok (= 0 (ssh-keys:cert-serial key))
	  "Serial number")

      ;; Key identity
      (ok (string= (ssh-keys:cert-key-id key) "john.doe")
	  "Key identity")

      ;; Valid principals
      (ok (equal (ssh-keys:cert-valid-principals key) nil)
	  "Valid principals")

      ;; Valid After
      (ok (equal (ssh-keys:cert-valid-after key) 0)
	  "Valid After")

      ;; Valid Before
      (ok (equal (ssh-keys:cert-valid-before key) ssh-keys:+ssh-cert-max-valid-to+)
	  "Valid Before")

      ;; Critical Options
      (ok (equal (ssh-keys:cert-critical-options key) nil)
	  "Critical options")

      ;; Extensions
      (ok (equal (ssh-keys:cert-extensions key)
		 '("permit-X11-forwarding"
		   "permit-agent-forwarding"
		   "permit-port-forwarding"
		   "permit-pty"
		   "permit-user-rc"))
	  "Extensions")

      ;; Reserved
      (ok (equalp (ssh-keys:cert-reserved key) #())
	  "Reserved")

      ;; Signature
      (ok (equal (ssh-keys:signature-type (ssh-keys:cert-signature key))
		 '(:name "rsa-sha2-512" :digest :sha512))
	  "Signature type")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string cert-file-path)
		   (get-output-stream-string string-out-stream))
	  "Write cert file into text representation"))))

(deftest ecdsa-sha2-nistp521-cert-v01
  (testing "decode ecdsa-sha2-nistp521-cert-v01"
    (let* ((cert-file-path (get-test-key-path #P"id_ecdsa_nistp521-cert.pub"))
	   (key (ssh-keys:parse-public-key-file cert-file-path))
	   (string-out-stream (make-string-output-stream)))
      ;; Client key
      (ok (string= (ssh-keys:fingerprint :md5 key)
		   "20:e7:81:b1:5b:25:5b:51:86:68:d9:0d:f2:4f:c2:bc")
	  "Client key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
		   "1itTOyxo/LDunoesxEBlQbvRnSM")
	  "Client key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
		   "IpPQNSCfvLbG1/RfcELgaG12r3RH4av+qWE32dp2yWE")
	  "Client key SHA-256 fingerprint")

      ;; Key kind
      (ok (equalp (ssh-keys:key-kind key)
		  '(:name "ecdsa-sha2-nistp521-cert-v01@openssh.com"
		    :plain-name "ecdsa-sha2-nistp521"
		    :short-name "ECDSA-CERT"
		    :id :ecdsa-sha2-nistp521-cert-v01
		    :is-cert t))
	  "Key kind")

      ;; Key comment
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
	  "Key comment")

      ;; CA key
      (ok (string= (ssh-keys:fingerprint :md5 (ssh-keys:cert-signature-key key))
		   "73:08:1c:1b:e5:63:0f:46:a7:87:c9:34:10:e9:bc:ee")
	  "CA key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 (ssh-keys:cert-signature-key key))
		   "yLj/8sjCpPxWVngCdxd9jnsSfjg")
	  "CA key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 (ssh-keys:cert-signature-key key))
		   "TqL9a97yRr48oop+puCjf4sxwiwevsBQ7N+jVScnBhY")
	  "CA key SHA-256 fingerprint")

      ;; Serial
      (ok (= 0 (ssh-keys:cert-serial key))
	  "Serial number")

      ;; Key identity
      (ok (string= (ssh-keys:cert-key-id key) "john.doe")
	  "Key identity")

      ;; Valid principals
      (ok (equal (ssh-keys:cert-valid-principals key) nil)
	  "Valid principals")

      ;; Valid After
      (ok (equal (ssh-keys:cert-valid-after key) 0)
	  "Valid After")

      ;; Valid Before
      (ok (equal (ssh-keys:cert-valid-before key) ssh-keys:+ssh-cert-max-valid-to+)
	  "Valid Before")

      ;; Critical Options
      (ok (equal (ssh-keys:cert-critical-options key) nil)
	  "Critical options")

      ;; Extensions
      (ok (equal (ssh-keys:cert-extensions key)
		 '("permit-X11-forwarding"
		   "permit-agent-forwarding"
		   "permit-port-forwarding"
		   "permit-pty"
		   "permit-user-rc"))
	  "Extensions")

      ;; Reserved
      (ok (equalp (ssh-keys:cert-reserved key) #())
	  "Reserved")

      ;; Signature
      (ok (equal (ssh-keys:signature-type (ssh-keys:cert-signature key))
		 '(:name "rsa-sha2-512" :digest :sha512))
	  "Signature type")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string cert-file-path)
		   (get-output-stream-string string-out-stream))
	  "Write cert file into text representation"))))

(deftest ssh-ed25519-cert-v01
  (testing "decode ssh-ed25519-cert-v01"
    (let* ((cert-file-path (get-test-key-path #P"id_ed25519-cert.pub"))
	   (key (ssh-keys:parse-public-key-file cert-file-path))
	   (string-out-stream (make-string-output-stream)))
      ;; Client key
      (ok (string= (ssh-keys:fingerprint :md5 key)
		   "5a:53:0e:89:dd:92:5b:5a:0a:e4:b7:f2:0e:81:49:fe")
	  "Client key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 key)
		   "wfa33emGK+n5KO6ksuyCP5J3nPI")
	  "Client key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 key)
		   "SVZTs6OE/EiAhmiZD9vGPQlavM+tmW0Y2pWRoUE+/kY")
	  "Client key SHA-256 fingerprint")

      ;; Key kind
      (ok (equalp (ssh-keys:key-kind key)
		  '(:name "ssh-ed25519-cert-v01@openssh.com"
		    :plain-name "ssh-ed25519"
		    :short-name "ED25519-CERT"
		    :id :ssh-ed25519-cert-v01
		    :is-cert t))
	  "Key kind")

      ;; Key comment
      (ok (string= (ssh-keys:key-comment key) "john.doe@localhost")
	  "Key comment")

      ;; CA key
      (ok (string= (ssh-keys:fingerprint :md5 (ssh-keys:cert-signature-key key))
		   "73:08:1c:1b:e5:63:0f:46:a7:87:c9:34:10:e9:bc:ee")
	  "CA key MD5 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha1 (ssh-keys:cert-signature-key key))
		   "yLj/8sjCpPxWVngCdxd9jnsSfjg")
	  "CA key SHA-1 fingerprint")
      (ok (string= (ssh-keys:fingerprint :sha256 (ssh-keys:cert-signature-key key))
		   "TqL9a97yRr48oop+puCjf4sxwiwevsBQ7N+jVScnBhY")
	  "CA key SHA-256 fingerprint")

      ;; Serial
      (ok (= 0 (ssh-keys:cert-serial key))
	  "Serial number")

      ;; Key identity
      (ok (string= (ssh-keys:cert-key-id key) "john.doe")
	  "Key identity")

      ;; Valid principals
      (ok (equal (ssh-keys:cert-valid-principals key) nil)
	  "Valid principals")

      ;; Valid After
      (ok (equal (ssh-keys:cert-valid-after key) 0)
	  "Valid After")

      ;; Valid Before
      (ok (equal (ssh-keys:cert-valid-before key) ssh-keys:+ssh-cert-max-valid-to+)
	  "Valid Before")

      ;; Critical Options
      (ok (equal (ssh-keys:cert-critical-options key) nil)
	  "Critical options")

      ;; Extensions
      (ok (equal (ssh-keys:cert-extensions key)
		 '("permit-X11-forwarding"
		   "permit-agent-forwarding"
		   "permit-port-forwarding"
		   "permit-pty"
		   "permit-user-rc"))
	  "Extensions")

      ;; Reserved
      (ok (equalp (ssh-keys:cert-reserved key) #())
	  "Reserved")

      ;; Signature
      (ok (equal (ssh-keys:signature-type (ssh-keys:cert-signature key))
		 '(:name "rsa-sha2-512" :digest :sha512))
	  "Signature type")

      ;; Verify encoding back into text representation
      (ssh-keys:write-key key string-out-stream)
      (ok (string= (alexandria:read-file-into-string cert-file-path)
		   (get-output-stream-string string-out-stream))
	  "Write cert file into text representation"))))
