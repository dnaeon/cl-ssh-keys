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
          "RSA 3072-bit private key cipher name")
      (ok (string= (ssh-keys:key-kdf-name key) "none")
          "RSA 3072-bit private key KDF name")
      (ok (equalp (ssh-keys:key-kdf-options key) #())
          "RSA 3072-bit private key KDF options")

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
      (ok (equalp (ssh-keys:key-kdf-options key) #())
          "RSA 3072-bit private key KDF options")

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
      (ok (equalp (ssh-keys:key-kdf-options priv-key) #())
          "Generated RSA private key KDF options")
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
      (ok (equalp (ssh-keys:key-kdf-options key) #())
          "DSA 1024-bit private key KDF options")

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
      (ok (equalp (ssh-keys:key-kdf-options priv-key) #())
          "Generated DSA private key KDF options")
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
      (ok (equalp (ssh-keys:key-kdf-options key) #())
          "Ed25519 private key KDF options")

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
      (ok (equalp (ssh-keys:key-kdf-options priv-key) #())
          "Generated Ed25519 private key KDF options")
      (ok (equal (ssh-keys:embedded-public-key priv-key)
                 pub-key)
          "Generated Ed25519 private key embedded public key")
      (ok (= (length (ssh-keys:ed25519-key-y priv-key)) 32)
          "Generated Ed25519 private key - y")
      (ok (= (length (ssh-keys:ed25519-key-x priv-key)) 32)
          "Generated Ed25519 private key - x"))))

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
      (ok (equalp (ssh-keys:key-kdf-options key) #())
          "ECDSA NIST P-384 private key KDF options")

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
      (ok (plusp (ssh-keys:secp384r1-key-y pub-key))
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
      (ok (equalp (ssh-keys:key-kdf-options priv-key) #())
          "Generated ECDSA NIST P-384 private key KDF options")
      (ok (equal (ssh-keys:embedded-public-key priv-key)
                 pub-key)
          "Generated ECDSA NIST P-384 private key embedded public key")
      (ok (plusp (ssh-keys:secp384r1-key-y priv-key))
          "Generated ECDSA NIST P-384 private key - y")
      (ok (plusp (ssh-keys:secp384r1-key-x priv-key))
          "Generated ECDSA NIST P-384 private key - x"))))

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
                 '(let ((key (ssh-keys:parse-private-key "-----BEGIN OPENSSH PRIVATE KEY----- ...")))
                   (ssh-keys:fingerprint :sha256 key)))
        "Test WITH-PRIVATE-KEY macro expanding"))
  (testing "with-private-key-file macro"
    (ok (expands '(ssh-keys:with-private-key-file (key #P"id_rsa")
                   (ssh-keys:fingerprint :sha256 key))
                 '(let ((key (ssh-keys:parse-private-key-file #P"id_rsa")))
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
