(defpackage :cl-ssh-keys-system
  (:use :cl :asdf))
(in-package :cl-ssh-keys-system)

(defsystem "cl-ssh-keys"
  :name "cl-ssh-keys"
  :long-name "cl-ssh-keys"
  :description "Common Lisp system for generating and parsing of OpenSSH keys"
  :version "0.1.0"
  :author "Marin Atanasov Nikolov <dnaeon@gmail.com>"
  :maintainer "Marin Atanasov Nikolov <dnaeon@gmail.com>"
  :license "BSD 2-Clause"
  :long-description #.(uiop:read-file-string
                       (uiop:subpathname *load-pathname* "README.md"))
  :homepage "https://github.com/dnaeon/cl-ssh-keys"
  :bug-tracker "https://github.com/dnaeon/cl-ssh-keys"
  :source-control "https://github.com/dnaeon/cl-ssh-keys"
  :depends-on (:cl-rfc4251
               :ironclad
               :uiop
               :alexandria
               :binascii)
  :components ((:module "core"
                :pathname #P"src/"
                :components ((:file "package")
                             (:file "rfc8017")
                             (:file "generics" :depends-on ("package"))
                             (:file "public-key" :depends-on ("package"))
                             (:file "private-key" :depends-on ("package"))
                             (:file "conditions" :depends-on ("package"))
                             (:file "key-types" :depends-on ("package"))
                             (:file "ciphers" :depends-on ("package"))))
               (:module "keys"
                :pathname #P"src/"
                :depends-on ("core")
                :components ((:file "rsa")
                             (:file "dsa")
                             (:file "ed25519")
                             (:file "ecdsa-nistp256")
                             (:file "ecdsa-nistp384")
                             (:file "ecdsa-nistp521")
                             (:file "cert-key"))))
  :in-order-to ((test-op (test-op "cl-ssh-keys.test"))))
