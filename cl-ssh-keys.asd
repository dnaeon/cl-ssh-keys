(defpackage :cl-ssh-keys-system
  (:use :cl :asdf))
(in-package :cl-ssh-keys-system)

(defsystem "cl-ssh-keys"
  :name "cl-ssh-keys"
  :long-name "cl-ssh-keys"
  :description "Common Lisp system for generating and parsing OpenSSH keys"
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
                :components ((:file "core")))
               (:module "keys"
                :pathname #P"src/"
                :depends-on ("core")
                :components ((:file "rsa")))
               (:module "client-package"
                :pathname #P"src/"
                :depends-on ("core" "keys")
                :components ((:file "package"))))
  :in-order-to ((test-op (test-op "cl-ssh-keys.test"))))
