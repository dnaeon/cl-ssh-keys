(defpackage cl-ssh-keys-test-system
  (:use :cl :asdf))
(in-package :cl-ssh-keys-test-system)

(defsystem "cl-ssh-keys.test"
  :name "cl-ssh-keys.test"
  :long-name "cl-ssh-keys.test"
  :description "Test suite for cl-ssh-keys system"
  :version "0.1.0"
  :author "Marin Atanasov Nikolov <dnaeon@gmail.com>"
  :maintainer "Marin Atanasov Nikolov <dnaeon@gmail.com>"
  :license "BSD 2-Clause"
  :homepage "https://github.com/dnaeon/cl-ssh-keys"
  :bug-tracker "https://github.com/dnaeon/cl-ssh-keys"
  :source-control "https://github.com/dnaeon/cl-ssh-keys"
  :depends-on (:cl-ssh-keys
               :rove)
  :components ((:module "tests"
                :pathname #P"t/"
                :components ((:file "test-suite"))))
  :perform (test-op (op c) (uiop:symbol-call :rove :run-suite :cl-ssh-keys.test)))
