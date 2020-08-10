#!/usr/bin/env sh

set -e

sbcl --eval '(ql:quickload :cl-ssh-keys.test)' \
     --eval '(setf rove:*enable-colors* nil)' \
     --eval '(asdf:test-system :cl-ssh-keys.test)' \
     --eval '(quit)'
