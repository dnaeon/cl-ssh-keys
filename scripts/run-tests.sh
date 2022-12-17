#!/usr/bin/env sh

set -e

LISP=${LISP:-sbcl}

${LISP} --eval '(ql:quickload :cl-ssh-keys.test)' \
        --eval '(setf rove:*enable-colors* nil)' \
        --eval '(asdf:test-system :cl-ssh-keys.test)' \
        --eval '(uiop:quit (length (rove/core/stats:all-failed-assertions rove/core/stats:*stats*)))'
