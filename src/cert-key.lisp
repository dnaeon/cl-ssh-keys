;; Copyright (c) 2020-2021 Marin Atanasov Nikolov <dnaeon@gmail.com>
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

(defconstant +ssh-cert-type-user+ 1
  "Indicates a user certificate")

(defconstant +ssh-cert-type-host+ 2
  "Indicates a host certificate")

(defconstant +ssh-cert-max-valid-to+ (1- (expt 2 64))
  "Max expiry date for a certificate")

(defparameter *ssh-cert-options*
  `((:name "force-command"
     :description ,(format nil "Specifies a command that is executed ~
                                (replacing any the user specified on the ~
                                ssh command-line) whenever this key is ~
                                used for authentication.")
     :is-critical t)
    (:name "source-address"
     :description ,(format nil "Comma-separated list of source addresses ~
                               from which this certificate is accepted ~
                               for authentication. Addresses are ~
                               specified in CIDR format (nn.nn.nn.nn/nn ~
                               or hhhh::hhhh/nn). ~
                               If this option is not present then ~
                               certificates may be presented from any ~
                               source address.")
     :is-critical t)
    (:name "no-presence-required"
     :description ,(format nil "Flag indicating that signatures made with ~
                                this certificate need not assert user ~
                                presence. This option only makes sense for ~
                                the U2F/FIDO security key types that support ~
                                this feature in their signature formats.")
     :is-critical nil)
    (:name "permit-X11-forwarding"
     :description ,(format nil "Flag indicating that X11 forwarding ~
                                should be permitted. X11 forwarding will ~
                                be refused if this option is absent."))
    (:name "permit-agent-forwarding"
     :description ,(format nil "Flag indicating that agent forwarding should be ~
                                allowed. Agent forwarding must not be permitted ~
                                unless this option is present.")
     :is-critical nil)
    (:name "permit-port-forwarding"
     :description ,(format nil "Flag indicating that port-forwarding ~
                                should be allowed. If this option is ~
                                not present then no port forwarding will ~
                                be allowed.")
     :is-critical nil)
    (:name "permit-pty"
     :description ,(format nil "Flag indicating that PTY allocation ~
                                should be permitted. In the absence of ~
                                this option PTY allocation will be disabled.")
     :is-critical nil)
    (:name "permit-user-rc"
     :description ,(format nil "Flag indicating that execution of ~
                                ~~/.ssh/rc should be permitted. Execution ~
                                of this script will not be permitted if ~
                                this option is not present.")
     :is-critical nil))
  "Supported OpenSSH certificate options")

(defun describe-cert-option (name)
  "Describe the OpenSSH certificate option with the given NAME"
  (let ((option (find name *ssh-cert-options* :key (lambda (x) (getf x :name)) :test #'string=)))
    (when option
      (format t "Name: ~a~%" (getf option :name))
      (format t "Is Critical: ~a~%" (getf option :is-critical))
      (format t "Description: ~a~%" (getf option :description)))))

(defun get-supported-cert-options ()
  "Returns a list of the supported certificate options"
  (mapcar (lambda (option)
            (getf option :name))
          *ssh-cert-options*))

(defmethod rfc4251:decode ((type (eql :ssh-cert-embedded-strings)) stream &key)
  "Decode a list of embedded strings from an OpenSSH certificate key.

The OpenSSH certificate format encodes the list of `valid principals`
as a list of strings embedded within a buffer. While this seems okay
it makes you wonder why not using the `name-list` data type from RFC
4251, section 5 instead, since `name-list` solves this particular
problem."
  (let ((header-size 4)  ;; uint32 specifying the buffer size
        (length (rfc4251:decode :uint32 stream))) ;; Number of bytes representing the buffer
    (when (zerop length)
      (return-from rfc4251:decode (values nil header-size)))
    (loop for (value size) = (multiple-value-list (rfc4251:decode :string stream))
          :summing size :into total
          :collect value :into result
          :while (< total length)
          :finally (return (values result (+ header-size length))))))
