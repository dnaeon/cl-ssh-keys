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
                                be refused if this option is absent.")
     :is-critical nil)
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

(defun get-cert-critical-options ()
  "Returns the list of certificate critical options"
  (remove-if-not (lambda (item)
                   (getf item :is-critical))
                 *ssh-cert-options*))

(defmethod rfc4251:decode ((type (eql :ssh-cert-valid-principals)) stream &key)
  "Decode the list of valid principals from an OpenSSH certificate key.

The OpenSSH certificate format encodes the list of `valid principals`
as a list of strings embedded within a buffer. While this seems okay
it makes you wonder why not using the `name-list` data type from RFC
4251, section 5 instead, since `name-list` solves this particular
problem."
  (let ((header-size 4)  ;; uint32 specifying the buffer size
        (length (rfc4251:decode :uint32 stream)))  ;; Number of bytes representing the buffer
    (when (zerop length)
      (return-from rfc4251:decode (values nil header-size)))
    (loop :for (value size) = (multiple-value-list (rfc4251:decode :string stream))
          :summing size :into total
          :collect value :into result
          :while (< total length)
          :finally (return (values result (+ header-size total))))))

(defmethod rfc4251:encode ((type (eql :ssh-cert-valid-principals)) value stream &key)
  "Encode a list of valid principals into an OpenSSH certificate key"
  (let ((s (rfc4251:make-binary-output-stream)))
    (loop :for item :in value :do
      (rfc4251:encode :string item s))
    (rfc4251:encode :buffer (rfc4251:get-binary-stream-bytes s) stream)))

(defmethod rfc4251:decode ((type (eql :ssh-cert-critical-options)) stream &key)
  "Decode OpenSSH certificate critical options.

Please refer to [1] for more details.

[1]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys"
  (let ((header-size 4)  ;; uint32 specifying the buffer size
        (length (rfc4251:decode :uint32 stream)))  ;; Number of bytes representing the options data
    (when (zerop length)
      (return-from rfc4251:decode (values nil header-size)))
    (loop :for (name name-size) = (multiple-value-list (rfc4251:decode :string stream))
          ;; The data is packed inside another string buffer
          :for (buffer buffer-size) = (multiple-value-list (rfc4251:decode :buffer stream))
          :for data-stream = (rfc4251:make-binary-input-stream buffer)
          :for data = (rfc4251:decode :string data-stream)
          :summing name-size :into total
          :summing buffer-size :into total
          :collect (cons name data) :into result
          :while (< total length)
          :finally (return (values result (+ header-size total))))))

(defmethod rfc4251:encode ((type (eql :ssh-cert-critical-options)) value stream &key)
  "Encode OpenSSH certificate critical options list.
VALUE is a list a of cons cells, each representing a
critical option, e.g. (OPTION-NAME . OPTION-VALUE)."
  (let ((s (rfc4251:make-binary-output-stream))) ;; Use a temp stream and encode it as a whole once ready
    (loop :for (option-name . option-value) :in value :do
      (rfc4251:encode :string option-name s)
      ;; The option-value is packed inside a buffer
      (rfc4251:with-binary-output-stream (option-s)
        (rfc4251:encode :string option-value option-s)
        (rfc4251:encode :buffer (rfc4251:get-binary-stream-bytes option-s) s)))
    (rfc4251:encode :buffer (rfc4251:get-binary-stream-bytes s) stream)))

(defmethod rfc4251:decode ((type (eql :ssh-cert-extensions)) stream &key)
  "Decode OpenSSH certificate extensions.

Please refer to [1] for more details.

[1]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys"
  (let ((header-size 4)  ;; uint32 specifying the buffer size
        (length (rfc4251:decode :uint32 stream)))  ;; Number of bytes representing the options data
    (when (zerop length)
      (return-from rfc4251:decode (values nil header-size)))
    (loop :for (name name-size) = (multiple-value-list (rfc4251:decode :string stream))
          :for (nil data-size) = (multiple-value-list (rfc4251:decode :string stream))
          :summing name-size :into total
          :summing data-size :into total
          :collect name :into result
          :while (< total length)
          :finally (return (values result (+ header-size total))))))

(defmethod rfc4251:encode ((type (eql :ssh-cert-extensions)) value stream &key)
  "Encodes a list of OpenSSH certificate extensions

Please refer to [1] for more details.

[1]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys"
  (let ((s (rfc4251:make-binary-output-stream)))
    (loop :for name :in value :do
      (rfc4251:encode :string name s)
      ;; Extensions are flags only, so no data is associated with them
      (rfc4251:encode :string "" s))
    (rfc4251:encode :buffer (rfc4251:get-binary-stream-bytes s) stream)))

(defparameter *cert-signature-types*
  '((:name "ssh-rsa"
     :digest :sha1)
    (:name "rsa-sha2-256"
     :digest :sha256)
    (:name "rsa-sha2-512"
     :digest :sha512))
  "OpenSSH certificate signature types")

(defun get-signature-type (value)
  "Get the signature type with name identified by VALUE"
  (find value *cert-signature-types*
	:key (lambda (item)
	       (getf item :name))
	:test #'equal))

(defun get-signature-type-or-lose (value)
  (let ((signature-type (get-signature-type value)))
    (unless signature-type
      (error 'base-error
	     :description (format nil "Unknown signature type ~a" value)))
    signature-type))

(defclass signature ()
  ((type
   :initarg :type
   :reader signature-type
   :initform (error "Must specify signature type")
   :documentation "Signature type")
   (blob
    :initarg :blob
    :reader signature-blob
    :initform (error "Must specify signature blob")
    :documentation "Computed signature"))
  (:documentation "Certificate signature"))

(defmethod rfc4251:decode ((type (eql :cert-signature)) stream &key)
  "Decode certificate key signature"
  (let* ((type-data (multiple-value-list (rfc4251:decode :string stream)))
	 (blob-data (multiple-value-list (rfc4251:decode :buffer stream)))
	 (type (first type-data))
	 (blob (first blob-data))
	 (total (+ (second type-data) (second blob-data)))
	 (signature-type (get-signature-type-or-lose type))
	 (signature (make-instance 'signature
				   :type signature-type
				   :blob blob)))
    (values signature total)))

(defmethod rfc4251:encode ((type (eql :cert-signature)) (value signature) stream &key)
  "Encode certificate signature into the given stream"
  (with-accessors ((type signature-type) (blob signature-blob)) value
    (let ((type-name (getf type :name)))
      (+ (rfc4251:encode :string type-name stream)
	 (rfc4251:encode :buffer blob stream)))))

(defclass certificate (base-key)
  ((nonce
    :initarg :nonce
    :initform (error "Must provide nonce")
    :accessor cert-nonce
    :documentation "CA-provided nonce")
   (key
    :initarg :key
    :initform (error "Must specify certificate public key")
    :reader cert-key
    :documentation "The public key of the user/host")
   (serial
    :initarg :serial
    :initform 0
    :accessor cert-serial
    :documentation "Optional certificate serial number set by the CA")
   (type
    :initarg :type
    :initform (error "Must specify certificate type")
    :accessor cert-type
    :documentation "Certificate type. Must be either +SSH-CERT-TYPE-USER+ or +SSH-CERT-TYPE-HOST+")
   (key-id
    :initarg :key-id
    :initform nil
    :accessor cert-key-id
    :documentation "Key identity filled in by the CA at the time of signing")
   (valid-principals
    :initarg :valid-principals
    :initform nil
    :accessor cert-valid-principals
    :documentation "List of usernames/hostnames for which this certificate is valid")
   (valid-after
    :initarg :valid-after
    :initform 0
    :accessor cert-valid-after
    :documentation "The validity period after which the certificate is valid")
   (valid-before
    :initarg :valid-before
    :initform +ssh-cert-max-valid-to+
    :accessor cert-valid-before
    :documentation "The validity period before which the certificate is valid")
   (critical-options
    :initarg :critical-options
    :initform nil
    :accessor cert-critical-options
    :documentation "Certificate critical options")
   (extensions
    :initarg :extensions
    :initform nil
    :accessor cert-extensions
    :documentation "Certificate extensions")
   (reserved
    :initform nil
    :initarg :reserved
    :reader cert-reserved
    :documentation "Currently unused and ignored in this version of the protocol")
   (signature-key
    :initarg :signature-key
    :initform (error "Must specify signature key")
    :accessor cert-signature-key
    :documentation "The public key of the CA that signed the certificate")
   (signature
    :initarg :signature
    :accessor cert-signature
    :initform (error "Must specify signature")
    :documentation "The certificate signature"))
  (:documentation "An OpenSSH certificate key"))

(defmethod get-bytes-for-signing ((cert certificate) &key)
  "Returns the portion of the certificate key which will be signed"
  (rfc4251:with-binary-output-stream (s)
    (rfc4251:encode :string (getf (key-kind cert) :name) s)  ;; Kind
    (rfc4251:encode :buffer (cert-nonce cert) s)  ;; Nonce
    (rfc4251:encode :public-key (cert-key cert) s :encode-key-type-p nil)  ;; Client public key
    (rfc4251:encode :uint64 (cert-serial cert) s)  ;; Serial
    (rfc4251:encode :uint32 (cert-type cert) s)  ;; Cert type (user or host)
    (rfc4251:encode :string (cert-key-id cert) s)  ;; Key identity
    (rfc4251:encode :ssh-cert-valid-principals (cert-valid-principals cert) s)  ;; Valid principals
    (rfc4251:encode :uint64 (cert-valid-after cert) s)  ;; Valid after
    (rfc4251:encode :uint64 (cert-valid-before cert) s)   ;; Valid before
    (rfc4251:encode :ssh-cert-critical-options (cert-critical-options cert) s)  ;; Critical options
    (rfc4251:encode :ssh-cert-extensions (cert-extensions cert) s)  ;; Extensions
    (rfc4251:encode :buffer (cert-reserved cert) s)  ;; Reserved

    ;; Signature key. This one resides in a buffer of it's own
    (rfc4251:with-binary-output-stream (signature-key-s)
      (rfc4251:encode :public-key (cert-signature-key cert) signature-key-s)
      (rfc4251:encode :buffer (rfc4251:get-binary-stream-bytes signature-key-s) s))
    (rfc4251:get-binary-stream-bytes s)))

(defmethod rfc4251:decode ((type (eql :ssh-cert-key)) stream &key kind comment)
  "Decodes an OpenSSH certificate key from the given stream"
  (let ((client-pk-plain-name (getf kind :plain-name))
	(total 0)  ;; Total bytes read from the stream
	nonce
	client-pk  ;; Client public key
	serial  ;; Certificate serial number
	cert-key-type  ;; Cert key type (user or host key)
	key-identity
	valid-principals
	valid-after
	valid-before
	critical-options
	extensions
	reserved
	signature-key
	signature
	cert)
    ;; Nonce
    (multiple-value-bind (value size) (rfc4251:decode :buffer stream)
      ;; nonce should be 16 or 32 bytes in size
      (unless (or (= 16 (length value)) (= 32 (length value)))
	(error 'invalid-key-error
	       :description "nonce should be 16 or 32 bytes"))
      (incf total size)
      (setf nonce value))

    ;; Client public key
    (multiple-value-bind (value size)
	(rfc4251:decode :public-key stream :key-type-name client-pk-plain-name :comment comment)
      (incf total size)
      (setf client-pk value))

    ;; Serial
    (multiple-value-bind (value size) (rfc4251:decode :uint64 stream)
      (incf total size)
      (setf serial value))

    ;; Cert key type (user or host)
    (multiple-value-bind (value size) (rfc4251:decode :uint32 stream)
      (unless (member value (list +ssh-cert-type-user+ +ssh-cert-type-host+))
	(error 'invalid-key-error
	       :description "invalid cert key type"))
      (incf total size)
      (setf cert-key-type value))

    ;; Cert key identity
    (multiple-value-bind (value size) (rfc4251:decode :string stream)
      (incf total size)
      (setf key-identity value))

    ;; Valid principals
    (multiple-value-bind (value size) (rfc4251:decode :ssh-cert-valid-principals stream)
      (incf total size)
      (setf valid-principals value))

    ;; Valid after
    (multiple-value-bind (value size) (rfc4251:decode :uint64 stream)
      (incf total size)
      (setf valid-after value))

    ;; Valid before
    (multiple-value-bind (value size) (rfc4251:decode :uint64 stream)
      (incf total size)
      (setf valid-before value))

    ;; Critical options
    (multiple-value-bind (value size) (rfc4251:decode :ssh-cert-critical-options stream)
      (incf total size)
      (setf critical-options value))

    ;; Extensions
    (multiple-value-bind (value size) (rfc4251:decode :ssh-cert-extensions stream)
      (incf total size)
      (setf extensions value))

    ;; Reserved
    (multiple-value-bind (value size) (rfc4251:decode :buffer stream)
      ;; Reserved field is currently unused and ignored
      (unless (zerop (length value))
	(error 'invalid-key-error
	       :description "invalid/unknown reserved field"))
      (incf total size)
      (setf reserved value))

    ;; Signature key. This one resides in a buffer on it's own, so
    ;; decode the buffer first.
    (multiple-value-bind (value size) (rfc4251:decode :buffer stream)
      (incf total size)
      (cl-rfc4251:with-binary-input-stream (s value)
	(setf signature-key (rfc4251:decode :public-key s))))

    ;; Signature
    (multiple-value-bind (value size) (rfc4251:decode :buffer stream)
      (incf total size)
      (cl-rfc4251:with-binary-input-stream (s value)
	(setf signature (rfc4251:decode :cert-signature s))))

    ;; Create the certificate key
    (setf cert
     (make-instance 'certificate
		    :comment comment
		    :kind kind
		    :nonce nonce
		    :key client-pk
		    :serial serial
		    :type cert-key-type
		    :key-id key-identity
		    :valid-principals valid-principals
		    :valid-after valid-after
		    :valid-before valid-before
		    :critical-options critical-options
		    :extensions extensions
		    :reserved reserved
		    :signature-key signature-key
		    :signature signature))

    (unless (verify-signature (cert-signature-key cert)
			      (get-bytes-for-signing cert)
			      (signature-blob signature)
			      (getf (signature-type signature) :digest))
      (error 'invalid-key-error
	     :description "Signature verification failed"))

    (values cert total)))

