FROM clfoundation/sbcl:2.2.4

ENV QUICKLISP_ADD_TO_INIT_FILE=true
ENV QUICKLISP_DIST_VERSION=latest

WORKDIR /app
COPY . .

RUN mkdir -p ~/.config/common-lisp/source-registry.conf.d && \
    echo '(:tree "/app/")' >  ~/.config/common-lisp/source-registry.conf.d/workspace.conf && \
    /usr/local/bin/install-quicklisp

ENTRYPOINT ["./scripts/run-tests.sh"]

