FROM fukamachi/sbcl:latest

WORKDIR /root/.roswell/local-projects
COPY . .

ENTRYPOINT ["./entrypoint.sh"]
