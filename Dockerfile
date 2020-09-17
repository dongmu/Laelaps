FROM ubuntu:18.04

WORKDIR /root
COPY ./ ./
RUN ./dockerbuild.sh
