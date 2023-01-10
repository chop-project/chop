FROM ubuntu:18.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get upgrade -y && \
    apt-get -y install --no-install-suggests --no-install-recommends \
    apt-utils \
    build-essential \
    ca-certificates \
    clang \
    cmake \
    git \
    libgtest-dev \
    lld \
    openssl \
    python \ 
    sudo \
    xz-utils 

RUN mkdir /usr/src/gtest/build
WORKDIR /usr/src/gtest/build 
RUN cmake .. && make && make install

WORKDIR /
RUN git clone https://github.com/HexHive/ShadowStack.git
WORKDIR /ShadowStack/Compiler-Impl
RUN ./configure.sh
RUN make

CMD [ "/bin/bash" ]
