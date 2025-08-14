FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    gdb \
    clang \
    clang-format \
    clang-tidy \
    pkg-config \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /project